# `piv` package — library reference

The `piv` package and its subpackages provide a Go vocabulary for PIV (NIST SP 800-73-4) operations against GlobalPlatform smart cards. The library targets cross-card use: it speaks Standard PIV by default and treats vendor extensions (currently YubiKey) as opt-in capabilities behind a profile gate.

For the CLI built on top of this library, see [`scpctl.md`](./scpctl.md). For hardware compatibility status, see [`piv-compatibility.md`](./piv-compatibility.md).

## Package layout

```
piv/
  types.go      Named types: Slot, Algorithm, PINPolicy, TouchPolicy,
                ManagementKeyAlgorithm, ManagementKey, ObjectID.
                Parsers for user-facing strings ("9a", "eccp256",
                "aes192", "default").
  errors.go     CardError type plus status-word predicates
                (IsWrongPIN, IsPINBlocked, IsAuthRequired, etc).
                Sentinel errors: ErrUnsupportedByProfile,
                ErrNotAuthenticated.
  piv.go        Low-level APDU builders (GenerateKey, PutCertificate,
                VerifyPIN, etc). Some are Standard PIV, some are
                YubiKey-proprietary. Profile gating in piv/session
                decides which are emitted.
  mgmt_auth.go  PIV management-key mutual authentication helpers.
  genkey_response.go  Parser for GENERATE KEY response data.
  reset_retry.go      RESET RETRY COUNTER builder.

  profile/      Capability profiles (YubiKey, StandardPIV, Probed)
                and the non-destructive Probe function.
  session/      Stateful PIV API over any APDU transmitter, with
                host-side capability gating.
```

## Profile model

A `profile.Profile` is a small description of what a particular card class will accept. The session consults the active profile before emitting any APDU and refuses operations the profile does not claim, returning `piv.ErrUnsupportedByProfile` host-side.

Three profiles ship today:

### `YubiKeyProfile`

Hardware-verified for YubiKey 5.x. Capability set is firmware-aware:

- Ed25519 / X25519: firmware 5.7.0+
- AES-192 default management key: firmware 5.4.2+ (older firmware ships 3DES)
- SCP11b at the PIV applet: firmware 5.7.0+
- Key move between slots: firmware 5.7.0+

`profile.NewYubiKeyProfile()` defaults to firmware 5.7.2 (current shipping). Use `NewYubiKeyProfileVersion(v)` when you have firmware information out of band, or rely on `Probe` to detect it.

### `StandardPIVProfile`

NIST SP 800-73-4 / SP 800-78-5 instruction subset only. Refuses YubiKey-proprietary instructions:

- IMPORT KEY (0xFE) — no key import in SP 800-73-4
- RESET (0xFB) — no applet-level reset in SP 800-73-4
- ATTEST (0xF9) — not standard
- PIN policy / touch policy bytes on GENERATE KEY — YubiKey extensions
- Protected management key, key delete, key move — vendor-specific

Algorithms: RSA-2048, ECC P-256, ECC P-384. Default management key: 3DES per SP 800-78-4.

This profile is **spec-implemented and protocol-correct, awaiting hardware verification against a non-YubiKey PIV card**. It sits in the same assurance tier as SCP03 AES-192/256 in the README's tier table: the wire bytes are correct by code review and the algorithm refusals are correct by code review, but no Standard-PIV hardware run has been recorded yet. The compatibility matrix tracks which behaviors have been exercised end to end.

### `ProbedProfile`

Thin wrapper around `YubiKeyProfile` or `StandardPIVProfile` selected by `Probe()`. Name is prefixed `probed:` for diagnostics; capabilities pass through unchanged. Auto-detect never silently selects YubiKey for a card that did not identify as one.

## Probe

`profile.Probe(ctx, transmitter)` is non-destructive. Two APDUs:

1. **SELECT AID PIV** (`00 A4 04 00 [aid]`). Required. Failure here yields `ErrNoPIVApplet`.
2. **GET VERSION** (`00 FD 00 00 00`). YubiKey-specific. Returns 3 bytes major.minor.patch on YubiKey; `6D00` on Standard PIV. The probe falls through to `StandardPIVProfile` on anything other than a clean 3-byte success response.

`Probe` never generates keys, decrements retry counters, writes objects, or issues any state-changing instruction. The two APDUs above are the entire probe surface.

## Session

`session.Session` is the stateful PIV API. One session per card. Not safe for concurrent use; the underlying card serializes APDUs and the session tracks per-card state (PIN-verified, mgmt-auth-complete) that would race under concurrent access.

```go
sess, err := session.New(ctx, transport, session.Options{})
defer sess.Close()
```

`New` always issues SELECT AID PIV before returning. Without it the card refuses every PIV INS with `6985`; doing it inside `New` means callers cannot get into that state.

`Options.Profile` is optional. If nil, `New` runs `profile.Probe` and uses the result. If set, `New` uses the supplied profile and skips GET VERSION.

### Authenticated operations

Write operations (PUT CERTIFICATE, GENERATE KEY on cards that require mgmt auth for generate, IMPORT KEY) require `AuthenticateManagementKey` to have succeeded. PIN-gated operations require `VerifyPIN`. The session tracks both flags and refuses operations that have not met their preconditions with `ErrNotAuthenticated`.

### Cert-to-public-key binding

`PutCertificate` accepts a `RequirePubKeyBinding` option that refuses to install a cert whose public key does not match the slot's expected key. Expected key comes from:

1. `ExpectedPublicKey` in options (caller-supplied, the usual case for a CA-signed cert).
2. The cached `LastGeneratedPublicKey` from the most recent `GenerateKey` on the same slot in this session, when option 1 is nil.

If neither is available, `PutCertificate` errors rather than silently disabling the binding check.

### Status-word handling

Every operation that touches the card returns `*piv.CardError` on a non-success status word. Callers branch on the predicates:

```go
if err := sess.VerifyPIN(ctx, pin); err != nil {
    if piv.IsWrongPIN(err) {
        retries, _ := piv.RetriesRemaining(err)
        // ...
    }
    if piv.IsPINBlocked(err) {
        // ...
    }
}
```

Both the canonical 63Cx form and the bare 63xx form are recognized.

## Why cert-to-public-key binding matters

Installing a certificate whose SubjectPublicKeyInfo does not match the slot's actual public key produces a credential that fails every signature verification it's used for. The card happily stores the cert (it has no way to know what key the slot holds). The error surfaces only at first use, often days or weeks later, and is hard to diagnose because the cert chain validates cleanly and the slot has a key.

The binding check happens host-side, before any APDU is transmitted. A mismatch never reaches the card.

## Why destructive operations are guarded

`Reset` erases all 24 slot keys, all certs, and resets PIN/PUK/management key to factory defaults. The CLI requires `--confirm-write`; the library refuses `Reset` under any profile that does not advertise it. Provisioning flows that rotate the management key or replace a slot's contents follow the same pattern: the library accepts the operation only when the profile claims support, and the CLI demands confirmation.

This is not paranoia. A wrong-cert provisioning that succeeds is a cert that has to be re-issued, with all of the trust-bootstrap cost that implies.

## Adding a new card profile

When a non-YubiKey card has been validated end to end:

1. Add the relevant capability flags to `profile.Capabilities` if the card supports anything `StandardPIV` does not (or supports something the existing flags don't cover).
2. Add a new `New<Vendor>Profile()` constructor returning the validated capability set.
3. Update `profile.Probe` to recognize the card from its SELECT response or a vendor-specific GET VERSION equivalent.
4. Update `docs/piv-compatibility.md` to reflect the new verified row.
5. Add a card-specific mock to `mockcard` if test coverage needs it.

Promote `StandardPIVProfile` from "spec-implemented" to "verified" in the README assurance table only after a non-YubiKey card has actually been driven through the full provisioning flow.
