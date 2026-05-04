# `piv` package — library reference

The `piv` package and its subpackages provide a Go vocabulary for PIV (NIST SP 800-73-4) operations against GlobalPlatform smart cards. The library targets cross-card use: it speaks Standard PIV by default and treats vendor extensions (currently YubiKey) as opt-in capabilities behind a profile gate.

For the CLI built on top of this library, see [`scpctl.md`](./scpctl.md). For hardware compatibility status, see [`piv-compatibility.md`](./piv-compatibility.md).

## Public API at a glance

There are three entry points and the right one for a given caller is usually obvious.

`piv/session` is what almost everyone wants. It is the stateful PIV API: open a session over any APDU transmitter (raw PC/SC, an established SCP channel, a mock), and the session methods orchestrate authentication state, host-side capability gating, and the multi-APDU sequences that PIV operations actually require. Cert-to-public-key binding, retry-counter parsing, and profile refusal all live here. New code targeting PIV provisioning, enrollment, or admin should use `piv/session` exclusively unless it needs something the session does not expose.

`piv` (the parent package) is the shared vocabulary: typed slot constants, algorithm enums, PIN/touch policy enums, management-key types, object IDs, and the `CardError` plus its status-word predicates. It has no APDU surface of its own. Library callers consume these types; `piv/session` and `piv/apdu` produce and accept them.

`piv/apdu` (Go package name `pivapdu` to avoid colliding with the unrelated GlobalPlatform `apdu` package) is the low-level builder layer. It is sharp-edged on purpose: callers are responsible for sequencing, authentication state, and capability gating, none of which the builders enforce. Use this package when you need to send a hand-rolled APDU sequence through an unusual transport, when implementing a custom session that the canonical `piv/session` does not cover, or when writing tests against APDU bytes. Most code should not need it.

The package split is deliberate. Callers reaching into `piv/apdu` for routine flows are usually working around something `piv/session` should grow to handle; please file an issue rather than ship a downstream session reimplementation.

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

## Channel mode: raw vs SCP11b-on-PIV

Destructive `scpctl piv` commands accept an optional `--scp11b` flag plus the shared trust flags `--trust-roots <pem>` and `--lab-skip-scp11-trust`. The default is raw APDUs; the SCP11b path is opt-in.

The reason for this default is that the threat model splits cleanly along the host-trust boundary:

**Raw is correct when the host between the operator and the card is in the operator's trust boundary.** The dominant case is local USB administration: an operator at a workstation plugging a YubiKey directly into a USB port and running `scpctl piv ...` against it. The PC/SC stack, the kernel, the running shell, and the binary itself are all already in scope. SCP11b in this configuration adds no security: the same host that would attack the raw APDUs would attack the SCP11b key derivation.

**SCP11b is correct when the host between the operator and the card is not in the operator's trust boundary.** This includes:

- APDU relay through an untrusted network or browser. The card is at one end, the operator at the other, and the relay sees every APDU.
- Remote provisioning where the agent running scpctl is on a remote machine the operator does not fully trust.
- Multi-tenant CI environments where the runner sees the management key in the clear if the channel is raw.
- Any path where the card's PIV operations transit a host the operator would not personally administer the YubiKey from.

In those configurations, SCP11b establishes an authenticated key agreement against the card's certificate (with `--trust-roots` providing the issuer chain), and every PIV APDU is then encrypted and integrity-protected end to end through the relay or remote host.

The two configurations require different trust flags:

```
# Raw (default): local USB, no extra flags.
scpctl piv key generate --slot 9a --confirm-write ...

# SCP11b with production trust:
scpctl piv key generate --slot 9a --confirm-write \
  --scp11b --trust-roots ./oce-issuer-roots.pem ...

# SCP11b for wire-protocol smoke (NOT production):
scpctl piv key generate --slot 9a --confirm-write \
  --scp11b --lab-skip-scp11-trust ...
```

`--lab-skip-scp11-trust` produces an opportunistically-encrypted channel without authenticated key agreement: the card's cert is not validated, so a relay running a swap-the-card MITM is undetectable. Use it only to exercise the wire protocol.

The PIN, PUK, and management-key change paths in `scpctl piv pin`, `scpctl piv puk`, and `scpctl piv mgmt` accept the same flags. They are technically not "destructive" in the `--confirm-write` sense (they manipulate counters that the card itself enforces), but the secret material they carry is exactly what an untrusted host would target. Pass `--scp11b --trust-roots ...` whenever the host between you and the card is not in your trust boundary.

## Adding a new card profile

When a non-YubiKey card has been validated end to end:

1. Add the relevant capability flags to `profile.Capabilities` if the card supports anything `StandardPIV` does not (or supports something the existing flags don't cover).
2. Add a new `New<Vendor>Profile()` constructor returning the validated capability set.
3. Update `profile.Probe` to recognize the card from its SELECT response or a vendor-specific GET VERSION equivalent.
4. Update `docs/piv-compatibility.md` to reflect the new verified row.
5. Add a card-specific mock to `mockcard` if test coverage needs it.

Promote `StandardPIVProfile` from "spec-implemented" to "verified" in the README assurance table only after a non-YubiKey card has actually been driven through the full provisioning flow.
