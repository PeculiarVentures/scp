# scpctl

Administrative CLI for the [`PeculiarVentures/scp`](https://github.com/PeculiarVentures/scp) library. Four command groups:

- `test` runs the hardware regression checks: against a real card, validate that the SCP library produces wire bytes the card accepts (`scp03-sd-read`, `scp11b-sd-read`, `scp11a-sd-read`), and that the wire layer survives being wrapped around a higher-level applet protocol (`scp11b-piv-verify`). Read-only against the card. Renamed from the earlier `smoke` group; same checks, clearer name.
- `piv` is the user-facing PIV operation surface backed by `piv/session`. The full surface is wired: `info`, `pin verify|change|unblock`, `puk change`, `mgmt auth|change-key`, `key generate|attest`, `cert get|put|delete`, `object get|put`, `reset`, and `provision`. Destructive and credential-bearing commands require an explicit channel-mode choice (`--scp11b` or `--raw-local-ok`) and either `--confirm-write` (for slot-scoped operations) or `--confirm-reset-piv` (for the applet-wide `reset`).
- `sd` is the Security Domain operation surface. Wired today: `info`, `reset`, `lock`, `unlock`, `terminate`, `bootstrap-oce`, `bootstrap-scp11a`, `bootstrap-scp11a-sd`. State-changing commands are gated: bootstraps and `lock`/`unlock` use `--confirm-write`; `reset` uses `--confirm-reset-sd`; `terminate` (irreversible) uses `--confirm-terminate-card`. The distinct flag for each scope of irreversibility is the foot-gun mitigation.
- `oce` is host-only OCE certificate diagnostics: `verify` validates a chain off-card, `gen` produces a fresh known-good chain. Does not touch a card.
- `gp` is the generic GlobalPlatform card-content management surface. Wired today: `probe` (gp-tagged unauthenticated SD probe, `--sd-aid` override and `--discover-sd` candidate-list probing both supported), `registry` (authenticated SCP03 walk over ISD/Applications/LoadFiles+Modules with automatic LoadFilesAndModules → LoadFiles fallback; same JSON registry shape as `sd info --full`), `install` and `delete` (INSTALL [for load] + LOAD + INSTALL [for install] / DELETE; dry-run by default with `--confirm-write` and `--expected-card-id` safety gates), and `cap inspect` (host-only CAP file inspector with Header / Applet / Import decode and Java Card runtime version inference). Real-card validation against JCOP and SafeNet is the next step.

Plus two top-level utilities, `readers` and `probe`, for the things operators reach for outside any group.

This binary is hardware-targeting: most subcommands need an actual reader and card. For library-level testing without hardware, use the `mockcard` package directly.

## What this is for

The `test` group answers two questions against a real card:

1. **Does the SCP library produce wire bytes that an actual card accepts?** — `scp03-sd-read`, `scp11b-sd-read`, `scp11a-sd-read`
2. **Does the wire layer survive being wrapped around a higher-level applet protocol?** — `scp11b-piv-verify`

Plus a top-level `probe` that tells you what the card claims to be before you authenticate to it, and a `test all` aggregator that runs the lot.

The `piv` group is the operator-facing surface for PIV administration: PIN/PUK lifecycle, management-key authentication and rotation, slot key generation, certificate install/read/delete, raw object I/O, attestation, full applet reset, and the SCP11b-secured `provision` flow. These commands write to the card; safety is documented in the next section.

The `sd` group exposes Security Domain identity and bootstrap. `info` reads CRD and the key-info template over an unauthenticated session. `reset` factory-resets SD key material. `bootstrap-oce` / `bootstrap-scp11a` / `bootstrap-scp11a-sd` are the day-1 provisioning flows that install OCE material and the SCP11a SD ECDH key on fresh cards.

## Safety

The `test` group is read-only and behaves as it always did: no key rotation, no authentication lockouts, no SD writes over SCP11b, no card reset as a recovery mechanism.

The `piv` group writes to the card. The safety model rests on four explicit gates:

- **`--confirm-write`** is required for every destructive *slot-scoped* PIV operation (`key generate`, `cert put`, `cert delete`, `object put`, `mgmt change-key`). The flag exists so destructive commands can never run without an explicit operator decision.
- **`--confirm-reset-piv`** is required for `piv reset` (the applet-wide wipe). The distinct flag is the foot-gun mitigation: a full applet wipe is qualitatively different from a single-slot operation, and giving it its own confirm flag prevents an operator who pastes a stale slot-rotation command line from accidentally turning it into a full reset. `--confirm-write` is accepted on `piv reset` for stale-script compatibility but on its own falls through to dry-run with a deprecation notice; `--confirm-reset-piv` is the one that actually mutates.
- **`--scp11b` or `--raw-local-ok`** must be specified explicitly on every destructive or credential-bearing PIV command. Specifying neither is a usage error; specifying both is a usage error. This fail-closed default ensures a missed channel-mode flag cannot silently downgrade an SCP11b-secured operation to raw transport.
- **Cert-to-public-key binding is on by default.** `piv cert put` requires `--expected-pubkey <path>` unless `--no-pubkey-binding` is explicitly passed; the safe default rejects installing a certificate whose public key does not match the slot's generated key.

The `sd` group writes follow the same overall philosophy with two distinct gate flags for irreversible operations:

- **`--confirm-write`** gates the reversible writes (`lock`, `unlock`, `bootstrap-oce`, `bootstrap-scp11a`, `bootstrap-scp11a-sd`).
- **`--confirm-reset-sd`** is required *instead* for `sd reset`. SD reset and PIV reset have different blast radii; a shared flag would mean a single careless invocation could clear keys the operator didn't intend to touch.
- **`--confirm-terminate-card`** is required *instead* for `sd terminate`. Terminate is irreversible — a TERMINATED card cannot be recovered by any operation — and sharing a confirm flag with reversible operations means a typo could brick a card. The loud, specific flag name is a deliberate "type the consequence" friction.

Profile gating is host-side: operations the active card profile does not claim are refused with `piv.ErrUnsupportedByProfile` before any APDU goes on the wire (Ed25519 under Standard PIV, attestation under Standard PIV, reset under Standard PIV, etc.). The active profile is selected by probing the card; YubiKey-specific assumptions are not made unprobed.

## Build

This is a Go submodule with its own `go.mod` because [`transport/pcsc`](../../transport/pcsc) requires CGo and links against `pcsclite` / `winscard`.

### Linux

```bash
sudo apt install pcscd libpcsclite-dev   # Debian/Ubuntu
sudo dnf install pcsc-lite pcsc-lite-devel   # Fedora/RHEL
sudo systemctl enable --now pcscd

cd cmd/scpctl
go build -o scpctl .
```

### macOS, Windows

PC/SC is built into the OS. No package install needed; just `go build`.

## Usage

```text
scpctl <group> <subcommand> [flags]
scpctl <utility> [flags]
```

Run `scpctl help`, `scpctl test help`, or `scpctl <group> <cmd> -h` for full flag lists.

The `readers` and `probe` utilities are also reachable directly:

```bash
scpctl readers
scpctl probe --reader "YubiKey"
```

### List PC/SC readers

```bash
scpctl readers
```

```bash
scpctl readers --json
```

### Probe a card

Opens an unauthenticated Security Domain session, fetches Card Recognition Data via `GET DATA` tag `0x66`, parses, and prints the card's claimed capabilities.

```bash
scpctl probe --reader "YubiKey"
```

Sample output (against a retail YubiKey 5.7+):

```
scpctl probe
  reader: YubiKey
  data:
    auth_mode: none
    card_identification_oid: 1.2.840.114283.3
    cplc: {"ic_fabricator":"4090", "ic_serial_number":"BD969B1A", ...}
    gp_version: 2.3.1
    profile: yubikey-sd
    scp_parameter: 0x60
    scp_version: 0x03
    scps: ["SCP03 i=0x60", "SCP11 i=0x0D86"]
  discover ISD attempt             PASS — A000000151000000 — GP Card Spec v2.3.1 §F.6 (default Issuer Security Domain AID) — SW=9000
  discover ISD                     PASS — matched A000000151000000
  GET DATA tag 0x66                PASS — 65 bytes
  parse CRD                        PASS
  GP version                       PASS — 2.3.1
  SCP advertised                   PASS — SCP03 i=0x60
  SCP advertised                   PASS — SCP11 i=0x0D86
  GET DATA tag 0x9F7F (CPLC)       PASS — IC fabricator=0x4090 serial=BD969B1A
  GET DATA tag 0x0042 (IIN)        SKIP — not present (SW=6A88)
  GET DATA tag 0x0045 (CIN)        SKIP — not present (SW=6A88)
  GET DATA tag 0x00CF (KDD)        SKIP — not present (SW=6A88)
  GET DATA tag 0x00C1 (SSC)        SKIP — not present (SW=6A88)
  GET DATA tag 0x0067 (Card Capabilities) SKIP — not present (SW=6A88)
```

YubiKey reports CPLC with the post-fabrication date fields holding random per-card serial bytes (the parser tolerates this and renders affected dates as `"{raw} (raw)"`); IIN/CIN/KDD/SSC/Card Capabilities are not exposed by YubiKey 5.x and surface as SKIP. A SafeNet eToken Fusion or other Thales/Gemalto card under the same probe populates all five reads with hex bytes (the IIN value ASCII-decodes to the issuer name) and decodes valid CPLC dates.

CRD is **discovery input, not authorization**. A card that lies about its CRD is the card's bug; this tool does not infer trust from the probe output.

### SCP03 Security Domain read

Opens an SCP03 session against the ISD using YubiKey factory credentials (KVN `0xFF`, key `404142434445464748494A4B4C4D4E4F` for ENC/MAC/DEK), then verifies that `GetKeyInformation` and `GetCardRecognitionData` succeed under secure messaging.

```bash
scpctl test scp03-sd-read --reader "YubiKey"
```

This is expected to fail on a YubiKey that has had its SCP03 keys rotated to a custom KVN — that's an informative failure, not a bug. Custom-key flag support (`--kvn`, `--enc`, `--mac`, `--dek`) is a follow-up; it isn't in this version because the threshold for "is the wire working at all?" doesn't need it.

### SCP11b Security Domain read

```bash
scpctl test scp11b-sd-read --reader "YubiKey" --lab-skip-scp11-trust
```

SCP11b authenticates the card to the host but **not** the host to the card. The test verifies this by asserting `Session.OCEAuthenticated()` is `false`. After that it issues `GetKeyInformation` to exercise the wire layer.

`--lab-skip-scp11-trust` skips the SCP11 card-certificate validation step. This is for separating "the wire-protocol is broken" from "the trust bootstrap isn't configured." When the flag is omitted and no trust roots are configured, this command **skips** rather than fails — the rationale is that an unconfigured trust state is not a wire-protocol failure.

### SCP11b → PIV → VERIFY PIN

Opens an SCP11b session targeting the PIV applet (NOT the ISD; SCP is applet-scoped on YubiKey) and verifies the PIN over the secure channel.

```bash
scpctl test scp11b-piv-verify --reader "YubiKey" --pin 123456 --lab-skip-scp11-trust
```

A successful `VERIFY PIN` proves three things at once: SCP11b can target a non-SD applet, the PIV APDU builders survive secure-messaging wrap, and the card accepts the PIN through the wrapped channel.

If the card returns a `63Cx` SW (PIN wrong, x retries), the failure surfaces with the status word in the error so you can distinguish "wire broken" from "PIN wrong."

### SCP11a Security Domain read

SCP11a is mutual auth: the host validates the card AND the card validates the host's OCE certificate chain against an OCE root that was previously installed on the card. After a successful open, the session is OCE-authenticated and capable of driving SD writes (key rotation, certificate store, allowlist updates).

```bash
scpctl test scp11a-sd-read \
  --reader "YubiKey" \
  --oce-key /path/to/oce.key.pem \
  --oce-cert /path/to/oce-chain.pem \
  --lab-skip-scp11-trust
```

Pre-conditions for this to succeed against real hardware:

1. The card has an OCE root + key reference provisioned at `--oce-kid` (default `0x10`) / `--oce-kvn` (default `0x03`). On factory-fresh YubiKey this is **not** the case; the OCE has to be bootstrapped first (see `bootstrap-oce`, follow-up).
2. The OCE private key file corresponds to the leaf certificate in the chain.
3. The chain leaf is signed by the OCE root the card has installed.

The test asserts the SCP11a-specific invariant `Session.OCEAuthenticated() == true` — a regression that silently downgraded to SCP11b-shape session keys would be caught here rather than going unnoticed.

PEM key formats accepted: PKCS#8 (`PRIVATE KEY`, modern `openssl genpkey` default) and SEC1 (`EC PRIVATE KEY`, what older `openssl ecparam -genkey` produces and what Yubico fixtures use). Curve must be P-256 — the loader rejects other curves explicitly.

### bootstrap-oce — Day-1 OCE provisioning

Installs an OCE public key onto a card via SCP03 with factory keys (and optionally registers a CA Subject Key Identifier), so subsequent SCP11a sessions can complete mutual auth. This is the step that has to happen *before* `scp11a-sd-read` works against a fresh card.

```bash
scpctl sd bootstrap-oce \
  --reader "YubiKey" \
  --oce-cert /path/to/oce-chain.pem \
  --ca-ski 0123456789ABCDEF0123456789ABCDEF01234567 \
  --confirm-write
```

Without `--confirm-write` the command runs in **dry-run mode**: it loads and validates the cert chain, types the public key, prints what it would do, and exits without transmitting any APDU that mutates card state. This mirrors the safety pattern in the destructive-ops note above and gives operators a way to sanity-check inputs before flipping the card.

By default the CLI assumes SCP03 factory keys (KVN `0xFF`, default ENC/MAC/DEK) — the typical state of a fresh YubiKey. For cards whose SCP03 keys have been rotated, pass the explicit triple via `--scp03-kvn`, `--scp03-enc`, `--scp03-mac`, `--scp03-dek` (all four required together; partial specification is a usage error). Pinning `--profile=standard-sd` requires the explicit triple — there's no implicit factory-key fallback for non-YubiKey cards.

The OCE certificate chain is **NOT stored on the card**. It travels on the wire at SCP11 session-open via PSO (GP §7.5.3), and the card validates it against the registered CA pubkey + SKI. `bootstrap-oce` thus performs two writes: `PUT KEY` to install the OCE CA pubkey at KID=0x10, and `STORE DATA` to register the CA SKI. The leaf cert's pubkey and the chain bytes themselves are never written to card storage — that would be a category error (the card has no slot for OCE chains), and earlier versions that tried to do this got SW=6A80 from retail YubiKeys. If you need to store an *SD* attestation chain (a chain whose leaf certifies the on-card SD pubkey), that's a separate provisioning step against the SD key reference, not part of `bootstrap-oce`.

### sd reset — restore the Issuer Security Domain to factory state

Erases custom Security Domain key material and restores the factory SCP03 key set, regenerating the SCP11b key at `KID=0x13/KVN=0x01`. Does NOT touch the PIV applet — that lives in a separate applet with separate state, recoverable via `piv reset`.

```bash
scpctl sd reset \
  --reader "YubiKey" \
  --confirm-reset-sd
```

The flow:

1. Read the pre-reset key inventory (for the operator-visible diff).
2. For every installed SCP key, send 65 wrong-credential attempts to block it (`6983`). The card's own footgun guard is that destructive SD reset only fires when every key is in the BLOCKED state.
3. The card auto-restores factory SCP03 (`KID=0x01/0x02/0x03 at KVN=0xFF`, the publicly documented `404142...4F` AES-128 key set) and regenerates a fresh SCP11b key at `KID=0x13/KVN=0x01`.

**Power-cycle the card before issuing further APDUs.** The SD lifecycle transition does not fully apply until the next reader power-up. Hammering the card with `SELECT` immediately after `sd reset` returns `SW=6A82` on every applet — not because the reset failed, but because the card hasn't completed its self-restoration yet. Unplug + replug (or remove + replace from an NFC reader). The success message from `sd reset` includes a reminder to do this.

`--confirm-reset-sd` (not `--confirm-write`) is required to mutate, by design: SD reset clears credentials at a different blast radius than `piv reset`, and a shared confirmation flag would let a single careless invocation against the wrong subcommand clear keys the operator didn't intend to touch.

### piv reset — restore the PIV applet to factory state

Recovers a YubiKey from a wrong-cert provisioning, an unknown PIN, or any other PIV state you want to undo without physically swapping the hardware. Erases ALL 24 PIV slot keypairs and certificates, returns PIN to `123456` and PUK to `12345678`, and resets the management key (to the well-known 3DES default on pre-5.7 firmware, or a randomly regenerated AES-192 key in protected metadata on 5.7+). Does NOT touch installed OCE roots or the Issuer Security Domain — those live outside the PIV applet.

```bash
scpctl piv reset \
  --reader "YubiKey" \
  --lab-skip-scp11-trust \
  --confirm-reset-piv
```

The flow:

1. Open SCP11b session targeting the PIV applet.
2. Block the PIN by sending VERIFY PIN with deliberately wrong PINs (`00000000`) until the card returns `6983`. Typically 3 attempts.
3. Block the PUK by sending RESET RETRY COUNTER with deliberately wrong PUKs until the card returns `6983`. Typically 3 attempts.
4. Send the YubiKey-specific PIV reset APDU (`INS=0xFB`).

The card's own foot-gun guard is the precondition that BOTH PIN and PUK retry counters must be exhausted before `INS=0xFB` is accepted. A casual operator can't accidentally wipe a slot by sending one APDU; they have to first deliberately block both credentials, which this command does only when `--confirm-reset-piv` is supplied. Without `--confirm-reset-piv`, `piv reset` runs in dry-run mode and prints what would happen. (`--confirm-write` is also accepted for stale-script compatibility but on its own falls through to dry-run with a deprecation notice; pass `--confirm-reset-piv` to actually mutate.)

After a successful reset, you can immediately re-run `piv provision` against the now-clean card.

### piv provision — generate a slot keypair (and optionally install a cert)

Provisions a PIV slot through an SCP11b-secured channel: `VERIFY PIN` → `GENERATE KEY` → optional `PUT CERTIFICATE` → optional `ATTESTATION`. Same `--confirm-write` dry-run gating as `bootstrap-oce`.

```bash
scpctl piv provision \
  --reader "YubiKey" \
  --pin 123456 \
  --slot 9a \
  --algorithm eccp256 \
  --cert /path/to/leaf.pem \
  --attest \
  --lab-skip-scp11-trust \
  --confirm-write
```

Slots: `9a` (PIV Authentication), `9c` (Digital Signature), `9d` (Key Management), `9e` (Card Authentication), `82`–`95` (Retired Key Management 1–20), and `f9` (YubiKey Attestation). Algorithms: `rsa2048`, `eccp256`, `eccp384`, plus YubiKey 5.7+ exclusives `ed25519` and `x25519`.

**Cert-to-pubkey binding check.** When `--cert` is supplied, after `GENERATE KEY` succeeds, `piv provision` parses the public key returned by the card and refuses to install the cert if its public key does not match. Without this check, a wrong cert (different slot, stale chain, typo'd path that resolved to something unintended) would install onto a slot whose keypair doesn't actually correspond — the slot would then attest to an identity it can't prove possession of. Mismatch produces a `cert binding FAIL` line and a non-zero exit; `PUT CERTIFICATE` is not transmitted.

The check runs against the parsed public key for the relevant algorithm: RSA (modulus + exponent), ECDSA (curve + X/Y), Ed25519 (32-byte raw). X25519 keys are not bound by X.509 certs, so the binding step is skipped with a `parse pubkey SKIP` note.

**Management-key authentication.** PIV `GENERATE KEY` and `PUT CERTIFICATE` are gated on PIV management-key authentication on stock cards. Pass `--mgmt-key` (hex) and `--mgmt-key-algorithm` to run the mutual-auth flow before the writes. Without `--mgmt-key`, the auth step is skipped — useful for testing the rest of the sequence against a card you've already authenticated to out of band, or against the mock with no enforcement configured.

```bash
# YubiKey with the historic pre-5.7 factory 3DES default
scpctl piv provision \
  --reader "YubiKey" --pin 123456 --slot 9a \
  --mgmt-key default --mgmt-key-algorithm 3des \
  --lab-skip-scp11-trust --confirm-write

# YubiKey 5.7+ with a rotated AES-192 management key
scpctl piv provision \
  --reader "YubiKey" --pin 123456 --slot 9a \
  --mgmt-key A1B2C3...  --mgmt-key-algorithm aes192 \
  --lab-skip-scp11-trust --confirm-write
```

`--mgmt-key default` is shorthand for the well-known pre-5.7 YubiKey 3DES factory key; only valid with `--mgmt-key-algorithm 3des`. The hex value accepts spaces, colons, and dashes for paste-from-docs convenience. Length is validated against the algorithm at the CLI boundary.

The mock implements crypto-correct mutual auth when `PIVMgmtKey` and `PIVMgmtKeyAlgo` are configured; tests use this to round-trip the full flow without real hardware.

### `test` aggregator

Runs `probe` + the SCP read tests in sequence and prints a single PASS/FAIL/SKIP summary at the end.

```bash
scpctl test all \
  --reader "YubiKey" \
  --pin 123456 \
  --oce-key /path/to/oce.key.pem \
  --oce-cert /path/to/oce-chain.pem \
  --lab-skip-scp11-trust
```

`test all` accepts the same `--scp03-*` flag set as `scp03-sd-read` and forwards them to that subcheck. Use this on cards whose SCP03 keys have been rotated (the implicit factory-keys default fails on rotated cards), on standard GP cards (no Yubico factory keys), or on cards where `bootstrap-*` invalidated factory SCP03 as a documented side effect.

```bash
# Pass factory keys explicitly (same behavior as omitting; visible in scripts)
scpctl test all --reader "YubiKey" --scp03-keys-default --pin 123456 --lab-skip-scp11-trust

# Rotated AES-128 set
scpctl test all --reader "YubiKey" \
  --scp03-kvn 01 \
  --scp03-enc 11111111111111111111111111111111 \
  --scp03-mac 22222222222222222222222222222222 \
  --scp03-dek 33333333333333333333333333333333 \
  --pin 123456 --lab-skip-scp11-trust
```

Process exit code is 1 if any check failed; 0 otherwise (including SKIP results). The SCP11a check is skipped automatically if `--oce-key`/`--oce-cert` are not supplied.

## Group structure

Four command groups, non-overlapping purposes:

`scpctl test` is the **hardware regression and validation harness**. Read-only against real cards; validates the SCP library produces wire bytes the card accepts and that the wire layer carries through the higher-level applet protocols. Used in CI to catch regressions before they ship. Renamed from the earlier `smoke` group; the checks themselves are unchanged.

`scpctl piv` is the **operator surface for PIV operations**. PIN/PUK management, key generation, certificate install/read/delete, attestation, object I/O, reset, and the SCP11b-secured `provision` flow all live here, wired through `piv/session`. Profile gating is host-side: operations the active profile does not claim are refused before any APDU goes on the wire. Destructive and credential-bearing commands require an explicit channel-mode choice: either `--scp11b` for an authenticated channel against an untrusted host path, or `--raw-local-ok` to assert the host is in the operator's trust boundary (the typical local-USB administration case). Specifying neither is a usage error. Standard PIV is spec-implemented but not yet hardware-verified; see `docs/piv-compatibility.md`.

`scpctl sd` is the **operator surface for Security Domain operations**. `info` reads CRD and key-info template over an unauthenticated session. `reset` factory-resets SD key material. `lock` and `unlock` toggle the ISD between SECURED and CARD_LOCKED via GP SET STATUS; both are reversible and gated by `--confirm-write`. `terminate` transitions the ISD to TERMINATED — IRREVERSIBLE — gated by a distinct `--confirm-terminate-card` flag so a careless invocation of `--confirm-write` on the wrong command can never brick a card. `bootstrap-oce`, `bootstrap-scp11a`, and `bootstrap-scp11a-sd` are the day-1 provisioning flows that install OCE material and the SCP11a SD ECDH key on fresh cards; all are state-changing and gated by `--confirm-write`.

Every generic SD command (`info`, `reset`, `lock`/`unlock`/`terminate`, `keys list|export|delete|generate|import`, `allowlist set|clear`) accepts `--sd-aid` to target a non-default Security Domain AID. Empty (the default) targets the GP-standard ISD `A0000001510000`; non-empty SELECTs the named AID instead — useful for vendor cards whose ISD lives at a different AID, or for Supplementary Security Domains addressed by AID. Hex input is permissive: bare hex, colon-separated, space-separated, or dash-separated (`A0:00:00:01:51:00:00:00`, `A0 00 00 01 51 00 00 00`, `a0000001510000` all parse identically). Length must be 5-16 bytes per ISO 7816-5; out-of-range input surfaces as a usage error before any transport activity. The bootstrap commands (`bootstrap-oce`, `bootstrap-scp11a`, `bootstrap-scp11a-sd`) deliberately do not accept `--sd-aid` — they target the standard ISD by definition.

`scpctl oce` is **off-card OCE certificate diagnostics**. `verify` validates a chain off-card; `gen` produces a fresh known-good chain. Host-only — does not touch a card.

`scpctl gp` is the **operator surface for generic GlobalPlatform card-content management**, distinct from the YubiKey-flavored `sd` group.

`gp probe` is functionally equivalent to the legacy top-level `probe` under a `gp probe` report label (unauthenticated SELECT, GET DATA tag 0x66 for CRD).

`gp registry` opens an authenticated SCP03 session and walks the GP registry across three scopes (ISD, Applications, LoadFiles+Modules) via GET STATUS. Per-scope failure policy reports SW=6A88 (no entries) as PASS and SW=6982 (auth required) as SKIP. The LoadFiles+Modules scope automatically falls back to LoadFiles-only when the card rejects the modules-included form (SW=6A86 or SW=6D00); the report flags this as "modules omitted" so the operator knows the data is partial because of card behavior, not a tool limitation. JSON output carries `load_files_requested_scope` and `load_files_actual_scope` fields (omitempty) so consumers can detect when the fallback fired and avoid asserting module presence on cards that returned LoadFiles-only.

**YubiKey 5.7+ note.** YubiKey 5.7+ returns `SW=6A86` or `SW=6D00` across every GET STATUS scope by design — the SD does not expose the GP registry, and `ykman`'s equivalent inventory uses out-of-band APIs. This is expected, not a tool failure. The SKIP detail in the report appends an operator-friendly hint (`"card refuses GET STATUS INS entirely on this scope (typical of cards that don't expose the GP registry; e.g. YubiKey 5.7+)"`) so the empty `gp registry` output on a YubiKey doesn't get misread as a misconfiguration.

`gp install` loads and installs an applet from a CAP file. The flow runs INSTALL [for load], a sequence of LOAD chunks, then INSTALL [for install] with P1=0x0C (combined install + make-selectable per GP §11.5.2.1, the standard one-shot form). `--load-block-size` controls the chunk size (default 200, hard-capped at 231 to stay within the 255-byte short-Lc limit after SCP03 LevelFull SM overhead). Mid-flow failure surfaces as `PartialInstallError` with the stage, bytes loaded, and last sequence number, so the operator knows whether to clean up the load file, the install, or both. Dry-run by default; pass `--confirm-write` to transmit. The dry-run preflight prints the components actually going into the load image (Debug / Descriptor exclusion takes effect here), the LOAD chunk plan (count, size, final block bytes), the raw privilege bytes, the hash policy, and the final INSTALL [for install] data field hex (`install_data_hex` in JSON) so JC applet operators can verify their install-params TLV form before authorizing the write. Re-running with `--confirm-write` produces the same preflight lines so a JSON consumer can diff the two and detect drift between preview and execution.

`--install-params <hex>` and `--load-params <hex>` carry operator-supplied bytes verbatim into the INSTALL [for install] / [for load] parameters fields per GP §11.5.2.3. JC applets are sensitive to the C9/EF/C7/C8 TLV form here; the host does no TLV validation beyond hex parse and the 255-byte LV cap. Whitespace and `:` separators are accepted (e.g. `C9 04 49 4E 49 54` parses identically to `C90449494E4954`). Empty (default) sends a zero-length field, correct for applets that don't expect parameters.

**Scope of `gp install`.** Plain (non-Delegated) Management on the SD that the SCP03 session is authenticated against. The following are **not implemented** and `gp install` does not pretend to be a substitute for tools that do:

- **Delegated Management.** No first-class flag for DM tokens, no token receipt handling, no Authorized Receipt-of-Notification verification. Cards that require DM tokens reject the INSTALL with 6985/6982/6A80 depending on personalization. Operators with DM-required cards must use `--install-params` / `--load-params` to inject the vendor-specific payload and accept that the host will not validate it.
- **DAP signing.** No host-side DAP signature computation, no DAP signature key management, no card-side `MandatedDAPVerification`-flag enforcement before LOAD. The `--load-hash hex:<digest>` mode passes a precomputed digest verbatim, which is how operators with DAP-signed flows feed in their out-of-band signature; the host does not produce one.
- **Receipt verification.** Cards that emit install or load receipts have those receipts logged through the JSON output as raw bytes. They are NOT cryptographically validated. Receipt validation requires the issuer's verification public key, which is out of scope for this CLI.
- **Loading via a DM-delegated SD.** INSTALL [for load] always targets the SD the SCP03 session is authenticated against; there is no chained delegation through an intermediate DAP/SSD.

These limits exist because validating DM, DAP, and receipts against real cards requires personalization material this project has no access to. The protocol-level correctness for the surfaces above is in scope; the cryptographic verification is not yet implemented and the CLI will not pretend it is.

`--load-hash <none|sha1|sha256|hex:DIGEST>` controls the load file data block hash. Default is `none` (no hash on the wire, LV field empty). `sha1` and `sha256` make the host compute the digest of the load image. `hex:DEADBEEF` sends an operator-supplied digest verbatim (used with DAP / vendor-signed flows). SD policy varies across cards: some require a particular algorithm, some reject any hash. The default of `none` matches the safest baseline; set this when the target SD is known to require it.

`--expected-card-id <hex>` pins the card's CIN (GET DATA 0x0045) before any destructive APDU so fleet automation cannot accidentally write to the wrong card.

During the actual LOAD phase (text mode only; `--json` suppresses), per-block progress lines like `LOAD 5/12 (160/2400 bytes)` are emitted to stderr so an operator watching a long install sees progress rather than a silent stall.

`gp delete` removes an applet or load file by AID. `--cascade` adds the cascade-delete flag (P2 high bit) to remove instances along with the load file. Same `--confirm-write` and `--expected-card-id` gates as install.

`gp cap inspect` is host-only and reads a CAP file from disk to print package AID, package version, applet inventory, imported packages, the inferred Java Card runtime version (e.g. "JC 2.2.2" from `javacard.framework` 1.4), and the component manifest. The output explicitly states that the parser is structural-only (Header + Applet + Import); a successful parse is not a guarantee the CAP will load — Method bytecode, ConstantPool offsets, install_method_offset references, and per-card load policy are not validated. When the package name was inferred from the ZIP directory layout rather than read from the Header component (because Header carried no `package_name` field), the report flags the line as `WARN` so the operator knows the name may be stale if the archive was repackaged.

Three flags are shared across the gp group:

- `--sd-aid <hex>` overrides the Security Domain AID for cards with a non-default ISD (some SafeNet/Fusion variants, custom JCOP installs). Default is the GP ISD AID `A000000151000000`.
- `--discover-sd` (probe only) walks `gp.ISDDiscoveryAIDs` until one candidate AID returns 9000. Mutually exclusive with `--sd-aid`. The matched AID appears in the report so subsequent runs can pin it via `--sd-aid`. Each attempt emits a per-candidate report line (`discover ISD attempt — <AID> — <source> — SW=<hex>`) so an operator can see what was tried when discovery fails. SW=6A87 is treated as "not found" alongside SW=6A82 (per the feat/sd-keys-cli coordination brief, some SmartJac and SafeNet variants reject unknown AIDs at the dispatcher with 6A87 rather than at AID matching with 6A82). SW=6283 ("selected file/application invalidated") surfaces distinctly as `ErrLockedISD`: the SD exists at this AID but is in TERMINATED/LOCKED state and needs out-of-band recovery before the discovery list will settle.
- `--expected-card-id <hex>` (install/delete only) aborts before any destructive APDU when the card's CIN does not match.

The boundary against `sd`: `sd` is YubiKey-flavored Security Domain identity and bootstrap; `gp` is generic GP card-content management against any conformant card. End-to-end mock testing uses `mockcard.SCP03Card` (SCP03 + GP combined). Real-card validation against JCOP and SafeNet is the next step.

## `piv info` and `sd info`

The `piv` and `sd` groups expose read-only `info` commands that probe a card without authentication or state change.

### `scpctl piv info`

Selects the PIV applet, runs the YubiKey-specific `GET VERSION` (returns `6D00` on standard PIV cards), and reports the detected profile and capability set:

```bash
scpctl piv info --reader "YubiKey"
scpctl piv info --reader "YubiKey" --json
```

Output names the active profile (`yubikey-5.7.2`, `standard-piv`, or `probed:<inner>`) and lists which operations the profile claims support for. The probe is two APDUs and changes nothing on the card.

### `scpctl sd info`

Opens an unauthenticated Security Domain session and reports the card's identity: parsed Card Recognition Data (issuer identification number, card image number, application provider, application version) plus the Key Information Template if available. No authentication, no state change.

`--full` extends the report with a GP §11.4.2 GET STATUS walk across three scopes: ISD, Applications + SSDs, and Load Files + Modules. Each entry reports its AID, lifecycle (parsed for the scope's state machine), privilege bits set, and — for Load Files — version and module AIDs. Cards typically permit GET STATUS on the ISD without authentication but require auth for the other scopes; auth-required scopes appear as SKIP rather than FAIL, so an operator can see exactly which scopes need an authenticated session for a complete view. Pass `--scp03-keys-default` (or the explicit `--scp03-{kvn,enc,mac,dek}` triple for a card with rotated keys) alongside `--full` to authenticate the registry walk and replace the SKIPs with populated entries. JSON output structures the registry under `data.registry.{isd, applications, load_files}` and reports the auth posture in `data.auth_mode` (`"none"` or `"scp03"`) for programmatic consumers.

`--sd-aid` targets a non-default Security Domain AID (see the `scpctl sd` group description above for the input shapes accepted). Required when the card uses a vendor-specific ISD AID; without it, SELECT against the GP-standard AID returns `6A82` (file not found) and the command fails on the first APDU.

```bash
scpctl sd info --reader "YubiKey" --full
scpctl sd info --reader "YubiKey" --full --json
scpctl sd info --reader "YubiKey" --full --scp03-keys-default --json
scpctl sd info --reader "VendorCard" --sd-aid A0:00:00:06:47:2F:00:01 --full
```

## Design notes worth knowing

These are not v0-only constraints; they're intentional shape:

- **SCP is applet-scoped on YubiKey.** This tool sets `SelectAID` on the SCP `Config` before opening the channel rather than opening on the ISD and then SELECTing PIV inside. Selecting a different applet inside an SCP session terminates the session.
- **CRD is advisory.** The probe reports what the card claims; subsequent commands do not inherit trust from the probe.
- **SCP11b never authorizes writes.** SCP11b proves card-to-host authentication only. Any operation requiring OCE authentication will be refused under SCP11b regardless of what the user asks for.
- **The library expects an explicit Config.** `nil` configs are rejected by both `scp03.Open` and `scp11.Open`. The CLI passes specific helper-built configs (e.g. `yubikey.FactorySCP03Config()`) so it's obvious to anyone reading the code which keys are in use.

## Cross-references

The library implementations and behaviors validated by this tool are documented in:

- YubiKey Technical Manual — `docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-scp-specifics.html`
- Yubico Python `yubikit.securitydomain` — CRD retrieval pattern, key info parsing
- Yubico .NET SDK `Yubico.YubiKey.Scp.SecurityDomainSession` — high-level session API
- GP Card Specification v2.3.1 §H.2/H.3 — Card Recognition Data structure
- GP Card Specification v2.3.1 Amendment F — SCP11

## Trust configuration for SCP11 commands

Every SCP11 subcommand (`scp11b-sd-read`, `scp11a-sd-read`, `scp11b-piv-verify`, `bootstrap-oce`, `piv provision`, `piv reset`) accepts the same two mutually-exclusive trust flags:

| Flag | Purpose |
|---|---|
| `--trust-roots <pem-path>` | **Production.** Loads CERTIFICATE blocks from the named PEM bundle and configures `cfg.CardTrustAnchors` so the card's certificate is verified during the SCP11 handshake. |
| `--lab-skip-scp11-trust` | **Lab only.** Skips card cert validation entirely. Against a real card this is opportunistic encryption, not authenticated key agreement. |

Neither flag set produces a `trust mode SKIP` and the command exits without opening the session. Both flags set is a usage error.

```bash
# Production: validate the card cert against a pinned Yubico SD root
scpctl test scp11b-piv-verify \
  --reader "YubiKey" \
  --pin 123456 \
  --trust-roots /etc/scp/yubikey-roots.pem

# Lab: skip validation for wire-only test
scpctl test scp11b-piv-verify \
  --reader "YubiKey" \
  --pin 123456 \
  --lab-skip-scp11-trust
```

The PEM bundle may contain multiple CERTIFICATE blocks; non-CERTIFICATE blocks (e.g. a stray private key) are rejected so a misnamed file doesn't silently produce an empty trust pool.

## SCP03 keys for `scp03-sd-read` and `bootstrap-oce`

Both commands default to YubiKey factory SCP03 keys (KVN `0xFF`, the publicly documented `404142...4F` AES-128 key set). For cards whose SCP03 keys have been rotated, supply the rotated set explicitly:

| Flag | Purpose |
|---|---|
| `--scp03-keys-default` | Explicit opt-in to factory keys. Same as the implicit default; useful when scripts want the choice to be visible. |
| `--scp03-kvn <hex byte>` | Custom key version number (e.g. `01`, `FF`). |
| `--scp03-enc <hex>` | Custom channel encryption key (16/24/32 bytes for AES-128/192/256). |
| `--scp03-mac <hex>` | Custom channel MAC key, same length as `--scp03-enc`. |
| `--scp03-dek <hex>` | Custom data encryption key, same length as `--scp03-enc`. |

The four custom-key flags must all be supplied together — partial specification fails closed at the CLI boundary so a half-completed rotation can't misfire. `--scp03-keys-default` and the custom-key flags are mutually exclusive. Hex values tolerate spaces, colons, and dashes for paste-from-docs convenience.

```bash
# Factory (implicit)
scpctl test scp03-sd-read --reader "YubiKey"

# Rotated to a custom AES-128 set
scpctl sd bootstrap-oce \
  --reader "YubiKey" \
  --oce-cert /path/to/oce-chain.pem \
  --scp03-kvn 01 \
  --scp03-enc 11111111111111111111111111111111 \
  --scp03-mac 22222222222222222222222222222222 \
  --scp03-dek 33333333333333333333333333333333 \
  --confirm-write
```

The CLI never logs key bytes — the report shows `SCP03 keys PASS — custom (KVN 0x01, AES-128)` (or `factory (KVN 0xFF, AES-128 well-known)`), nothing more.

## SCP11a/c management auth for `sd keys *` and `sd allowlist *`

Every management verb in the `sd` group (`allowlist set`/`clear`, `keys delete`/`generate`/`import`) accepts SCP11a or SCP11c as an alternative to SCP03 for cards that have been moved off shared-secret SCP03 management onto certificate-based authentication. SCP11b is deliberately **not** offered: it's one-way auth (the card authenticates to the host but the host does not authenticate to the card), and every OCE-gated command on these verbs would be rejected by the card with `SW=6982`. The flag parser refuses `--scp11-mode=b` at parse time so the failure is fast and the diagnostic is clear.

The flag set parallels the smoke-test surface but uses an `--scp11-` prefix to keep the auth flag group visually separate from the OCE-installation flags on `bootstrap-oce`:

| Flag | Purpose |
|---|---|
| `--scp11-mode a`\|`c` | SCP11 variant. `a` = mutual auth via certificate chain (GP slot KID `0x11`). `c` = mutual auth with receipt for scriptable replay (KID `0x15`). Empty default keeps the command on SCP03. |
| `--scp11-oce-key <pem>` | OCE private key (PKCS#8 or SEC1, P-256). Required when `--scp11-mode` is set. |
| `--scp11-oce-cert <pem>` | OCE certificate chain, leaf-last. Required when `--scp11-mode` is set. The card validates this chain against its installed OCE root before accepting the authentication. |
| `--scp11-oce-kid <hex>` | OCE Key ID on the card (defaults to `0x10` per Yubico factory). |
| `--scp11-oce-kvn <hex>` | OCE Key Version Number (defaults to `0x03`). |
| `--scp11-sd-kid <hex>` | Card-side SD key reference KID. Defaults to `0x11` for SCP11a or `0x15` for SCP11c per GP Amendment F §7.1.1. Override only for non-standard slots. |
| `--scp11-sd-kvn <hex>` | Card-side SD KVN. Defaults to `0x00` (GP literal "any version"). |
| `--scp11-trust-roots <pem>` | **Production.** PEM bundle of card root certificates. Loaded into `cfg.CardTrustAnchors` so the card's certificate is validated during the SCP11 handshake. |
| `--scp11-lab-skip-trust` | **Lab only.** Skip card cert validation. Reduces SCP11 to opportunistic encryption against an unauthenticated card key. Mutually exclusive with `--scp11-trust-roots`. |

`--scp03-*` and `--scp11-*` are mutually exclusive — pick one auth mode per command. The trust-config flags (`--scp11-trust-roots` vs `--scp11-lab-skip-trust`) are also mutually exclusive within the SCP11 group; opening SCP11 against an unauthenticated card key without explicit lab opt-in is opportunistic encryption rather than authenticated key agreement, and the helper refuses to do that silently.

```bash
# SCP03 (default) — historical management-auth path
scpctl sd keys delete \
  --reader "YubiKey" --kid 11 --kvn 7F \
  --confirm-delete-key

# SCP11a — cert-based mutual auth, production trust roots
scpctl sd allowlist set \
  --reader "VendorCard" \
  --kid 11 --kvn 01 \
  --serial 0x12ab --serial 0x34cd \
  --scp11-mode a \
  --scp11-oce-key /etc/oce/oce.key.pem \
  --scp11-oce-cert /etc/oce/oce.chain.pem \
  --scp11-trust-roots /etc/oce/card-roots.pem \
  --confirm-write

# SCP11c — same shape with the receipt-validating variant
scpctl sd keys generate \
  --reader "VendorCard" --kid 11 --kvn 02 \
  --scp11-mode c \
  --scp11-oce-key /etc/oce/oce.key.pem \
  --scp11-oce-cert /etc/oce/oce.chain.pem \
  --scp11-trust-roots /etc/oce/card-roots.pem \
  --confirm-write
```

The session report names which mode opened: `open SCP11 session PASS` (with the protocol string in JSON's `data.channel` reading `scp11a` or `scp11c`) or `open SCP03 session PASS` for the historical path.

## Status

- Current: `readers`, `probe`, `scp03-sd-read`, `scp11b-sd-read`, `scp11a-sd-read`, `scp11b-piv-verify`, `bootstrap-oce`, `piv-provision` (mgmt-key auth + cert-binding), `piv-reset`, `test`. SCP11 smoke commands accept `--trust-roots <pem>` for production trust validation. SCP03 commands accept `--scp03-{kvn,enc,mac,dek}` for rotated-key cards. The `sd` management verbs (`sd allowlist set`/`clear`, `sd keys delete`/`generate`/`import`) accept SCP11a/c as an alternative to SCP03 via the `--scp11-*` flag group documented above; SCP11b is rejected for OCE-gated operations. `sd info` tolerates SW=6283 from SELECT (CARD_LOCKED) and reports `data.card_locked=true` rather than failing closed, so an operator can describe a locked card; the `--sd-aid` flag targets a non-default Security Domain AID across every generic SD verb. `piv reset` is gated to YubiKey-profile cards only (Standard PIV refuses host-side, before INS=0xFB crosses the wire) and requires the dedicated `--confirm-reset-piv` flag.
- Next: `GET METADATA` (Yubico extension) for auto-detecting management-key algorithm against a card whose state isn't known up front.
- Deferred: SCP11c with `HostID` / `CardGroupID` — the `scp11.Config` fields are wired into the KDF but the AUTHENTICATE parameter bit and tag-`0x84` TLV on the wire side aren't, and `scp11.Open` fails closed if either is set. SCP11c WITHOUT those parameters works today as the receipt-validating variant of SCP11a (with `KID=0x15` per GP) and is what `--scp11-mode c` exposes; the deferred work is exclusively the host-identifier path. A dedicated `scp11c-sd-read` CLI command without the wire side would be a downgrade attack against operators who think they got SCP11c-with-host-binding. Holding until the protocol layer ships the wire side, which itself depends on transcript vectors from a card or reference implementation that exercises HostID/CardGroupID.
- Deferred: PIVMAN protected management key (YubiKey extension; not implemented). YubiKey ships a "protected management key" feature where the card stores the management key inside a YubiKey-specific data object (`PIVMAN_DATA` at `0x5FFF00`, `PIVMAN_PROTECTED_DATA` at `0x5FFF01`) protected by the PIN, so a PIN-only operator can authenticate management operations without holding the management-key bytes. ykman implements this; `scpctl` does NOT. The capability bit `ProtectedManagementKey` exists on YubiKey profiles for forward compatibility and is asserted false on Standard PIV, but no read or write path against `0x5FFF00` / `0x5FFF01` is wired. An operator with a YubiKey configured for protected management key cannot use `scpctl piv` to manage it; ykman is the right tool for that flow today. Adding this would require: (a) typed read/write paths for the PIVMAN data objects, (b) PIN-derived KDF for unprotecting the management-key bytes, (c) an opt-in CLI flag distinct from `--mgmt-key` so the operator clearly chooses between the two auth modes. Not on the near-term roadmap; the use case is YubiKey-specific and the threat model differs from the keys-as-flags pattern this CLI is built around. Per the third external review, Section 4: this feature is YubiKey-only PIVMAN behavior, NOT Standard PIV.

## Reset-blocked detection (deferred)

YubiKey BIO and some YubiKey configurations ship with PIV reset disabled by configuration. That state lives in a YubiKey-specific data object that `scpctl` does not currently read at probe time. As a result, `scpctl piv reset --confirm-reset-piv` against a card with reset disabled will reach the destructive path and the card will refuse with `SW=6985` ("conditions of use not satisfied"); an operator-side host-time refusal would be cleaner. Tracked as a deferred item (Section 2 item 5 of the third external review). Adding it requires (1) probe-time read of the relevant YubiKey config object, (2) a `Capabilities.ResetBlocked` flag wired through the profile layer, (3) a CLI refusal with a clear message before transmit. Not a regression on Standard PIV (where Reset is refused unconditionally regardless of the blocked state).
