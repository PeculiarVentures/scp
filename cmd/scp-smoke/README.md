# scp-smoke

Hardware smoke-test harness for the [`PeculiarVentures/scp`](https://github.com/PeculiarVentures/scp) library. Validates SCP03 and SCP11b against real PC/SC-attached cards (primarily retail YubiKeys) and emits PASS/FAIL/SKIP results suitable for both human and machine consumption.

This binary is hardware-targeting: most subcommands need an actual reader and card. For library-level testing without hardware, use the `mockcard` package directly.

## What this is for

The two questions this tool answers, against a real card:

1. **Does the SCP library produce wire bytes that an actual card accepts?** — `scp03-sd-read`, `scp11b-sd-read`, `scp11a-sd-read`
2. **Does the wire layer survive being wrapped around a higher-level applet protocol?** — `scp11b-piv-verify`

Plus a `probe` step that tells you what the card claims to be before you authenticate to it, and a `test` aggregator that runs the lot.

## Safety

This tool is read-only by default. It will **not**:

- Rotate SCP03 keys.
- Trigger authentication lockouts.
- Attempt Security Domain writes over SCP11b.
- Reset cards as a recovery mechanism.

A `restore-yubikey-factory` subcommand is described in the design doc but **deliberately not implemented in this version**. It will land in a follow-up under heavy guards: explicit destructive confirmation flag, OCE-authenticated session required, refused over SCP11b, and YubiKey-only.

## Build

This is a Go submodule with its own `go.mod` because [`transport/pcsc`](../../transport/pcsc) requires CGo and links against `pcsclite` / `winscard`.

### Linux

```bash
sudo apt install pcscd libpcsclite-dev   # Debian/Ubuntu
sudo dnf install pcsc-lite pcsc-lite-devel   # Fedora/RHEL
sudo systemctl enable --now pcscd

cd cmd/scp-smoke
go build -o scp-smoke .
```

### macOS, Windows

PC/SC is built into the OS. No package install needed; just `go build`.

## Usage

```text
scp-smoke <subcommand> [flags]
```

Run `scp-smoke help` or `scp-smoke <cmd> -h` for full flag lists.

### List PC/SC readers

```bash
scp-smoke readers
```

```bash
scp-smoke readers --json
```

### Probe a card

Opens an unauthenticated Security Domain session, fetches Card Recognition Data via `GET DATA` tag `0x66`, parses, and prints the card's claimed capabilities.

```bash
scp-smoke probe --reader "YubiKey"
```

Sample output:

```
scp-smoke probe
  reader: YubiKey
  select ISD                       PASS
  GET DATA tag 0x66                PASS — 76 bytes
  parse CRD                        PASS
  GP version                       PASS — 2.3.1
  SCP advertised                   PASS — SCP03 i=0x65
```

CRD is **discovery input, not authorization**. A card that lies about its CRD is the card's bug; this tool does not infer trust from the probe output.

### SCP03 Security Domain read

Opens an SCP03 session against the ISD using YubiKey factory credentials (KVN `0xFF`, key `404142434445464748494A4B4C4D4E4F` for ENC/MAC/DEK), then verifies that `GetKeyInformation` and `GetCardRecognitionData` succeed under secure messaging.

```bash
scp-smoke scp03-sd-read --reader "YubiKey"
```

This is expected to fail on a YubiKey that has had its SCP03 keys rotated to a custom KVN — that's an informative failure, not a bug. Custom-key flag support (`--kvn`, `--enc`, `--mac`, `--dek`) is a follow-up; it isn't in this version because the threshold for "is the wire working at all?" doesn't need it.

### SCP11b Security Domain read

```bash
scp-smoke scp11b-sd-read --reader "YubiKey" --lab-skip-scp11-trust
```

SCP11b authenticates the card to the host but **not** the host to the card. The smoke check verifies this by asserting `Session.OCEAuthenticated()` is `false`. After that it issues `GetKeyInformation` to exercise the wire layer.

`--lab-skip-scp11-trust` skips the SCP11 card-certificate validation step. This is for separating "the wire-protocol is broken" from "the trust bootstrap isn't configured." When the flag is omitted and no trust roots are configured, this command **skips** rather than fails — the rationale is that an unconfigured trust state is not a wire-protocol failure.

### SCP11b → PIV → VERIFY PIN

Opens an SCP11b session targeting the PIV applet (NOT the ISD; SCP is applet-scoped on YubiKey) and verifies the PIN over the secure channel.

```bash
scp-smoke scp11b-piv-verify --reader "YubiKey" --pin 123456 --lab-skip-scp11-trust
```

A successful `VERIFY PIN` proves three things at once: SCP11b can target a non-SD applet, the PIV APDU builders survive secure-messaging wrap, and the card accepts the PIN through the wrapped channel.

If the card returns a `63Cx` SW (PIN wrong, x retries), the failure surfaces with the status word in the error so you can distinguish "wire broken" from "PIN wrong."

### SCP11a Security Domain read

SCP11a is mutual auth: the host validates the card AND the card validates the host's OCE certificate chain against an OCE root that was previously installed on the card. After a successful open, the session is OCE-authenticated and capable of driving SD writes (key rotation, certificate store, allowlist updates).

```bash
scp-smoke scp11a-sd-read \
  --reader "YubiKey" \
  --oce-key /path/to/oce.key.pem \
  --oce-cert /path/to/oce-chain.pem \
  --lab-skip-scp11-trust
```

Pre-conditions for this to succeed against real hardware:

1. The card has an OCE root + key reference provisioned at `--oce-kid` (default `0x10`) / `--oce-kvn` (default `0x03`). On factory-fresh YubiKey this is **not** the case; the OCE has to be bootstrapped first (see `bootstrap-oce`, follow-up).
2. The OCE private key file corresponds to the leaf certificate in the chain.
3. The chain leaf is signed by the OCE root the card has installed.

The smoke command asserts the SCP11a-specific invariant `Session.OCEAuthenticated() == true` — a regression that silently downgraded to SCP11b-shape session keys would be caught here rather than going unnoticed.

PEM key formats accepted: PKCS#8 (`PRIVATE KEY`, modern `openssl genpkey` default) and SEC1 (`EC PRIVATE KEY`, what older `openssl ecparam -genkey` produces and what Yubico fixtures use). Curve must be P-256 — the loader rejects other curves explicitly.

### bootstrap-oce — Day-1 OCE provisioning

Installs an OCE public key (and optionally a certificate chain + CA Subject Key Identifier) onto a card via SCP03 with factory keys, so subsequent SCP11a sessions can complete mutual auth. This is the step that has to happen *before* `scp11a-sd-read` works against a fresh card.

```bash
scp-smoke bootstrap-oce \
  --reader "YubiKey" \
  --oce-cert /path/to/oce-chain.pem \
  --store-chain \
  --ca-ski 0123456789ABCDEF0123456789ABCDEF01234567 \
  --confirm-write
```

Without `--confirm-write` the command runs in **dry-run mode**: it loads and validates the cert chain, types the public key, prints what it would do, and exits without transmitting any APDU that mutates card state. This mirrors the safety pattern in the destructive-ops note above and gives operators a way to sanity-check inputs before flipping the card.

The CLI assumes SCP03 factory keys (KVN `0xFF`, default ENC/MAC/DEK). A card whose SCP03 keys have already been rotated will get an authentication error from `OpenSCP03` — custom-keys flags (`--kvn`, `--enc`, `--mac`, `--dek`) are follow-up work; the structural mechanism is straightforward (build an `scp03.Config` from the flags rather than calling `FactoryYubiKeyConfig`).

`--store-chain` calls `STORE CERTIFICATES` so the card has the full OCE chain locally, useful when its trust model validates against the chain rather than just the root. `--ca-ski` registers a CA Subject Key Identifier via `STORE CA-IDENTIFIER`. Either or both can be omitted; the OCE public-key install is the only required step.

### piv-provision — generate a slot keypair (and optionally install a cert)

Provisions a PIV slot through an SCP11b-secured channel: `VERIFY PIN` → `GENERATE KEY` → optional `PUT CERTIFICATE` → optional `ATTESTATION`. Same `--confirm-write` dry-run gating as `bootstrap-oce`.

```bash
scp-smoke piv-provision \
  --reader "YubiKey" \
  --pin 123456 \
  --slot 9a \
  --algorithm eccp256 \
  --cert /path/to/leaf.pem \
  --attest \
  --lab-skip-scp11-trust \
  --confirm-write
```

Slots: `9a` (PIV Authentication), `9c` (Digital Signature), `9d` (Key Management), `9e` (Card Authentication), and the `82` retired-key range. Algorithms: `rsa2048`, `eccp256`, `eccp384`, plus YubiKey 5.7+ exclusives `ed25519` and `x25519`.

**Cert-to-pubkey binding check.** When `--cert` is supplied, after `GENERATE KEY` succeeds, `piv-provision` parses the public key returned by the card and refuses to install the cert if its public key does not match. Without this check, a wrong cert (different slot, stale chain, typo'd path that resolved to something unintended) would install onto a slot whose keypair doesn't actually correspond — the slot would then attest to an identity it can't prove possession of. Mismatch produces a `cert binding FAIL` line and a non-zero exit; `PUT CERTIFICATE` is not transmitted.

The check runs against the parsed public key for the relevant algorithm: RSA (modulus + exponent), ECDSA (curve + X/Y), Ed25519 (32-byte raw). X25519 keys are not bound by X.509 certs, so the binding step is skipped with a `parse pubkey SKIP` note.

**Management-key authentication.** PIV `GENERATE KEY` and `PUT CERTIFICATE` are gated on PIV management-key authentication on stock cards. Pass `--mgmt-key` (hex) and `--mgmt-key-algorithm` to run the mutual-auth flow before the writes. Without `--mgmt-key`, the auth step is skipped — useful for testing the rest of the sequence against a card you've already authenticated to out of band, or against the mock with no enforcement configured.

```bash
# YubiKey with the historic pre-5.7 factory 3DES default
scp-smoke piv-provision \
  --reader "YubiKey" --pin 123456 --slot 9a \
  --mgmt-key default --mgmt-key-algorithm 3des \
  --lab-skip-scp11-trust --confirm-write

# YubiKey 5.7+ with a rotated AES-192 management key
scp-smoke piv-provision \
  --reader "YubiKey" --pin 123456 --slot 9a \
  --mgmt-key A1B2C3...  --mgmt-key-algorithm aes192 \
  --lab-skip-scp11-trust --confirm-write
```

`--mgmt-key default` is shorthand for the well-known pre-5.7 YubiKey 3DES factory key; only valid with `--mgmt-key-algorithm 3des`. The hex value accepts spaces, colons, and dashes for paste-from-docs convenience. Length is validated against the algorithm at the CLI boundary.

The mock implements crypto-correct mutual auth when `PIVMgmtKey` and `PIVMgmtKeyAlgo` are configured; tests use this to round-trip the full flow without real hardware.

### `test` aggregator

Runs `probe` + the SCP smoke checks in sequence and prints a single PASS/FAIL/SKIP summary at the end.

```bash
scp-smoke test \
  --reader "YubiKey" \
  --pin 123456 \
  --oce-key /path/to/oce.key.pem \
  --oce-cert /path/to/oce-chain.pem \
  --lab-skip-scp11-trust
```

Process exit code is 1 if any check failed; 0 otherwise (including SKIP results). The SCP11a check is skipped automatically if `--oce-key`/`--oce-cert` are not supplied.

## Design notes worth knowing

These are not v0-only constraints; they're intentional shape:

- **SCP is applet-scoped on YubiKey.** This tool sets `SelectAID` on the SCP `Config` before opening the channel rather than opening on the ISD and then SELECTing PIV inside. Selecting a different applet inside an SCP session terminates the session.
- **CRD is advisory.** The probe reports what the card claims; subsequent commands do not inherit trust from the probe.
- **SCP11b never authorizes writes.** SCP11b proves card-to-host authentication only. Any operation requiring OCE authentication will be refused under SCP11b regardless of what the user asks for.
- **The library expects an explicit Config.** `nil` configs are rejected by both `scp03.Open` and `scp11.Open`. The CLI passes specific helper-built configs (e.g. `scp03.FactoryYubiKeyConfig()`) so it's obvious to anyone reading the code which keys are in use.

## Cross-references

The library implementations and behaviors validated by this tool are documented in:

- YubiKey Technical Manual — `docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-scp-specifics.html`
- Yubico Python `yubikit.securitydomain` — CRD retrieval pattern, key info parsing
- Yubico .NET SDK `Yubico.YubiKey.Scp.SecurityDomainSession` — high-level session API
- GP Card Specification v2.3.1 §H.2/H.3 — Card Recognition Data structure
- GP Card Specification v2.3.1 Amendment F — SCP11

## Status

- Current: `readers`, `probe`, `scp03-sd-read`, `scp11b-sd-read`, `scp11a-sd-read`, `scp11b-piv-verify`, `bootstrap-oce`, `piv-provision` (with mgmt-key mutual auth), `test`.
- Next: custom SCP03 key flags for `bootstrap-oce` against rotated cards (`--kvn` / `--enc` / `--mac` / `--dek`), and a `piv-mgmt-key-set` command that runs SetManagementKey with mutual auth as a precondition.
- Deferred: SCP11c support — the `scp11.Config` HostID/CardGroupID fields are wired into the KDF but the AUTHENTICATE parameter bit and tag-`0x84` TLV on the wire side aren't, and `scp11.Open` fails closed if either is set. Adding a `scp11c-sd-read` CLI command without the wire side would be a downgrade attack against operators who think they got SCP11c. Holding until the protocol layer ships the wire side, which itself depends on transcript vectors from a card or reference implementation that exercises HostID/CardGroupID.
- Deferred: `restore-yubikey-factory` (destructive; needs explicit-destructive-confirmation flag, OCE-auth requirement, SCP11b refusal, YubiKey-only).
