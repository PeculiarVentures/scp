# scp-smoke

Hardware smoke-test harness for the [`PeculiarVentures/scp`](https://github.com/PeculiarVentures/scp) library. Validates SCP03 and SCP11b against real PC/SC-attached cards (primarily retail YubiKeys) and emits PASS/FAIL/SKIP results suitable for both human and machine consumption.

This binary is hardware-targeting: most subcommands need an actual reader and card. For library-level testing without hardware, use the `mockcard` package directly.

## What this is for

The two questions this tool answers, against a real card:

1. **Does the SCP library produce wire bytes that an actual card accepts?** — `scp03-sd-read`, `scp11b-sd-read`
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

### `test` aggregator

Runs `probe` + the three smoke checks in sequence and prints a single PASS/FAIL/SKIP summary at the end.

```bash
scp-smoke test --reader "YubiKey" --pin 123456 --lab-skip-scp11-trust
```

Process exit code is 1 if any check failed; 0 otherwise (including SKIP results).

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

- v0 (this version): `readers`, `probe`, `scp03-sd-read`, `scp11b-sd-read`, `scp11b-piv-verify`, `test`.
- v0.1 (next): `restore-yubikey-factory` (guarded), trace capture with redaction, custom SCP03 key flags.
- v1 (later): PIV provisioning over SCP, OCE trust bootstrap, SCP11a/c support.
