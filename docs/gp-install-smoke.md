# GP install smoke runbook

This document is the operator-facing runbook for taking a small JavaCard CAP file from "I think it should install" to "the applet is provably selectable on the card." It is intentionally narrow: simple non-DAP applet provisioning on a modern SCP11-capable GlobalPlatform card. Delegated Management, DAP signing, SCP02, and bytecode verification are out of scope and not covered here.

## What you need

A SCP11-capable JavaCard reachable over PC/SC. YubiKey 5.7+, recent NXP/Infineon GP-conformant cards, and most SCP03+SCP11 dual-stack cards work. Vendor-locked cards where the card manager keys are mediated by a closed-source middleware (SafeNet eToken Fusion, SafeNet Token JC) will not work for this flow without breaking another auth gate first; pick a different card.

A small CAP file. The Java Card SDK ships HelloWorld; any other minimal applet works. The smaller the better — a 2-4 KB CAP exercises every code path without the chunked-LOAD edge cases that larger applets hit. Note the package AID, the module AID, and the applet AID; you will pass all three on the command line.

The `scpctl` binary built from this repo. `cd cmd/scpctl && go build -o ~/bin/scpctl .` is the standard build.

## Phase 1: identify the card

Before any destructive operation, confirm the card is reachable, GP-conformant, and not in a constrained lifecycle state.

```bash
scpctl readers
```

You should see exactly one reader name in the output. Pick one and export it for the rest of the session:

```bash
export READER='<reader name from above>'
```

```bash
scpctl probe --reader "$READER" --discover-sd
```

The probe should return a JSON or text report identifying the card class (YubiKey, generic GP, etc.), the SD AID (often the GP standard `A000000151000000` but sometimes vendor-specific), and any GET DATA tags the card answers without authentication. If `probe` reports `card_locked: true`, stop — the card needs a vendor-mediated reset before any install will succeed.

```bash
scpctl sd info --reader "$READER" --discover-sd --full
```

This reads the unauthenticated portion of the SD: CRD (Card Recognition Data, GP §H.2), KIT (Key Information Template), CPLC if the card permits unauthenticated reads. The `--full` flag also surfaces vendor-specific GET DATA tags. If `sd info` returns 6A88 for everything, the SD permits no unauthenticated reads — proceed anyway, the auth path may still work.

## Phase 2: prove the card answers SCP11

Before the destructive install, prove the card's SCP11 stack works. `--lab-skip-scp11-trust` skips certificate-chain validation — appropriate for lab work where you don't have the card's CA chain pinned, NOT appropriate for production fleets.

```bash
scpctl sd info \
  --reader "$READER" \
  --discover-sd \
  --scp11b \
  --lab-skip-scp11-trust \
  --full
```

If this returns SW=9000 and reads a populated KIT, the SCP11 channel is working. If this fails:

- Card returns `6A88` to GET DATA over SCP11: the card has SCP11 disabled or the SCP11 keyset isn't provisioned. Check with the vendor whether SCP11 is the default channel; some cards ship SCP03-only and require explicit SCP11 enablement.
- Card returns `6982` to MUTUAL AUTHENTICATE: the card's SCP11 trust posture rejects an unsigned/untrusted OCE. `--lab-skip-scp11-trust` is host-side only and does not bypass card-side trust enforcement.
- Card never responds to AUTHENTICATE: GP §10.5 SCP11 isn't supported on this card. Fall back to SCP03 — the install flow works identically; replace `--scp11b --lab-skip-scp11-trust` with `--scp03-keys-default` (or rotated keys via `--scp03-kvn/enc/mac/dek`).

## Phase 3: dry-run the install

The dry-run mode validates inputs, parses the CAP, computes hashes, and reports the planned operations without transmitting any destructive APDU. The point of the dry-run is to catch CLI-level mistakes (wrong AID, malformed install params) before the card mutates.

```bash
scpctl gp install \
  --reader "$READER" \
  --cap path/to/HelloWorld.cap \
  --package-aid <package-aid-hex> \
  --applet-aid <applet-aid-hex> \
  --module-aid <module-aid-hex> \
  --scp11b \
  --lab-skip-scp11-trust \
  --json
```

(Without `--confirm-write`, the command runs in dry-run mode.)

The output should show:

- `load_file_data_block_size`: the LFDB byte count (the input to the install hash).
- `load_file_size`: the wire-format Load File byte count (LFDB plus C4 wrapper, what gets streamed through LOAD).
- `load_file_prefix_hex`: the first 16 bytes of the wire stream. **This must start with `C4`** (or `E2` if you're DAP-signing, which this runbook doesn't cover). If it starts with anything else, the host is producing a malformed Load File and would fail on a real card.
- `load_file_data_block_sha256`: the LFDB SHA-256. Note this for post-install verification if the card stores LFDBH.
- `load_block_count` and `load_block_size`: the chunk plan. Reasonable values: `load_block_count` ≤ 256 (one-byte sequence number cap), `load_block_size` 200 bytes default.
- `package_aid` / `applet_aid` / `module_aid` echoed back: confirm these match the AIDs the CAP file declares. A mismatch here is the most common cause of `--verify-select` failure later.

## Phase 4: do the install

Once the dry-run looks right, run the actual install. The `--verify-select` flag is recommended on every real-card run: it issues a basic-channel SELECT for the applet AID after install completes and requires SW=9000, giving a smoke proof that the applet is actually selectable rather than just that LOAD/INSTALL returned success.

```bash
scpctl gp install \
  --reader "$READER" \
  --cap path/to/HelloWorld.cap \
  --package-aid <package-aid-hex> \
  --applet-aid <applet-aid-hex> \
  --module-aid <module-aid-hex> \
  --scp11b \
  --lab-skip-scp11-trust \
  --confirm-write \
  --verify-select
```

Expected output on success:

```
PASS  INSTALL [for load]: load file <package-aid> registered
PASS  LOAD blocks: <N> bytes streamed
PASS  INSTALL [for install]: applet <applet-aid> installed
PASS  verify-select: applet <applet-aid> selectable (SW=9000, FCI <M> bytes)
```

## Diagnostics

If the install fails, the failure stage tells you where to look:

| Stage failure | Likely causes |
|---|---|
| `INSTALL [for load]` | Package AID conflict (already installed; delete first), wrong load params, SD lifecycle constraint, applet exceeds card EEPROM. |
| `LOAD` mid-stream | Card rejected a LOAD block. Common: load block size too large for card's max APDU buffer (try `--load-block-size 128` or smaller). Less common: malformed LFDB (re-check the dry-run's `load_file_prefix_hex` starts with `C4`). |
| `INSTALL [for install]` | Applet AID conflict (already installed; delete first). Wrong install_params — the applet's installer expected specific TLV bytes. Privileges out of range. Module AID doesn't match a class actually present in the LFDB. |
| `verify-select` returned non-9000 SW | LOAD and INSTALL succeeded but the applet isn't selectable. Most common: `--applet-aid` typed wrong (the AID was registered but doesn't match what you're SELECTing). Less common: applet refused init_params during install and the lifecycle stayed at INSTALLED rather than advancing to SELECTABLE. Check the card vendor docs for required install params. |

## Branching guide

Quick triage for which subsystem to focus on:

- **SCP03 works but SCP11 fails**: focus on SCP11 channel/trust/key behavior. Re-run Phase 2 with verbose output. Likely candidates: card SCP11 disabled, OCE certificate chain not accepted, key usage qualifier mismatch.
- **Both SCP03 and SCP11 fail at LOAD**: focus on GP Load File formatting, block size, CAP content, or install params. The dry-run's `load_file_prefix_hex` starting with `C4` is the first thing to verify.
- **LOAD succeeds but verify-select fails**: focus on applet AID, install params, applet lifecycle, or module/app selection. Re-read the CAP file's AID declarations and confirm against `--applet-aid`/`--module-aid`/`--package-aid`.

## What NOT to do

If the card returns SW=6982 to INITIALIZE UPDATE before any cryptogram exchange, the card refused at policy level without ever testing key material. **Do not loop trying different keys** — the failed-auth counter (if any) is not the gate. See `docs/safenet-token-jc.md` for the long-form analysis of this case; the short version is that the card needs a vendor-mediated handshake that scpctl can't replay, and trying random keys won't break the gate.

## Out of scope for this runbook

- Delegated Management. The C4 Load File path this runbook exercises is the non-DM path. DM token computation requires keys and infrastructure that fleet operators have but lab work usually doesn't.
- DAP signing. The smoke runbook uses `gp.LoadFileOptions{}` defaults, which produce a plain C4-wrapped Load File without DAP blocks. Cards configured to require DAP-signed loads will reject the install at LOAD. Use a non-DAP-required card for the smoke run.
- SCP02. The library does not implement SCP02. Cards that only speak SCP02 are not supported by this runbook.
- Bytecode verification. The host does not run JC bytecode verifiers. The card's runtime does its own verification at install time; if the CAP is malformed, INSTALL [for install] returns an error and the install fails. Use the Java Card SDK's `verifycap` tool offline before bringing CAPs to a card if you don't trust the source.
