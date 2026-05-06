# `sd keys` and `sd allowlist` CLI plan

Status: proposal (revision 4 — Phase 2 design corrected after upstream check)
Audience: project maintainers
Scope: closing the operator-facing gaps between `scpctl sd` and the underlying `securitydomain.Session` API. Not a `ykman` clone.

## Background

A code-first comparison of `scpctl` and `Yubico/yubikey-manager` was written against the `gp/main-body` branch (commit `0ffb653`-era) and surfaced a single high-value parity gap: a generic, key-centric Security Domain CLI surface composed from the existing `securitydomain.Session` primitives.

That comparison is a useful starting point but is partly stale relative to current `main`. This document captures the prioritized, current-state plan.

Revision 4 corrects Phase 2: the Yubico Python SDK (`yubikit/securitydomain.py`) has `store_allowlist` but no `get_allowlist`. Reading the on-card allowlist back is not a supported operation in the upstream reference. Trying to invent one would be guessing at wire shape against a card that probably doesn't expose the read. Phase 2 drops `sd allowlist get` entirely and ships only `set` and `clear`. Operators maintain the authoritative allowlist in their own systems and use `set` to push it to the card.

Earlier revisions: rev 2 fixed phase numbering, fail-by-default for `sd keys export`, the read-only authentication model, explicit unknown-KID handling, and the OCE/CA versus SD-key import semantic split. Rev 3 incorporated review feedback: SCP03 import scope tightened to AES-128 (matching current library PUT KEY constraints); selective cert fetch in `sd keys list` to skip SCP03 references; delete-flag validation rules; `sd keys generate` documented as profile-gated; the SCP11c write-auth integration test made disposable, lab-gated, and self-cleaning; Phase 1 stable check names plus atomic file-write semantics defined as part of the contract.

## What's already done that the input comparison treats as missing

The library API is more complete than the input read implies:

- `PutSCP03Key(ref, keys, replaceKvn)` — SCP03 triple import. Library currently rejects key components that aren't 16 bytes (AES-128).
- `GenerateECKey(ref, replaceKvn)` — on-card EC key generation, returns SPKI. Uses INS=0xF1 (Yubico extension, **not** GP standard).
- `PutECPrivateKey(ref, key, replaceKvn)` — SCP11 private key import.
- `PutECPublicKey(ref, key, replaceKvn)` — OCE/CA public key install.
- `DeleteKey(ref, deleteLast)` — already supports both KID-targeted and KVN-only deletion.
- `StoreCertificates(ref, certs)` / `GetCertificates(ref)` — full cert bundle round-trip.
- `StoreCaIssuer(ref, ski)` — SKI registration.
- `StoreAllowlist(ref, serials)` / `ClearAllowlist(ref)` — allowlist write CRUD. **Read API intentionally not added** (see Phase 2 below).
- `GetSupportedCaIdentifiers(kloc, klcc)` — KLOC/KLCC query.
- `GetKeyInformation()` — KID/KVN/component summary.

The CLI also already covers more than the input describes:

- `sd info` walks the GP registry under `--full`.
- `sd lock` / `sd unlock` / `sd terminate` exist with distinct blast-radius gates.
- `sd terminate` uses `--confirm-terminate-card`; `sd reset` uses `--confirm-reset-sd`; `piv reset` uses `--confirm-reset-piv`. Ordinary writes use `--confirm-write`. New destructive `sd keys` work follows the same one-flag-per-blast-radius rule.

## What's actually missing in the CLI

Five things, in five phases. Read-only first, then writes split by hazard level (allowlist before key delete, generate before import):

1. **`sd keys list`** and **`sd keys export`** — read-only key/cert presentation. SCP03 authenticated-fallback support so the design holds for cards that gate key-information or cert-store reads behind authentication.
2. **`sd allowlist set` / `clear`** — production SCP11a policies need allowlist management. Read is intentionally omitted (see asymmetry note below).
3. **`sd keys delete`** — destructive, distinct confirm gate. Lands together with the YubiKey SCP11c write-authorization measurement.
4. **`sd keys generate`** — on-card EC key generation. Profile-gated (Yubico extension INS=0xF1).
5. **`sd keys import`** — KID-dispatched key install. Higher hazard: SCP03 triple parsing (AES-128 only initially), EC private key handling, public-cert / chain semantics, replace-KVN, SKI derivation.

The bootstrap flows (`bootstrap-oce`, `bootstrap-scp11a`, `bootstrap-scp11a-sd`) stay. They encode the fresh-card sequencing that avoids the factory-key consumption foot-gun and they are a better operator workflow than composing the lower-level primitives by hand. The new commands sit beside them, not in place of them.

## Branching model

This work lands as one branch — `feat/sd-keys-cli` — with each phase as its own commit (or small commit cluster) for clean review-time bisection. The earlier "each phase is one PR" wording in revisions 1–3 is replaced by the single-branch model.

## Non-goals

- Whole-device YubiKey UX (FIDO/OATH/OpenPGP/OTP/HSMAuth/`config`). Out of scope.
- Raw operator APDU shell. Useful in a lab; not product-critical; stays out of `sd`/`piv` if it ever lands.
- A speculative shared "secure-channel profile" abstraction across commands. Useful if and when concrete flag duplication becomes painful — defer until then.
- A separate `gp` command group on `main`. The `gp/main-body` work is on its own branch; if and when it merges, GP destructive operations are GP differentiation, not `ykman` parity.
- **Reading the on-card allowlist back.** See Phase 2.

## Authentication model for read-only commands

The default path is unauthenticated. The library exposes `OpenUnauthenticated` and the operations `sd keys list` and `sd keys export` rely on (`GetKeyInformation`, `GetSupportedCaIdentifiers`, `GetCertificates`) do not call `requireOCEAuth()` — they work without an established channel on YubiKey today.

But the read-permissions are card-defined, not standard. A non-YubiKey GP card may reasonably require SCP03 authentication before returning the Key Information Template or the cert store. The design has to allow for that without making YubiKey operators do extra work.

```text
sd keys list, sd keys export

  no auth flag set:
    Open unauthenticated. Optional sections (KLOC/KLCC, per-ref
    cert fetch when no chain) fail soft as SKIPs. Required reads
    (KIT for list; cert chain for export with no --allow-empty)
    fail hard.

  --scp03[-keys-default] or --scp03-{kvn,enc,mac,dek}:
    Open SCP03-authenticated. Same key-flag semantics as
    bootstrap-* commands but with read-only-aware help text
    (registerSCP03KeyFlags(fs, scp03Optional)). Auth failure is
    FAIL, not SKIP.
```

SCP11a authenticated fallback for read-only commands is a Phase 1b follow-up if there is demand.

## Stable check names (Phase 1)

The `Report.Checks` stream is the audit-log substrate. Operators and pipelines depend on the names not changing once published. Phase 1 commits to these names:

```text
sd keys list:
  select ISD                                  unauth path
  open SCP03 session                          auth path
  SCP03 keys                                  auth path label
  GET DATA tag 0x00E0 (KIT)
  GET DATA tags 0xFF33/0xFF34 (KLOC/KLCC)
  certificates kid=0x.. kvn=0x..              one per KIT entry

sd keys export:
  select ISD                                  unauth path
  open SCP03 session                          auth path
  SCP03 keys                                  auth path label
  GET DATA tag 0xBF21 kid=0x.. kvn=0x..
  chain present                               FAIL or SKIP per --allow-empty
  encode chain
  write file
```

Phase 2 extends the same shape:

```text
sd allowlist set:
  SCP03 keys                                  auth label
  open SCP03 session
  STORE DATA allowlist kid=0x.. kvn=0x..

sd allowlist clear:
  SCP03 keys
  open SCP03 session
  STORE DATA allowlist clear kid=0x.. kvn=0x..
```

Names are deliberately APDU-tag-anchored rather than abstract. When something fails on a card, knowing which GET DATA / STORE DATA tag the host requested is the fastest path to a diagnosis.

## Output safety: atomic file writes

`sd keys export` (and later `sd keys generate` for the SPKI output) write through an atomic helper:

```text
1. CreateTemp in the same directory as --out.
2. Write data.
3. Sync.
4. Close.
5. Chmod to requested mode.
6. Rename onto --out.

On any error after CreateTemp, the temp file is removed before
returning. On a successful run, no temp leftover remains in the
output directory.
```

The contract: after the command, the path named by `--out` either contains the complete, valid output or does not exist. There is no partial state.

## Command surface

### `sd keys list`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Composes `GetKeyInformation()` (every run), `GetSupportedCaIdentifiers(true, true)` (every run, missing tags are SKIP), and `GetCertificates(ref)` **only for cert-capable kinds**. SCP03 references skip cert fetch with a SKIP labelled `"scp03 ref (no chain expected)"`. Cert-capable kinds are SCP11 SD refs, OCE/CA public-key refs, and `unknown` (operator inspection of unfamiliar cards).

`kind` is derived host-side from `kid`:

```text
0x01           → "scp03"
0x10           → "ca-public"
0x11           → "scp11a-sd"
0x13           → "scp11b-sd"
0x15           → "scp11c-sd"
0x20–0x2F      → "ca-public"
anything else  → "unknown"
```

No private material in output ever. KCV / SPKI fingerprints / public SKIs only.

### `sd keys export`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Writes the certificate chain for one key reference as PEM (or DER on `--der`). Output goes through the atomic write helper.

```text
default behavior:
  exit 1, FAIL check named "chain present", no output file written.

--allow-empty:
  exit 0, SKIP check named "chain present", JSON-visible
  "certificates": [].
```

### `sd allowlist set` / `clear`

**Write-only by design.** Authenticated SCP03 (or SCP11a in Phase 2b). Both gate on `--confirm-write`. Library calls: `Session.StoreAllowlist` and `Session.ClearAllowlist` — already public.

```text
scpctl sd allowlist set   --kid 11 --kvn 01 --serial 1234 --serial 5678 --confirm-write [--scp03-* ...]
scpctl sd allowlist clear --kid 11 --kvn 01                              --confirm-write [--scp03-* ...]
```

`--serial` is repeatable and accepts decimal or `0x`-prefixed hex. Empty allowlist (zero `--serial` flags) on `set` is rejected as a usage error — operators who mean "remove the allowlist" use `clear` so the intent is unambiguous.

Dry-run by default: without `--confirm-write`, the command validates inputs, reports the planned action and key reference, and exits 0 without opening SCP03 or transmitting STORE DATA. Same dry-run pattern as `sd lock` / `sd unlock` / `sd terminate`.

#### Why no `sd allowlist get`

The Yubico Python SDK (`yubikit/securitydomain.py`) implements `store_allowlist` and `store_certificate_bundle` / `get_certificate_bundle`, but it does **not** implement `get_allowlist`. The on-card allowlist appears to be effectively write-only on retail YubiKey: there is no documented GET DATA tag for retrieving stored serials.

Inventing a speculative GET path here would mean guessing at wire shape against a card that almost certainly returns SW=6A88, producing a CLI verb that doesn't work in practice. Worse, it would invite operators to rely on it as a source of truth.

The production model is the right one: operators maintain the canonical allowlist in their own systems (configuration files, secret stores, deployment manifests) and use `sd allowlist set` to push the canonical list to the card. The card holds a deployed copy, not the source of record. Any drift between the operator's source of truth and the card is detected by re-applying `set` — `set` is idempotent at the card level (full replacement, not merge).

If a future YubiKey firmware exposes a documented GET path, or another card profile supports allowlist read, this decision can be revisited. Until then, attempting to read is worse than acknowledging the asymmetry honestly.

#### `sd allowlist set` flag-validation rules

```text
--kid + --kvn + at least one --serial:
  install the allowlist with the given serials.
--kid + --kvn alone (no --serial):
  USAGE ERROR. Use 'sd allowlist clear' instead — the empty allowlist
  has the same wire effect but the intent is explicit.
missing --kid or --kvn:
  USAGE ERROR.
--serial fails to parse as a non-negative integer:
  USAGE ERROR naming the offending --serial value.
```

### `sd keys delete`

Destructive. Authenticated SCP03 or SCP11a (mutual). Gated on `--confirm-delete-key` (NOT `--confirm-write`).

**Flag validation rules:**

```text
--kid + --kvn (no --all):
  delete exactly that ref. Maps to DeleteKey(ref, deleteLast=false).

--kvn + --all (no --kid):
  delete all keys at that KVN. Maps to DeleteKey({_, kvn}, deleteLast=true).

--kid only (no --kvn):
  USAGE ERROR.
--kvn only (no --all):
  USAGE ERROR.
--all + --kid:
  USAGE ERROR.
```

### `sd keys generate`

**Profile-gated.** GENERATE EC KEY uses INS=0xF1 — a Yubico extension. The CLI must detect the active profile and refuse host-side before sending the APDU on cards that don't declare support.

Authenticated SCP03 or SCP11a. Gated on `--confirm-write`. KID validation: must be an SCP11 SD slot (0x11 / 0x13 / 0x15). Composes `GenerateECKey`. Output (SPKI as PEM) goes through the atomic write helper.

### `sd keys import`

Authenticated. Gated on `--confirm-write`. KID-dispatched, with two distinct semantic categories kept separate:

| KID                     | Category                        | Library calls                                 | Cert handling                          |
|-------------------------|---------------------------------|-----------------------------------------------|----------------------------------------|
| `0x01`                  | SCP03 key set (**AES-128 only**)| `PutSCP03Key`                                 | n/a                                    |
| `0x10`, `0x20–0x2F`     | OCE / CA trust anchor           | `PutECPublicKey` + `StoreCaIssuer`            | OCE leaf chain is **wire-only**; do NOT call `StoreCertificates` for trust anchors. |
| `0x11`, `0x13`, `0x15`  | SD key (SCP11 endpoint key)     | `PutECPrivateKey` + optional `StoreCertificates` | Chain stored against the SD key ref via STORE DATA when `--certs` is given. |

**SCP03 import scope:** Phase 5 supports AES-128 SCP03 key triples only.

## SCP11c write authorization — measurement, lab-gated, self-cleaning

The library treats SCP11c as `oceAuthenticated=true` (correct per GP — SCP11c is mutual). `ykman` device tests behave as if SCP11c writes are rejected on YubiKey. Possibilities: card-side policy rejects, or `ykman`'s test phrasing reflects a `ykman`-side preference. The right move is **measurement, not refactor**, performed as part of Phase 3.

**Status:** the lab test is a follow-up commit on this branch. `sd keys delete` (Phase 3 main deliverable) only opens SCP03, so it is not gated on the SCP11c question. The measurement gates only future destructive verbs that would open over SCP11c.

**Test specifics (for the follow-up commit):**

```text
Build tag: //go:build lab
Env gates:
  SCPCTL_LAB_HARDWARE=1   required (belt-and-suspenders)
  SCPCTL_LAB_READER=...   PC/SC reader substring
  SCPCTL_LAB_SCP03_*      factory by default; override for rotated labs
  SCPCTL_LAB_OCE_KEY      PEM, OCE private key for SCP11c open
  SCPCTL_LAB_OCE_CERT     PEM, OCE leaf cert
  SCPCTL_LAB_TRUST_ROOT   PEM, card trust root

Library API surface to use:
  transport/pcsc.OpenReader(name) (*Transport, error)
  securitydomain.OpenSCP03(ctx, t, *scp03.Config)  → setup/cleanup
  securitydomain.OpenSCP11(ctx, t, *scp11.Config)  → SCP11c via Variant
  Session.GenerateECKey, Session.DeleteKey         → install + probe

Sequence:
  1. OpenSCP03 with factory (or SCPCTL_LAB_SCP03_* override).
  2. GenerateECKey at kid=0x11 kvn=0x7F (disposable, reserved).
  3. Close SCP03.
  4. OpenSCP11 with Variant=SCP11c using OCE key/cert/trust env.
  5. Probe: DeleteKey against the disposable ref. Record SW.
  6. t.Cleanup runs SCP03 again to remove the disposable ref;
     errors during cleanup are t.Errorf so the test result reflects
     residual card state.

Outcomes (logged for the measurement record, no assertion either way):
  ACCEPTED → library treatment is vindicated; no policy change.
  REJECTED → add SecurityDomainWritePolicy keyed on profile +
             protocol variant before exposing CLI surface that
             opens SCP11c for writes.
  SCP11c open itself fails → measurement inconclusive; documented
             as such (e.g. card profile doesn't support SCP11c).
```

If the card rejects, add a profile-aware `SecurityDomainWritePolicy` before exposing CLI surface that opens SCP11c for writes.

## Output shape

All new commands emit the standard `Report` (see `docs/scpctl.md`).

## Phasing and acceptance

| Phase | Commands                                              | Confirm gate(s)                | Library work                                        |
|-------|-------------------------------------------------------|--------------------------------|-----------------------------------------------------|
| 1     | `sd keys list`, `sd keys export`, SCP03 auth fallback | none (read-only)               | none                                                |
| 1b    | SCP11a auth fallback for read-only commands           | none                           | none — gated on demand                              |
| 2     | `sd allowlist set` / `clear`                          | `--confirm-write`              | none — `StoreAllowlist`/`ClearAllowlist` already public |
| 2b    | SCP11a auth for `sd allowlist set` / `clear`          | `--confirm-write`              | none — gated on demand                              |
| 3     | `sd keys delete` + YubiKey SCP11c write integration test | `--confirm-delete-key` + `--all`/`--kvn` validation | `SecurityDomainWritePolicy` only if measurement requires |
| 4     | `sd keys generate` (profile-gated)                    | `--confirm-write`              | none                                                |
| 5     | `sd keys import` (SCP03 AES-128 only)                 | `--confirm-write`              | AES-192/256 SCP03 PUT KEY remains a separate expansion |

## Acceptance criteria, common to all phases

- No private material in any output, ever. KCVs and SPKI fingerprints only.
- Destructive operations refuse to run without their distinct confirm flag.
- File outputs use the atomic-write contract: complete or absent, never partial.
- SCP11b is refused host-side for any SD write.
- SCP11 trust validation stays on by default; `--lab-skip-scp11-trust` opts out and surfaces in JSON.
- Each new command has a flag-coverage test in `dispatch_test.go` style and at least one mockcard-based behavior test.
- Each new command has a package-level docstring at the same level of detail as `cmd_sd_info.go` / `cmd_sd_reset.go`.
- Check names use the stable shape above. Adding a new check is fine; renaming an existing one is a contract break.

## Out of scope, explicitly

- A `gp` command group on `main`.
- A "shared secure-channel profile" object.
- Whole-device YubiKey UX.
- Raw APDU shell.
- AES-192 / AES-256 SCP03 import in Phase 5.
- **Reading the on-card allowlist.** The Yubico SDK does not implement this and we follow that precedent. Authoritative state lives in the operator's own systems.
