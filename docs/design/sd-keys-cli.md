# `sd keys` and `sd allowlist` CLI plan

Status: proposal (revision 3 — incorporates revision-2 review feedback)
Audience: project maintainers
Scope: closing the operator-facing gaps between `scpctl sd` and the underlying `securitydomain.Session` API. Not a `ykman` clone.

## Background

A code-first comparison of `scpctl` and `Yubico/yubikey-manager` was written against the `gp/main-body` branch (commit `0ffb653`-era) and surfaced a single high-value parity gap: a generic, key-centric Security Domain CLI surface composed from the existing `securitydomain.Session` primitives.

Revision 2 fixed phase numbering, fail-by-default for `sd keys export`, the read-only authentication model, explicit unknown-KID handling, and the OCE/CA versus SD-key import semantic split.

Revision 3 incorporates further review feedback: SCP03 import scope tightened to AES-128 (matching current library PUT KEY constraints); `sd keys list` cert-fetch made selective by KID kind to avoid wasted APDUs; `Session.GetAllowlist(ref)` made an explicit Phase 2 prerequisite; delete-flag validation rules locked in; `sd keys generate` documented as profile-gated because INS=0xF1 is a Yubico extension; the SCP11c write-auth integration test made disposable, lab-gated, and self-cleaning; and Phase 1 check names plus atomic file-write semantics defined as part of the contract.

## What's already done that the input comparison treats as missing

The library API is more complete than the input read implies:

- `PutSCP03Key(ref, keys, replaceKvn)` — SCP03 triple import. Library currently rejects key components that aren't 16 bytes (AES-128); `securitydomain/commands.go` has the explicit length guard.
- `GenerateECKey(ref, replaceKvn)` — on-card EC key generation, returns SPKI. Uses INS=0xF1 (Yubico extension, **not** GP standard).
- `PutECPrivateKey(ref, key, replaceKvn)` — SCP11 private key import.
- `PutECPublicKey(ref, key, replaceKvn)` — OCE/CA public key install.
- `DeleteKey(ref, deleteLast)` — already supports both KID-targeted and KVN-only deletion.
- `StoreCertificates(ref, certs)` / `GetCertificates(ref)` — full cert bundle round-trip.
- `StoreCaIssuer(ref, ski)` — SKI registration.
- `StoreAllowlist(ref, serials)` / `ClearAllowlist(ref)` — allowlist write CRUD. **No public read API yet**; `parseAllowlist` exists in `commands.go` and Phase 2 needs to expose `Session.GetAllowlist(ref)`.
- `GetSupportedCaIdentifiers(kloc, klcc)` — KLOC/KLCC query.
- `GetKeyInformation()` — KID/KVN/component summary.

The CLI also already covers more than the input describes:

- `sd info` walks the GP registry under `--full` (GP §11.4.2 GET STATUS, three scopes, unauthenticated, fail-soft on auth-required scopes).
- `sd lock` / `sd unlock` / `sd terminate` exist with distinct blast-radius gates.
- `sd terminate` uses `--confirm-terminate-card`; `sd reset` uses `--confirm-reset-sd`; `piv reset` uses `--confirm-reset-piv`. Ordinary writes use `--confirm-write`. New destructive `sd keys` work follows the same one-flag-per-blast-radius rule.

## What's actually missing in the CLI

Five things, in five phases. Read-only first, then writes split by hazard level (allowlist before key delete, generate before import):

1. **`sd keys list`** and **`sd keys export`** — read-only key/cert presentation. SCP03 authenticated-fallback support so the design holds for cards that gate key-information or cert-store reads behind authentication.
2. **`sd allowlist get` / `set` / `clear`** — production SCP11a policies need it. Requires `Session.GetAllowlist(ref)` library API as a prerequisite.
3. **`sd keys delete`** — destructive, distinct confirm gate. Lands together with the YubiKey SCP11c write-authorization measurement (see below).
4. **`sd keys generate`** — on-card EC key generation. Profile-gated (Yubico extension INS=0xF1). Single card-side operation, single output (SPKI).
5. **`sd keys import`** — KID-dispatched key install. Higher hazard: SCP03 triple parsing (AES-128 only initially), EC private key handling, public-cert / chain semantics, replace-KVN, SKI derivation.

The bootstrap flows (`bootstrap-oce`, `bootstrap-scp11a`, `bootstrap-scp11a-sd`) stay. They encode the fresh-card sequencing that avoids the factory-key consumption foot-gun and they are a better operator workflow than composing the lower-level primitives by hand. The new commands sit beside them, not in place of them.

## Non-goals

- Whole-device YubiKey UX (FIDO/OATH/OpenPGP/OTP/HSMAuth/`config`). Out of scope.
- Raw operator APDU shell. Useful in a lab; not product-critical; stays out of `sd`/`piv` if it ever lands.
- A speculative shared "secure-channel profile" abstraction across commands. Useful if and when concrete flag duplication becomes painful — defer until then.
- A separate `gp` command group on `main`. The `gp/main-body` work is on its own branch; if and when it merges, GP destructive operations are GP differentiation, not `ykman` parity.

## Authentication model for read-only commands

The default path is unauthenticated. The library exposes `OpenUnauthenticated` and the operations `sd keys list` and `sd keys export` rely on (`GetKeyInformation`, `GetSupportedCaIdentifiers`, `GetCertificates`) do not call `requireOCEAuth()` — they work without an established channel on YubiKey today.

But the read-permissions are card-defined, not standard. A non-YubiKey GP card may reasonably require SCP03 authentication before returning the Key Information Template or the cert store. The design has to allow for that without making YubiKey operators do extra work.

Behavior:

```text
sd keys list, sd keys export

  no auth flag set:
    Open unauthenticated. Optional sections (KLOC/KLCC, per-ref
    cert fetch when no chain) fail soft as SKIPs. Required reads
    (KIT for list; cert chain for export with no --allow-empty)
    fail hard.

  --scp03[-keys-default] or --scp03-{kvn,enc,mac,dek}:
    Open SCP03-authenticated. Same key-flag semantics as
    bootstrap-* commands (registerSCP03KeyFlags helper). Auth
    failure is FAIL, not SKIP — the operator explicitly asked for
    auth and the card rejected it.
```

SCP11a authenticated fallback is a Phase 1b follow-up if there is demand. The OCE-key / chain / trust-root flag surface is substantial and the read-only use case for SCP11a is rare (SCP11a is primarily a write channel). Adding it now would be speculative. Once `sd keys delete` / `generate` / `import` land and the SCP11a open helper is wired anyway (Phase 3+), revisit whether `list/export --scp11a` becomes cheap to enable.

## Stable check names (Phase 1)

The `Report.Checks` stream is the audit-log substrate. Operators and pipelines depend on the names not changing once published. Phase 1 commits to these names; later phases extend with the same shape:

```text
sd keys list:
  select ISD                                  unauth path
  open SCP03 session                          auth path
  SCP03 keys                                  auth path label (factory / custom)
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

The names are deliberately APDU-tag-anchored rather than abstract ("key information fetch"). When something fails on a card, knowing exactly which GET DATA tag the host requested is the fastest path to a diagnosis. "Stability" means these names don't churn — not that they're abstract.

## Output safety: atomic file writes

`sd keys export` (and later `sd keys generate` for the SPKI output) write through an atomic helper:

```text
1. CreateTemp in the same directory as --out (so rename is on the
   same filesystem and is atomic on POSIX).
2. Write data.
3. Sync.
4. Close.
5. Chmod to requested mode.
6. Rename onto --out.

On any error after CreateTemp, the temp file is removed before
returning. On a successful run, no temp leftover remains in the
output directory.
```

The contract for the operator: after the command, the path named by `--out` either contains the complete, valid output or does not exist. There is no partial state. This matters for automation that uses file existence as the success signal — a partially-written PEM/DER would be silently consumed and fail downstream parsing far from the cause.

## Command surface

### `sd keys list`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Composes:

- `GetKeyInformation()` — every run.
- `GetSupportedCaIdentifiers(true, true)` — every run; missing tags are SKIP, not FAIL.
- `GetCertificates(ref)` — **only for cert-capable kinds**. SCP03 references (KID=0x01) skip the fetch entirely with a SKIP check labelled `"scp03 ref (no chain expected)"`. SCP03 keys are symmetric and never carry a stored chain; issuing a 0xBF21 against KID=0x01 is wasted APDU traffic that always returns SW=6A88. Cert-capable kinds are SCP11 SD refs (0x11/0x13/0x15), CA / OCE public-key refs (0x10, 0x20–0x2F), and `unknown` (where the operator is explicitly inspecting an unfamiliar card and the extra fetch is the right tradeoff).

Output (`data` block):

```json
{
  "channel": "unauthenticated",
  "keys": [
    {
      "kid": 1,
      "kvn": 255,
      "kid_hex": "0x01",
      "kvn_hex": "0xFF",
      "kind": "scp03",
      "components": [{"id": 192, "type": 136}]
    },
    {
      "kid": 17,
      "kvn": 1,
      "kid_hex": "0x11",
      "kvn_hex": "0x01",
      "kind": "scp11a-sd",
      "components": [{"id": 240, "type": 80}],
      "ca_ski": "AABBCC...",
      "certificates": [
        {"subject": "...", "spki_fingerprint_sha256": "..."}
      ]
    }
  ]
}
```

`kind` is derived host-side from `kid`:

```text
0x01           → "scp03"
0x10           → "ca-public"
0x11           → "scp11a-sd"
0x13           → "scp11b-sd"
0x15           → "scp11c-sd"
0x20–0x2F      → "ca-public"   (Yubico KLCC extension range)
anything else  → "unknown"
```

The `unknown` case is explicit. Cards from other vendors may install references at non-canonical KIDs; those entries are still reported with their authoritative KID/KVN bytes, just without a host-side classification.

A future revision may add a `profile` field to the data block (e.g. `"yubikey"`, `"generic-gp"`, `"unknown"`) once profile detection is independently useful elsewhere. Not a Phase 1 commitment.

No private material in output ever. KCV / SPKI fingerprints / public SKIs only.

Flags: `--reader`, `--json`, `--scp03-*` (auth fallback). No write gates.

### `sd keys export`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Writes the certificate chain for one key reference as PEM (or DER on `--der`).

```text
scpctl sd keys export --kid 11 --kvn 01 --out chain.pem
```

`--kid` and `--kvn` are bare hex bytes (e.g. `01`, `FF`, `11`) matching the convention used by other `--scp03-*` flags in the project.

Composes: `GetCertificates(ref)`. Output writes go through the atomic helper described above.

**No-chain semantics:**

```text
default behavior:
  exit 1, FAIL check named "chain present", no output file written.
  An automation that piped through this command must not silently
  proceed as if it had received material.

--allow-empty:
  exit 0, SKIP check named "chain present", JSON-visible
  "certificates": []. For inventory scripts that want to walk a
  list of references and skip ones with no stored chain.
```

The asymmetry with `sd keys list` is deliberate. `list` is fundamentally an inventory call where empty cells are normal. `export` is a targeted retrieval where the operator named one reference and asked for its chain.

### `sd allowlist get|set|clear`

`get` is read-only; `set` and `clear` require authenticated SCP03 or SCP11a (mutual). Both writes gate on `--confirm-write`.

```text
scpctl sd allowlist get   --kid 11 --kvn 01
scpctl sd allowlist set   --kid 11 --kvn 01 --serial 1234567890 --serial 9876543210 --confirm-write [--scp03 ...]
scpctl sd allowlist clear --kid 11 --kvn 01 --confirm-write [--scp03 ...]
```

**Phase 2 prerequisite (library work):** add `Session.GetAllowlist(ref) ([]*big.Int, error)` as a public read API before the CLI lands. Tests must cover empty allowlist (SW=6A88 → empty slice, no error), single serial, multiple serials, malformed TLV (returns `ErrInvalidResponse`), and the "tag not supported" case some cards may return.

The CLI composes `Session.StoreAllowlist`, `Session.ClearAllowlist`, and the new `Session.GetAllowlist`. It does not reach into parser-only internals like `parseAllowlist`.

### `sd keys delete`

Destructive. Authenticated SCP03 or SCP11a (mutual). Gated on its own flag, **not** `--confirm-write`:

```text
--confirm-delete-key
```

Rationale: deleting a key reference is a recovery-meaningful action distinct from rotating one. Sharing `--confirm-write` with delete is a foot-gun in the same way `--confirm-reset-sd` and `--confirm-terminate-card` are. The rule is: **one confirm flag per blast radius**.

**Flag validation rules** (host-side, before any APDU is sent):

```text
--kid + --kvn (no --all):
  delete exactly that ref. Maps to DeleteKey(ref, deleteLast=false).

--kvn + --all (no --kid):
  delete all keys at that KVN. Maps to DeleteKey({_, kvn}, deleteLast=true).
  --all is the explicit "yes I mean all keys at this KVN" gate.

--kid only (no --kvn):
  USAGE ERROR. Card-side semantics for KID-only deletion are not
  consistently safe across profiles; require explicit KVN.

--kvn only (no --all):
  USAGE ERROR. Use --kid to target one ref or --all to target all
  refs at this KVN; the bare KVN form is ambiguous.

--all + --kid:
  USAGE ERROR. --all is incompatible with a specific --kid.
```

Combined with `--confirm-delete-key` this requires three explicit signals before broad deletion: `--kvn`, `--all`, and the confirm flag.

### `sd keys generate`

**Profile-gated.** GENERATE EC KEY uses INS=0xF1 — a Yubico extension, not GP standard (`securitydomain/commands.go: insGenerateKey byte = 0xF1 // Yubico extension — NOT 0xD8`). The CLI must detect the active profile and refuse host-side before sending the APDU on cards that don't declare support.

```text
scpctl sd keys generate --kid 11 --kvn 01 [--replace-kvn 0] --out sd-pub.pem --confirm-write [--scp03 ...]
```

Authenticated SCP03 or SCP11a. Gated on `--confirm-write`. On-card key generation only; the private key never crosses the wire. SPKI written as PEM by default through the atomic-write helper.

KID validation: must be an SCP11 SD slot (0x11 / 0x13 / 0x15). Other KIDs refuse host-side.

Profile validation: requires the YubiKey Security Domain profile (or a future profile that explicitly declares GENERATE EC KEY support). Unknown / generic GP profiles fail host-side with a clear message naming the missing capability.

Composes `GenerateECKey`.

### `sd keys import`

Authenticated. Gated on `--confirm-write`. KID-dispatched.

**Two distinct semantic categories** — keep them clearly separated to avoid the earlier category error of treating OCE chains as card-stored SD cert bundles:

| KID                     | Category                        | Library calls                                 | Cert handling                          |
|-------------------------|---------------------------------|-----------------------------------------------|----------------------------------------|
| `0x01`                  | SCP03 key set (**AES-128 only**)| `PutSCP03Key`                                 | n/a                                    |
| `0x10`, `0x20–0x2F`     | OCE / CA trust anchor           | `PutECPublicKey` + `StoreCaIssuer`            | OCE leaf chain is **wire-only**; do NOT call `StoreCertificates` for trust anchors unless the target profile explicitly stores OCE chains on-card. |
| `0x11`, `0x13`, `0x15`  | SD key (SCP11 endpoint key)     | `PutECPrivateKey` + optional `StoreCertificates` | Chain stored against the SD key ref via STORE DATA when `--certs` is given. |

**SCP03 import scope:** Phase 5 supports AES-128 SCP03 key triples only, matching the current Security Domain management profile (`putKeySCP03Cmd` rejects 24/32-byte components with `ErrInvalidKey`). AES-192 / AES-256 SCP03 import is an expansion target gated on library PUT KEY encoding work plus hardware validation.

Input forms accepted:

- `--key-pem path` (private or public per kid)
- `--scp03-keys hex:hex:hex` for SCP03 (or `--scp03-enc/mac/dek` triple for symmetry with auth flags)
- `--certs path` (PEM bundle) — only meaningful for the SD-key category; rejected with a clear usage error for the trust-anchor category unless `--profile` explicitly opts in
- `--ski hex` — explicit SKI override for trust-anchor imports (default: derived from leaf cert)
- `--replace-kvn N` — corresponds to library `replaceKvn`

The opinionated bootstrap flows still exist and remain the recommended path for fresh cards. `sd keys import` is for operators who already have an established trust path and want explicit control.

## SCP11c write authorization — measurement, lab-gated, self-cleaning

The input comparison flags a perceived mismatch: `securitydomain.Session` treats SCP11c as `oceAuthenticated=true` (correct per GP — SCP11c is mutual), while `ykman` device tests behave as if SCP11c writes are rejected on YubiKey. Two possibilities:

1. YubiKey card-side policy rejects SCP11c-authenticated SD writes. If so, the host-side gate is *too permissive* on the YubiKey profile and we add a card-profile-aware write policy.
2. `ykman`'s test phrasing reflects a `ykman`-side preference, not a card-side rejection. The library is correct as-is and no change is needed.

The right move is **measurement, not refactor**, performed as part of Phase 3.

**Test specifics** (must be safe for unattended lab CI):

```text
1. Open an SCP03 session against a retail YubiKey (in lab profile).
2. Generate or import a known-disposable SCP11 key reference. Use a
   high-numbered, deliberately disposable KVN (e.g. KVN=0x7E or
   0x7F) that the lab profile reserves for measurement-only writes.
   Do not use KVN=0x01 or any KVN that overlaps production
   provisioning.
3. Close SCP03. Open SCP11c against the lab profile.
4. Attempt a recoverable management op against the disposable ref
   (e.g. STORE CERTIFICATES with a known throwaway cert, or DELETE
   KEY against the disposable ref). Record the SW.
5. Restore: re-open SCP03 and clean up the disposable ref so the
   card returns to its pre-test state. The test must always run
   the cleanup, including on failure (defer / t.Cleanup).
6. The test is gated on a lab-profile flag (e.g. SCPCTL_LAB_HARDWARE
   environment variable) and is SKIP'd in normal CI.
```

Outcomes:

```text
SCP11c write accepted by the card:
  Document YubiKey behavior. Library treatment of
  SCP11c as OCEAuthenticated=true is vindicated. No
  code change.

SCP11c write rejected by the card:
  Add profile-aware SecurityDomainWritePolicy keyed on
  card profile + protocol variant before exposing any
  CLI surface that opens SCP11c for writes. Existing
  CLI commands continue to refuse host-side on the
  YubiKey profile until the policy lands.
```

This is **not** a blocker for `sd keys list/export` or `sd allowlist`. It blocks only the destructive verbs (`delete`, `generate`, `import`) that could be opened over SCP11c.

## Output shape

All new commands emit the standard `Report` (see `docs/scpctl.md`). Specifically:

- `subcommand` is `"sd keys list"` etc.
- `checks` uses the stable names listed above.
- `data` carries the structured payload with `channel` ("unauthenticated" or "scp03").
- Lab/trust skips remain visible (`lab_skip_scp11_trust: true` propagates from the underlying SCP11 open).
- Exit codes: `0` clean, `1` failure, `2` usage.

## Phasing and acceptance

| Phase | Commands                                              | Confirm gate(s)                | Library work                                        |
|-------|-------------------------------------------------------|--------------------------------|-----------------------------------------------------|
| 1     | `sd keys list`, `sd keys export`, SCP03 auth fallback | none (read-only)               | none                                                |
| 1b    | SCP11a auth fallback for read-only commands           | none                           | none — gated on demand                              |
| 2     | `sd allowlist get` / `set` / `clear`                  | `--confirm-write` for set/clear | **add `Session.GetAllowlist(ref)` first**           |
| 3     | `sd keys delete` + YubiKey SCP11c write integration test (lab-gated, self-cleaning) | `--confirm-delete-key` + `--all`/`--kvn` validation | `SecurityDomainWritePolicy` only if measurement says we need it |
| 4     | `sd keys generate` (profile-gated)                    | `--confirm-write`              | none                                                |
| 5     | `sd keys import` (SCP03 AES-128 only)                 | `--confirm-write`              | AES-192/256 SCP03 PUT KEY remains a separate expansion |

Each phase is one PR. No phase rolls forward without the prior phase's tests passing on a real card.

## Acceptance criteria, common to all phases

- No private material in any output, ever. KCVs and SPKI fingerprints only.
- Destructive operations refuse to run without their distinct confirm flag.
- File outputs (`export`, `generate`) use the atomic-write contract: complete or absent, never partial.
- SCP11b is refused host-side for any SD write (existing host-side gate).
- SCP11 trust validation stays on by default; `--lab-skip-scp11-trust` opts out and surfaces in JSON as it does today.
- Each new command has a flag-coverage test in `dispatch_test.go` style and at least one mockcard-based behavior test.
- Each new command has a package-level docstring at the same level of detail as `cmd_sd_info.go` / `cmd_sd_reset.go`.
- Check names use the stable shape above. Adding a new check is fine; renaming an existing one is a contract break and requires a deprecation note.

## Out of scope, explicitly

- A `gp` command group. If GP destructive lifecycle (`gp install`, `gp delete`, `gp cap inspect`) lands later from the `gp/main-body` line, it is independent differentiation and not subject to this plan.
- A "shared secure-channel profile" object. Revisit only after `sd keys import` lands and we can see the actual duplication.
- Whole-device YubiKey UX. The boundary is documented in `docs/scpctl.md` and `docs/glossary.md`.
- Raw APDU shell. If ever needed, lives under `lab` or similar — not under `sd`/`piv`/`gp`.
- AES-192 / AES-256 SCP03 import in Phase 5. Requires library PUT KEY work plus hardware validation; scoped as a separate expansion.
