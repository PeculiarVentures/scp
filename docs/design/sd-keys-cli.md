# `sd keys` and `sd allowlist` CLI plan

Status: proposal (revision 2 — incorporates review feedback)
Audience: project maintainers
Scope: closing the operator-facing gaps between `scpctl sd` and the underlying `securitydomain.Session` API. Not a `ykman` clone.

## Background

A code-first comparison of `scpctl` and `Yubico/yubikey-manager` was written against the `gp/main-body` branch (commit `0ffb653`-era) and surfaced a single high-value parity gap: a generic, key-centric Security Domain CLI surface composed from the existing `securitydomain.Session` primitives.

That comparison is a useful starting point but is partly stale relative to current `main`. This document captures the prioritized, current-state plan.

Revision 2 incorporates review feedback on revision 1: phase numbering and split for `generate` vs `import`; fail-by-default semantics for `sd keys export` when no chain is present; authenticated-fallback support for the read-only commands so the design holds beyond YubiKey; explicit `unknown` handling for non-canonical KIDs; and a tightened semantic split between OCE / CA trust-anchor import and SD key certificate-chain storage.

## What's already done that the input comparison treats as missing

The library API is more complete than the input read implies:

- `PutSCP03Key(ref, keys, replaceKvn)` — SCP03 triple import.
- `GenerateECKey(ref, replaceKvn)` — on-card EC key generation, returns SPKI.
- `PutECPrivateKey(ref, key, replaceKvn)` — SCP11 private key import.
- `PutECPublicKey(ref, key, replaceKvn)` — OCE/CA public key install.
- `DeleteKey(ref, deleteLast)` — already supports both KID-targeted and KVN-only deletion.
- `StoreCertificates(ref, certs)` / `GetCertificates(ref)` — full cert bundle round-trip.
- `StoreCaIssuer(ref, ski)` — SKI registration.
- `StoreAllowlist(ref, serials)` / `ClearAllowlist(ref)` — allowlist CRUD.
- `GetSupportedCaIdentifiers(kloc, klcc)` — KLOC/KLCC query.
- `GetKeyInformation()` — KID/KVN/component summary.

The CLI also already covers more than the input describes:

- `sd info` walks the GP registry under `--full` (GP §11.4.2 GET STATUS, three scopes, unauthenticated, fail-soft on auth-required scopes).
- `sd lock` / `sd unlock` / `sd terminate` exist with distinct blast-radius gates.
- `sd terminate` uses `--confirm-terminate-card`; `sd reset` uses `--confirm-reset-sd`; `piv reset` uses `--confirm-reset-piv`. Ordinary writes use `--confirm-write`. New destructive `sd keys` work follows the same one-flag-per-blast-radius rule.

## What's actually missing in the CLI

Five things, in five phases. Read-only first, then writes split by hazard level (allowlist before key delete, generate before import):

1. **`sd keys list`** and **`sd keys export`** — read-only key/cert presentation. SCP03 authenticated-fallback support so the design holds for cards that gate key-information or cert-store reads behind authentication.
2. **`sd allowlist get` / `set` / `clear`** — library is complete; CLI is the gap. SCP11a production policies need it.
3. **`sd keys delete`** — destructive, distinct confirm gate. Lands together with the YubiKey SCP11c write-authorization measurement (see below).
4. **`sd keys generate`** — on-card EC key generation. Single card-side operation, single output (SPKI). Lower hazard than import.
5. **`sd keys import`** — KID-dispatched key install. Higher hazard: SCP03 triple parsing, EC private key handling, public-cert / chain semantics, replace-KVN, SKI derivation.

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

SCP11a authenticated fallback is a Phase 1b follow-up if there is demand. The OCE-key / chain / trust-root flag surface is substantial and the read-only use case for SCP11a is rare (SCP11a is primarily a write channel). Adding it now would be speculative.

The default-unauth-with-opt-in-auth pattern is consistent with existing project conventions and avoids regressing the YubiKey ergonomics.

## Command surface

### `sd keys list`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Composes:

- `GetKeyInformation()` for KID/KVN/component summary.
- `GetSupportedCaIdentifiers(true, true)` for KLOC/KLCC SKIs.
- `GetCertificates(ref)` per key reference.

Output (`data` block):

```json
{
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

The `unknown` case is explicit. Cards from other vendors may install references at non-canonical KIDs; those entries are still reported with their authoritative KID/KVN bytes, just without a host-side classification. Forcing every key into a known kind would lie about the card.

A future revision may add a `profile` field to the data block (e.g. `"yubikey"`, `"generic-gp"`, `"unknown"`) once profile detection is independently useful elsewhere. Not a Phase 1 commitment.

No private material in output ever. KCV / SPKI fingerprints / public SKIs only.

Flags: `--reader`, `--json`, `--scp03-*` (auth fallback). No write gates.

### `sd keys export`

Read. Default unauthenticated; opens SCP03-authenticated when SCP03 flags are present.

Writes the certificate chain for one key reference as PEM (or DER on `--der`).

```text
scpctl sd keys export --kid 0x11 --kvn 1 --out chain.pem
```

Composes: `GetCertificates(ref)`.

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

The asymmetry with `sd keys list` is deliberate. `list` is fundamentally an inventory call where empty cells are normal (most SCP03 references have no cert chain). `export` is a targeted retrieval where the operator named one reference and asked for its chain. Empty there is a precise condition the operator should know about.

### `sd allowlist get|set|clear`

`get` is read-only; `set` and `clear` require authenticated SCP03 or SCP11a (mutual). Both writes gate on `--confirm-write`.

```text
scpctl sd allowlist get   --kid 0x11 --kvn 1
scpctl sd allowlist set   --kid 0x11 --kvn 1 --serial 1234567890 --serial 9876543210 --confirm-write [--scp03 ...]
scpctl sd allowlist clear --kid 0x11 --kvn 1 --confirm-write [--scp03 ...]
```

Composes `StoreAllowlist` / `ClearAllowlist` and a `parseAllowlist` read for `get` (existing `parseAllowlist` is already in `securitydomain/commands.go`; if no top-level read API exists, expose a `Session.GetAllowlist(ref)` first as a small library-side change).

### `sd keys delete`

Destructive. Authenticated SCP03 or SCP11a (mutual). Gated on its own flag, **not** `--confirm-write`:

```text
--confirm-delete-key
```

Rationale: deleting a key reference is a recovery-meaningful action distinct from rotating one. Sharing `--confirm-write` with delete is a foot-gun in the same way `--confirm-reset-sd` and `--confirm-terminate-card` are. The rule is: **one confirm flag per blast radius**.

```text
scpctl sd keys delete --kid 0x11 --kvn 1     --confirm-delete-key [--scp03 ...]
scpctl sd keys delete           --kvn 1 --all --confirm-delete-key [--scp03 ...]
```

`--all` maps to `DeleteKey(ref, deleteLast=true)` semantics for the KVN-only case.

### `sd keys generate`

Authenticated SCP03 or SCP11a. Gated on `--confirm-write`. On-card key generation only. Writes the SPKI as PEM by default.

```text
scpctl sd keys generate --kid 0x11 --kvn 1 [--replace-kvn 0] --out sd-pub.pem --confirm-write [--scp03 ...]
```

Composes `GenerateECKey`. If the kid is not an SCP11 SD slot (0x11 / 0x13 / 0x15), refuse host-side.

### `sd keys import`

Authenticated. Gated on `--confirm-write`. KID-dispatched.

**Two distinct semantic categories** — keep them clearly separated to avoid the earlier category error of treating OCE chains as card-stored SD cert bundles:

| KID                     | Category                        | Library calls                                 | Cert handling                          |
|-------------------------|---------------------------------|-----------------------------------------------|----------------------------------------|
| `0x01`                  | SCP03 key set                   | `PutSCP03Key`                                 | n/a                                    |
| `0x10`, `0x20–0x2F`     | OCE / CA trust anchor           | `PutECPublicKey` + `StoreCaIssuer`            | OCE leaf chain is **wire-only**; do NOT call `StoreCertificates` for trust anchors unless the target profile explicitly stores OCE chains on-card. |
| `0x11`, `0x13`, `0x15`  | SD key (SCP11 endpoint key)     | `PutECPrivateKey` + optional `StoreCertificates` | Chain stored against the SD key ref via STORE DATA when `--certs` is given. |

Input forms accepted:

- `--key-pem path` (private or public per kid)
- `--scp03-keys hex:hex:hex` for SCP03 (or `--scp03-enc/mac/dek` triple for symmetry with auth flags)
- `--certs path` (PEM bundle) — only meaningful for the SD-key category; rejected with a clear usage error for the trust-anchor category unless `--profile` explicitly opts in
- `--ski hex` — explicit SKI override for trust-anchor imports (default: derived from leaf cert)
- `--replace-kvn N` — corresponds to library `replaceKvn`

The opinionated bootstrap flows still exist and remain the recommended path for fresh cards. `sd keys import` is for operators who already have an established trust path and want explicit control.

## SCP11c write authorization — research item, not a precondition

The input comparison flags a perceived mismatch: `securitydomain.Session` treats SCP11c as `oceAuthenticated=true` (correct per GP — SCP11c is mutual), while `ykman` device tests behave as if SCP11c writes are rejected on YubiKey.

Two possibilities:

1. YubiKey card-side policy rejects SCP11c-authenticated SD writes. If so, the host-side gate is *too permissive* on the YubiKey profile and we should add a card-profile-aware write policy (the `SecurityDomainWritePolicy` shape suggested in the input, Option B).
2. `ykman`'s test phrasing reflects a `ykman`-side preference, not a card-side rejection. The library is correct as-is and no change is needed.

The right move is **measurement, not refactor**. As part of the `sd keys delete` work (the first SCP-authenticated destructive command landing through the new surface), add an integration test that:

1. Opens an SCP11c SD session against a retail YubiKey.
2. Attempts a disposable, recoverable management operation (e.g. write to and then delete a non-essential key reference).
3. Records the SW.

If YubiKey rejects, add the profile gate. If YubiKey accepts, the library treatment is vindicated and we document it.

This is *not* a blocker for `sd keys list/export` or `sd allowlist`.

## Output shape

All new commands emit the standard `Report` (see `docs/scpctl.md`). Specifically:

- `subcommand` is `"sd keys list"` etc.
- `checks` includes one entry per significant operation (e.g. `"key info fetch"`, `"certificate fetch (kid=0x11 kvn=1)"`, `"chain present"` for export).
- `data` carries the structured payload above.
- Lab/trust skips remain visible (`lab_skip_scp11_trust: true` propagates from the underlying SCP11 open).
- Exit codes: `0` clean, `1` failure, `2` usage.

## Phasing and acceptance

| Phase | Commands                                              | Confirm gate(s)                | Library work                                        |
|-------|-------------------------------------------------------|--------------------------------|-----------------------------------------------------|
| 1     | `sd keys list`, `sd keys export`, SCP03 auth fallback | none (read-only)               | none                                                |
| 1b    | SCP11a auth fallback for read-only commands           | none                           | none — gated on demand                              |
| 2     | `sd allowlist get` / `set` / `clear`                  | `--confirm-write` for set/clear | possibly add `Session.GetAllowlist(ref)`            |
| 3     | `sd keys delete` + YubiKey SCP11c write integration test | `--confirm-delete-key`     | none unless test fails → add `SecurityDomainWritePolicy` |
| 4     | `sd keys generate`                                    | `--confirm-write`              | none                                                |
| 5     | `sd keys import`                                      | `--confirm-write`              | none                                                |

Each phase is one PR. No phase rolls forward without the prior phase's tests passing on a real card.

## Acceptance criteria, common to all phases

- No private material in any output, ever. KCVs and SPKI fingerprints only.
- Destructive operations refuse to run without their distinct confirm flag.
- SCP11b is refused host-side for any SD write (existing host-side gate).
- SCP11 trust validation stays on by default; `--lab-skip-scp11-trust` opts out and surfaces in JSON as it does today.
- Each new command has a flag-coverage test in `dispatch_test.go` style and at least one mockcard-based behavior test.
- Each new command has a package-level docstring at the same level of detail as `cmd_sd_info.go` / `cmd_sd_reset.go`.

## Out of scope, explicitly

- A `gp` command group. If GP destructive lifecycle (`gp install`, `gp delete`, `gp cap inspect`) lands later from the `gp/main-body` line, it is independent differentiation and not subject to this plan.
- A "shared secure-channel profile" object. Revisit only after `sd keys import` lands and we can see the actual duplication.
- Whole-device YubiKey UX. The boundary is documented in `docs/scpctl.md` and `docs/glossary.md`.
- Raw APDU shell. If ever needed, lives under `lab` or similar — not under `sd`/`piv`/`gp`.
