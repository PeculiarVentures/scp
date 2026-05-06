# `sd keys` and `sd allowlist` — operator runbook

This document covers the operator-facing surface for inventory, rotation, and authorization of Security Domain key material on cards that speak GP SCP. It complements [`scpctl.md`](scpctl.md) (group structure + design rationale) and the bootstrap commands documented in [`cmd/scpctl/README.md`](../cmd/scpctl/README.md).

## What's in this group

Five `sd keys` verbs plus two `sd allowlist` verbs. Each verb is a single APDU sequence that maps to one or two GP commands.

| Verb | Reads / writes | GP commands | Auth |
|---|---|---|---|
| `sd keys list` | read | GET DATA tag E0 (KIT), tag FF33/FF34 (KLOC/KLCC), tag BF21 (cert store) per ref | unauthenticated by default; opt-in SCP03 |
| `sd keys export` | read | GET DATA tag BF21 | unauthenticated by default; opt-in SCP03 |
| `sd keys delete` | write | DELETE KEY (INS=E4) | SCP03 required |
| `sd keys generate` | write | GENERATE EC KEY (INS=F1, Yubico extension) | SCP03 required |
| `sd keys import` | write | PUT KEY (INS=D8) + optionally STORE DATA (INS=E2) | SCP03 required |
| `sd allowlist set` | write | STORE DATA tag 70 | SCP03 required |
| `sd allowlist clear` | write | STORE DATA tag 70 (empty serial list) | SCP03 required |

The split between read and write is also a safety boundary: read verbs default to unauthenticated and have no `--confirm-*` gate; write verbs are dry-run by default and require explicit confirmation. See [Safety](#safety) below.

## Authentication

Three modes, controlled by the same `--scp03-*` flag set on every verb:

**Unauthenticated.** No `--scp03-*` flags. Read verbs only — write verbs require auth and will reject this combination at flag-parse time. Whether unauthenticated reads succeed depends on the card; YubiKeys allow CRD (tag 0066) but typically gate KIT (tag 00E0) and the cert store (tag BF21) behind authentication. If a read returns SW=6982 unauthenticated, switch to one of the authenticated modes.

**Factory keys.** `--scp03-keys-default`. Authenticates with the well-known factory SCP03 keys (KVN=0xFF, AES-128, the values published in the YubiKey Security Domain SCP03 documentation). Use this for fresh cards or for read-only inspection of an unrotated card. Mutually exclusive with the custom-key flags. **Only valid on `--vendor-profile yubikey`** (the default); on `--vendor-profile generic`, this flag is rejected because the factory keys are vendor-specific.

**Custom triple.** `--scp03-kvn KVN --scp03-enc ENC --scp03-mac MAC --scp03-dek DEK`. All four required. KVN is a hex byte (e.g. `01`, `FE`); ENC, MAC, DEK are hex strings of equal length matching the AES variant (16 bytes for AES-128, 24 for AES-192, 32 for AES-256). Use this after the factory keys have been rotated, or on any non-YubiKey card.

Pick one mode. The flags reject the combination of `--scp03-keys-default` and `--scp03-kvn`.

### `--vendor-profile yubikey|generic`

Every SCP03-aware verb accepts `--vendor-profile`. Default is `yubikey` — preserves all current behavior, factory keys recognized, KIDs labeled with YubiKey conventions.

Pass `--vendor-profile generic` for non-YubiKey GP cards. Three behavioral changes apply:

- `--scp03-keys-default` is rejected at parse time. Operator must supply explicit `--scp03-{kvn,enc,mac,dek}`. Required-auth verbs without any SCP03 flags are also rejected (no implicit factory-key fallback).
- `sd keys generate` is rejected because GENERATE EC KEY (INS=0xF1) is a Yubico extension. To install an EC key on a non-YubiKey card, generate the keypair off-card and use `sd keys import` instead.
- `sd keys list` relabels KIDs 0x11/0x13/0x15 as `scp11-sd` (without the variant letter). The raw KID is still in the JSON's `kid_hex` field as the authoritative value.

The flag does not affect `sd keys export`, `sd keys delete`, or `sd allowlist set/clear` — those verbs use only GP-spec mechanics that don't depend on vendor.

## Verbs

### `sd keys list`

Read-only inventory of the card's installed key references. Composes three reads: GET DATA tag E0 (Key Information Template), tag FF33/FF34 (KLOC/KLCC SKIs), and tag BF21 per reference (certificate chain summaries). Output is one row per key reference with the components, the registered KLOC/KLCC SKI if any, and a chain summary (count + leaf subject) if present.

```
scpctl sd keys list --scp03-keys-default
```

JSON output:

```
scpctl sd keys list --scp03-keys-default --json
```

Schema (the `data` field of the standard Report envelope) — abbreviated; full reference in [JSON output](#json-output) below:

```json
{
  "channel": "scp03",
  "keys": [
    {
      "kid": 1, "kvn": 255,
      "kid_hex": "0x01", "kvn_hex": "0xFF",
      "kind": "scp03",
      "components": [{"id": 136, "type": 16}]
    }
  ]
}
```

### `sd keys export`

Read the cert chain stored at one key reference and write it to a file.

```
scpctl sd keys export --kid 11 --kvn 01 --out chain.pem --scp03-keys-default
```

PEM is the default output format; `--der` writes raw DER (concatenated, leaf last). `--allow-empty` makes the no-chain case a SKIP at exit 0 — without it, a missing chain is FAIL.

**Chain order.** `--chain-order` controls the order of certs in the output. Default `as-stored` preserves the on-card storage order (leaf-last on conforming cards, matching ykman/yubikit expectations). `leaf-last` actively reorders to put the leaf at the end (defensive against malformed cards). `leaf-first` reverses to validation order — leaf at position 0, then each subsequent cert is the issuer of the one before it. Leaf detection uses signature relationships; ambiguous chains (multiple unrelated leaves, or cycles) error rather than guessing.

The exported file content is byte-equal to what was stored: a successful `sd keys import --certs ...` followed by `sd keys export` produces a file that round-trips through `openssl x509 -in` to the same DER bytes that were imported.

### `sd keys delete`

Authenticated. Removes one key reference, or all keys at a given KVN if `--kid` is omitted.

```
scpctl sd keys delete --kid 11 --kvn 01 --confirm-delete-key --scp03-keys-default
```

`--confirm-delete-key` is a distinct flag from `--confirm-write` — a careless `--confirm-write` alone won't delete keys. Without `--confirm-delete-key`, the verb runs in dry-run mode (validates inputs, reports the planned APDU shape, makes no card-state mutations).

For SCP03 key set deletion, omit `--kid` and pass `--kvn` only; the library normalizes the deletion to "all keys at this version" which is the SCP03 keyset semantic.

**Orphan-auth pre-flight.** Before emitting DELETE KEY, the verb pre-fetches the inventory and refuses if the deletion would leave the card with zero SCP03 keysets — that's the foot-gun case where the operator removes the only authentication path and locks themselves out of subsequent management. Pass `--allow-orphan-auth` to bypass the check (intentional retirement, migration to a non-SCP03 auth model, or recovery scenarios). Pre-flight failures (card doesn't expose KIT) are logged as SKIP and the destructive operation proceeds — the operator already gave explicit consent via `--confirm-delete-key`.

### `sd keys generate`

Authenticated. Generates an EC P-256 keypair on-card at the named SCP11 SD slot. The private key never leaves the device; the public key is written to `--out` as PEM (`PUBLIC KEY`).

```
scpctl sd keys generate --kid 11 --kvn 01 --out pk.pem --confirm-write --scp03-keys-default
```

Implementation note: this uses Yubico's INS=0xF1 GENERATE EC KEY extension, not a GP-spec command. Cards that don't implement the Yubico extension will reject with SW=6D00. The verb's check name explicitly includes `INS=0xF1` so audit logs make the extension dependency visible.

### `sd keys import`

Authenticated. Installs a key from off-card key material. The KID dispatches to one of three install paths:

**`--kid 01` (SCP03 AES key set).** Three new key components (`--new-scp03-enc`, `--new-scp03-mac`, `--new-scp03-dek`), all-or-nothing. Currently AES-128 only. Replace-KVN semantic via `--replace-kvn`: pass `00` for additive install (default), or the KVN of the existing keyset to replace it.

```
scpctl sd keys import --kid 01 --kvn FE \
  --new-scp03-enc 00112233445566778899AABBCCDDEEFF \
  --new-scp03-mac 11223344556677889900AABBCCDDEEFF \
  --new-scp03-dek 22334455667788990011AABBCCDDEEFF \
  --confirm-write --scp03-keys-default
```

**`--kid 11`, `--kid 13`, `--kid 15` (SCP11 SD slots — SCP11a, SCP11b, SCP11c).** EC P-256 private key from `--key-pem` (PKCS#8 or SEC1). Optional cert chain via `--certs` PEM file (one or more `CERTIFICATE` blocks, leaf last). When `--certs` is provided, the import emits PUT KEY followed by STORE DATA with the chain; the leaf cert is checked for SPKI byte-equality with the imported private key (anti-typo guard).

```
scpctl sd keys import --kid 11 --kvn 01 \
  --key-pem sd-priv.pem --certs sd-chain.pem \
  --confirm-write --scp03-keys-default
```

**`--kid 10` or `--kid` in `0x20-0x2F` (CA/OCE trust anchor).** EC P-256 public key from `--key-pem`. The flag accepts either a PEM `PUBLIC KEY` block (PKIX SubjectPublicKeyInfo) OR a PEM `CERTIFICATE` block — when given a cert, the verb extracts the public key AND the SubjectKeyIdentifier extension. SKI source precedence: explicit `--ski` override > the cert's SubjectKeyIdentifier extension > computed SHA-1 of the SPKI per RFC 5280 §4.2.1.2 method 1. The `--certs` flag is REJECTED on this path (trust anchors don't carry chains; the chain-attaching flow is for SCP11 SD slots).

```
scpctl sd keys import --kid 10 --kvn 01 \
  --key-pem ca-cert.pem \
  --confirm-write --scp03-keys-default
```

### `sd allowlist set`

Pushes a certificate-serial-number allowlist to one key reference. The allowlist constrains which OCE leaf-cert serials the card will accept during SCP11a/c authentication against that key.

```
scpctl sd allowlist set --kid 11 --kvn 01 \
  --serial 0x1234567890ABCDEF \
  --serial 0xFEDCBA9876543210 \
  --confirm-write --scp03-keys-default
```

Serials are decimal or `0x`-prefixed hex; repeat `--serial` for multiple. At least one is required.

### `sd allowlist clear`

Removes the allowlist for one key reference. Implemented as `set` with an empty serial list; the wire shape is the same STORE DATA tag 70 emission.

```
scpctl sd allowlist clear --kid 11 --kvn 01 --confirm-write --scp03-keys-default
```

There is no `sd allowlist get` verb — the YubiKey doesn't expose a read API for the stored allowlist; the verb's design mirrors that.

## Safety

Three flag-gates protect against accidental destructive operations:

- **`--confirm-write`** — every write verb except delete. Without it, the verb runs in dry-run mode: validates inputs, reports the planned APDU shape, makes no card state mutations.
- **`--confirm-delete-key`** — distinct gate for `sd keys delete` only. The separate flag is the foot-gun mitigation: a careless `--confirm-write` invocation cannot delete keys.
- **`--confirm-reset-sd`** — for `sd reset` (covered in `scpctl.md`). Mentioned here for completeness; the sd-keys verbs don't reset the SD.

Read verbs (`list`, `export`) have no `--confirm-*` gate because they don't mutate card state.

For destructive flow combinations, the explicit dispatch order is: parse flags → validate inputs → require the right confirmation flag(s) → open the SD session → emit the APDU. A failure at any step before APDU emission is a no-op on card state.

## JSON output

Every verb emits a Report envelope with the same shape:

```json
{
  "subcommand": "sd keys list" | "sd keys export" | ...,
  "reader": "<reader name>",
  "checks": [
    {"name": "...", "result": "PASS|FAIL|SKIP", "detail": "..."}
  ],
  "data": { /* verb-specific payload */ }
}
```

The `checks` stream is the audit log — every step taken (open SCP03, GET DATA, PUT KEY, etc.) lands as one entry with PASS/FAIL/SKIP. The `data` payload is the structured result; its schema is verb-specific.

### `sd keys list` data schema

```json
{
  "channel": "scp03" | "unauthenticated",
  "keys": [
    {
      "kid": 17,
      "kvn": 1,
      "kid_hex": "0x11",
      "kvn_hex": "0x01",
      "kind": "scp11a" | "scp11b" | "scp11c" | "scp03" | "oce" | "trust_anchor",
      "components": [{"id": 136, "type": 16}],
      "ca_ski": "0123456789ABCDEF...",
      "certificates": [
        {
          "subject": "CN=...",
          "issuer": "CN=...",
          "not_before": "2024-...",
          "not_after": "2025-...",
          "spki_fingerprint_sha256": "AB12...",
          "serial_hex": "0x..."
        }
      ]
    }
  ]
}
```

`components`, `ca_ski`, and `certificates` use `omitempty` — absent when not present on the card. `certificates` is leaf-last (matching the card's storage order).

### `sd keys export` data schema

```json
{
  "channel": "scp03" | "unauthenticated",
  "kid_hex": "0x11",
  "kvn_hex": "0x01",
  "format": "pem" | "der",
  "out_path": "/path/to/written/file",
  "chain_order": "as-stored" | "leaf-last" | "leaf-first",
  "certificates": [
    {"subject": "...", "issuer": "...", "not_before": "...", "not_after": "...",
     "spki_fingerprint_sha256": "...", "serial_hex": "..."}
  ]
}
```

The `certificates` array carries metadata about every cert that was written to `--out`, in the order matching the file's actual cert order (after `--chain-order` is applied).

### `sd keys generate` data schema

```json
{
  "channel": "scp03",
  "kid_hex": "0x11",
  "kvn_hex": "0x01",
  "replace_kvn": 0,
  "curve": "P-256",
  "spki_fingerprint_sha256": "AB12...",
  "out_path": "/path/to/written/pubkey.pem"
}
```

`spki_fingerprint_sha256` is uppercase hex SHA-256 over the on-card-generated public key's DER-encoded SubjectPublicKeyInfo — matches what `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum` produces. Use this to confirm the key written to `--out` is the one the card returned.

### `sd keys import` data schema

```json
{
  "channel": "scp03",
  "category": "scp03" | "scp11-sd" | "ca-trust-anchor",
  "kid_hex": "0x11",
  "kvn_hex": "0x01",
  "replace_kvn": 0,
  "spki_fingerprint_sha256": "AB12...",
  "cert_count": 3,
  "ski_hex": "01234567...",
  "ski_origin": "cert-extension" | "computed-sha1-spki" | "explicit-override"
}
```

Fields are conditional on the import path:

- All categories: `channel`, `category`, `kid_hex`, `kvn_hex`, `replace_kvn`
- `scp11-sd` adds: `spki_fingerprint_sha256` (computed from the imported private key's public counterpart), `cert_count` (0 if `--certs` was omitted)
- `ca-trust-anchor` adds: `ski_hex`, `ski_origin` (audits how the SKI was derived — extension, computed, or operator override)
- `scp03` has neither extension; the rotation event is fully described by the base fields

### `sd keys delete` data schema

```json
{
  "channel": "scp03",
  "mode": "single" | "all-at-kvn",
  "kid_hex": "0x11",
  "kvn_hex": "0x01"
}
```

`mode` is `"single"` when both `--kid` and `--kvn` were given, `"all-at-kvn"` when only `--kvn` was given.

### `sd allowlist set` / `sd allowlist clear` data schema

```json
{
  "channel": "scp03",
  "action": "set" | "clear",
  "kid_hex": "0x11",
  "kvn_hex": "0x01",
  "serials": ["1311768467463790320", "..."]
}
```

`serials` is a list of decimal strings (big integers don't fit in JSON numbers reliably; the operator-input hex/decimal form is normalized to decimal here for unambiguous round-tripping).

## Common workflows

### Inspect a fresh card

```
scpctl sd keys list --scp03-keys-default
```

You'll see one entry: KID=0x01, KVN=0xFF, AES-128. That's the factory SCP03 key.

### Rotate the factory SCP03 key to a custom triple

Generate fresh key material off-card, then:

```
scpctl sd keys import --kid 01 --kvn FE \
  --replace-kvn FF \
  --new-scp03-enc <hex> --new-scp03-mac <hex> --new-scp03-dek <hex> \
  --confirm-write --scp03-keys-default
```

After rotation, every subsequent command needs the new triple via `--scp03-kvn FE --scp03-enc ... --scp03-mac ... --scp03-dek ...` instead of `--scp03-keys-default`.

### Install an SCP11a SD ECDH key with attestation chain

```
scpctl sd keys import --kid 11 --kvn 01 \
  --key-pem sd-priv.pem --certs sd-attestation-chain.pem \
  --confirm-write --scp03-kvn FE --scp03-enc <hex> ... 
```

Verify with `sd keys list --scp03-kvn FE ...` and `sd keys export --kid 11 --kvn 01 --out roundtrip.pem`. The roundtrip file should be byte-equal to the input chain (after PEM parsing).

### Install a CA trust anchor for SCP11a OCE chain validation

```
scpctl sd keys import --kid 10 --kvn 01 \
  --key-pem operator-ca-cert.pem \
  --confirm-write --scp03-kvn FE ...
```

The cert is parsed for SubjectKeyIdentifier; if not present, SKI is computed as SHA-1 of the SPKI per RFC 5280 §4.2.1.2 method 1. To override either source explicitly, add `--ski <40-hex>`.

### Restrict which OCE certs the card will accept

```
scpctl sd allowlist set --kid 11 --kvn 01 \
  --serial 0x... --serial 0x... \
  --confirm-write --scp03-kvn FE ...
```

After this, only OCE leaves with matching serials can authenticate via SCP11a/c against this SD slot.

## Lab test invocation

`cmd/scpctl/lab_scp11c_test.go` is a hardware-gated measurement test for the full SCP11c handshake against a real card. Build-tagged so it doesn't compile or run in normal CI; environment-gated so it skips in CI runners that happen to enable the build tag.

To run:

```bash
SCPCTL_LAB_HARDWARE=1 \
SCPCTL_LAB_READER="Yubico YubiKey OTP+CCID 0" \
SCPCTL_LAB_OCE_KEY=/path/to/oce-priv.pem \
SCPCTL_LAB_OCE_CERT=/path/to/oce-cert.pem \
SCPCTL_LAB_TRUST_ROOT=/path/to/trust-root.pem \
go test -tags=lab -run TestLab_SCP11c_Handshake_AgainstHardware ./cmd/scpctl/
```

Optional environment variables:

- `SCPCTL_LAB_OCE_KEY_KID` / `SCPCTL_LAB_OCE_KEY_KVN` — override OCE key reference (default 0x10 / 0x01)
- `SCPCTL_LAB_DISPOSABLE_KVN` — KVN for the disposable test key the test installs and tears down (default 0x7F)
- `SCPCTL_LAB_SCP03_KEYS` — `default` for factory keys, or hex-triple `KVN:ENC:MAC:DEK` for rotated cards
- `SCPCTL_LAB_FORCE` — bypass the disposable-KVN safety check; only use when you know the slot is empty

The test installs a disposable SCP11c key, opens a full SCP11c session against it, exercises encrypted+MAC'd commands through the channel, and tears down via `t.Cleanup` on a fresh transport. If anything fails mid-way the disposable key is still cleaned up, so test-run-induced state leakage is bounded.

## Cross-tool verification

The SPKI fingerprint format the JSON output emits matches industry-standard tooling. Confirm a fingerprint with openssl:

```bash
openssl x509 -in chain.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | sha256sum \
  | awk '{print toupper($1)}'
```

The output of that pipeline matches the `spki_fingerprint_sha256` field in `sd keys list --json` and `sd keys export --json`. Same algorithm Chrome's cert viewer labels as "Public Key SHA-256."

Cert-chain export output is openssl-parseable. Test in CI uses `openssl x509 -in <exported.pem> -noout` as an external parser witness on every chain export round-trip — see `cmd/scpctl/ykman_shape_interop_test.go`. The same PEM format is what ykman/yubikit consume, so a chain that round-trips through openssl will also round-trip through ykman.

## Diagnostic SW visibility

When optional GET DATA reads (KLOC tag FF33, KLCC tag FF34) fail with non-success status words other than 6A88/6A82 (Reference Data Not Found), the verb emits a SKIP with the actual SW preserved in the detail line — for example:

```
GET DATA tags 0xFF33/0xFF34 (KLOC/KLCC)        SKIP — securitydomain: get CA identifiers (tag 0xFF33): card error status: SW=6982
```

That distinguishes auth-required (6982) from instruction-not-supported (6D00) from other diagnostic SWs, so an operator running unauthenticated against a card that gates KLOC reads can re-run with `--scp03-keys-default` (or the custom triple) to see the data instead of guessing why the optional data was empty.

## Known limitations

- **AES-192 / AES-256 SCP03 import** is not yet implemented. The library's PUT KEY encoding currently fixes the AES-128 key length; expanding requires library work first.
- **GP `GET STATUS` (INS=0xF2) registry walk** is `sd info --full` territory, not exposed via this group.
- **Cert chain hash export** isn't pinned in JSON output; consumers that need a stable chain identity should hash the exported PEM directly.
