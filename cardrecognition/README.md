# cardrecognition

Parses GlobalPlatform Card Recognition Data (CRD) — the BER-TLV
structure a GP card returns from `GET DATA 80CA0066`.

CRD is the spec-defined way for a card to advertise its GP version,
supported SCP version + `i` parameter, card identification scheme,
and optional configuration / chip / trust-point details.

## Use

```go
import "github.com/PeculiarVentures/scp/cardrecognition"

// Against a transport that has had the ISD selected:
info, err := cardrecognition.Read(ctx, t)
if errors.Is(err, cardrecognition.ErrNotPresent) {
    // Card doesn't expose CRD; some don't.
}

fmt.Println(info.GPVersion)        // "2.3.1"
fmt.Printf("SCP%02X i=%02X\n",
    info.SCP, info.SCPParameter)   // "SCP03 i=70"
```

Or parse pre-captured bytes (e.g. from a trace file):

```go
info, err := cardrecognition.Parse(rawTagBytes)
```

## Scope

This package is **diagnostic / metadata only**. It does NOT drive
SCP protocol selection. The `scp03` and `scp11` packages still
require an explicit `Config`. Auto-detecting SCP from CRD has subtle
security implications — a hostile or buggy card could lie about CRD
to coerce a downgrade — so callers configure protocol explicitly
and use CRD only as a check.

What this package is good for:

- **Trace metadata.** Stamp `info` into a trace file header so the
  trace records what kind of card produced it.
- **Probe / diagnostic CLI output.** Render which GP version and
  SCP variants the card claims.
- **Sanity check.** "I configured SCP03; the card advertises only
  SCP02" → log a warning before the handshake fails opaquely.

## What is parsed

The full envelope per GP Card Spec v2.3.1 §H.2:

| Tag (App-Tag) | Field | Field on `CardInfo` |
|---|---|---|
| `60` (0) | GP version OID | `GPVersion`, `GPVersionOID` |
| `63` (3) | Card ID Scheme OID | `CardIDSchemeOID` |
| `64` (4) | SCP version + `i` | `SCP`, `SCPParameter`, `SCPVersionOID` |
| `65` (5) | Card Configuration Details (optional) | `CardConfigurationDetails` (raw) |
| `66` (6) | Card / Chip Details (optional) | `ChipDetails` (raw) |
| `67` (7) | Issuer Trust Point Info (optional) | `IssuerTrustPointInfo` (raw) |
| `68` (8) | Issuer Cert Info (optional) | `IssuerCertInfo` (raw) |

Optional sections are exposed as raw bytes — their internal format
is profile-specific and not currently decoded. Unrecognized inner
tags are collected into `UnknownTags` for diagnostic visibility
without forcing the caller to re-parse `Raw`.

## Verification

The parser has a real-card test against the Nokia 6131 NFC GP applet
CRD captured at `0x9000.blogspot.com/2009` (a widely-cited reference
sample), plus synthetic tests for SCP03 and SCP11 OID shapes. If the
parser ever produces output that contradicts the GP wiki annotation
of that capture, the parser is wrong.
