# scp

A Go implementation of the GlobalPlatform Secure Channel Protocols **SCP03** and **SCP11** for secure smart-card communication, plus a typed Security Domain management layer for key lifecycle, certificate provisioning, and trust validation.

The library is standards-oriented and compatibility-expanding. It is structured so consumers can match their integration to validated material rather than to a single vendor. Support is documented across three explicit categories: **verified profiles** (validated against hardware *and* independent reference implementations), **implemented GlobalPlatform capabilities** (standards-compatible behavior implemented against the GP specs, exercisable today against any GP-conformant card), and **expansion targets** (in-scope work waiting on additional cards or reference material to validate against).

## Table of contents

- [Assurance levels](#assurance-levels)
  - [Verified profiles](#verified-profiles)
  - [Implemented GlobalPlatform capabilities](#implemented-globalplatform-capabilities)
  - [Expansion targets](#expansion-targets)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Packages](#packages)
- [Security Domain Management](#security-domain-management)
- [Certificate Trust Validation](#certificate-trust-validation)
- [SCP03 Usage](#scp03-usage)
- [SCP11 Usage](#scp11-usage)
- [CLA encoding and logical channels](#cla-encoding-and-logical-channels)
- [Transports](#transports)
- [Testing](#testing)
- [Specification compliance](#specification-compliance)
- [License](#license)
- [Related implementations](#related-implementations)

---

## Assurance levels

### Verified profiles

A *verified profile* combines hardware execution with byte-exact validation against an independent reference implementation. Behavior in this category is the most reliable basis for production integration.

**YubiKey** is the currently verified profile. Verification covers:

- **SCP03 AES-128**: end-to-end handshake (INITIALIZE UPDATE + EXTERNAL AUTHENTICATE), session-key derivation, secure messaging (C-MAC, C-ENC, R-MAC, R-ENC), and `LevelFull` security. Verified byte-exact against Yubico's .NET SDK channel and KDF vectors and against martinpaljak/GlobalPlatformPro JCOP4 dumps.
- **SCP11 P-256, AES-128, S8, full security level**: SCP11a, SCP11b, and SCP11c handshakes, OCE certificate upload (PERFORM SECURITY OPERATION), receipt verification (mandatory by default per Amendment F v1.4), and post-handshake secure messaging. Verified byte-exact against Samsung OpenSCP-Java SCP11a transcripts and against the Yubico OCE certificate fixtures.
- **YubiKey-compatible empty-data behavior**: the channel package's `EmptyDataYubico` policy (pad-and-encrypt one block) is the default, matching what YubiKey expects.
- **YubiKey Security Domain management profile**: PUT KEY for AES-128 SCP03 keys and SCP11 ECKA P-256 keys; STORE CERTIFICATES, STORE DATA, GET DATA, GET KEY INFORMATION, GENERATE EC KEY, DELETE KEY, RESET. Tracks the operations exercised by `yubikit.securitydomain` and the .NET `SecurityDomainSession`.

### Implemented GlobalPlatform capabilities

A capability in this category is implemented against the GP/ISO specs and exercisable today against any conformant card. Where hardware validation has happened it is called out; where it has not, the behavior is built from the spec and from independent reference vectors but does not yet have an entry in the verified-profiles list.

| Capability | Notes |
|---|---|
| SCP03 AES-128 / AES-192 / AES-256 | All three key sizes implemented at handshake, KDF, and secure-messaging layers; all three byte-exact-verified against Samsung OpenSCP-Java vectors at the protocol layer. AES-128 is also verified against YubiKey hardware; AES-192 / AES-256 are protocol-layer-verified pending hardware validation against a card that supports them. |
| SCP03 S8 + S16 | All six combinations (3 AES sizes × 2 MAC modes) verified at the protocol layer against Samsung OpenSCP-Java. S8 verified end-to-end against YubiKey hardware. S16 is an [expansion target](#expansion-targets) for hardware verification. |
| SCP11 X.509 card-trust validation | The `trust` package validates SCP11 card certificate chains: leaf-last and leaf-first chain ordering, intermediate fall-through, EKU enforcement, optional SKI / serial-allowlist constraints, P-256 invariant enforced after every validator return. |
| Custom validation for GP-proprietary SCP11 certificate stores | `trust.Policy.CustomValidator` is the supported extension point for cards that present GP-proprietary SCP11 certificates instead of standard X.509. The hook owns the trust decision; the protocol layer still enforces P-256 and ECDH-convertibility on whatever public key the validator returns. See [Custom validation](#custom-validation-for-gp-proprietary-scp11-certificate-stores) below. |
| Configurable empty-data behavior | `channel.EmptyDataPolicy` selects between `EmptyDataYubico` (pad-and-encrypt one block; default) and `EmptyDataGPLiteral` (skip encryption when data is empty) so the channel layer can match either of the two interpretations real GP cards have shipped. |
| Short and extended APDUs | The `apdu` package and the `transport.Transmit*` helpers handle both ISO 7816-4 short-form (4-byte header, ≤256-byte data) and extended-length (7-byte header, up to 65535-byte data) APDUs throughout the stack. SCP11 OCE certificate upload uses extended APDUs by default; transports that lack extended-APDU support are flagged as an [expansion target](#expansion-targets). |
| GET RESPONSE chaining | `transport.TransmitWithChaining` and `TransmitCollectAll` issue follow-up `00 C0 00 00 Le` commands when the card returns `61xx` continuation indications, with `MaxGetResponseIterations` and `MaxCollectedResponseBytes` caps to prevent hostile-card resource exhaustion. |
| BER-TLV parsing and construction | The `tlv` package handles GP-relevant BER-TLV constructs used in INITIALIZE UPDATE responses, EXTERNAL AUTHENTICATE payloads, OCE certificate stores (BF21), and Security Domain command/response data. |
| Transport-independent APDU construction | The `transport.Transport` interface is the integration boundary. Any byte-pipe that can carry ISO 7816-4 APDUs in either parsed (`*apdu.Command` / `*apdu.Response`) or raw (`[]byte`) form satisfies the interface. PC/SC, in-memory mock cards, and gRPC-style remote APDU relays (see [`docs/remote-apdu-transport.md`](docs/remote-apdu-transport.md)) all plug in here. |
| ISO 7816-4 CLA encoding | The `channel` package centralizes CLA decoding for first-interindustry, further-interindustry, and proprietary classes. Secure-messaging bit position differs by class (0x04 vs 0x20); `Wrap` uses `channel.SecureMessagingCLA` so the same secure-messaging stack drives basic-channel and logical-channel commands without silently miscoding. See [CLA encoding and logical channels](#cla-encoding-and-logical-channels). |

### Expansion targets

Work that is in scope for the project but waiting on additional cards, reference material, or consumer feedback to validate against. Items in this category are expected to be picked up as the verification footprint grows.

- **Additional non-YubiKey GP cards** as verified profiles. The protocol-layer correctness is in place; what's missing is hardware exposure to surface vendor-specific quirks (SELECT response shapes, GET KEY INFORMATION dialect variations, status-word semantics that differ from the GP spec).
- **Java Card security domains** as verified profiles. Java Card SDs follow GP Card Spec but typical cards run the GP reference implementation with vendor patches; both happy-path and quirk coverage need real cards.
- **Additional vendor certificate-store formats**. The trust package currently understands BF21 X.509 chains and exposes `CustomValidator` for GP-proprietary stores. Specific vendor formats (Samsung OpenSCP, NXP J3R200) can be added as named typed validators when reference material is available.
- **SCP03 AES-192 / AES-256 management profiles**. `scp03.Open` already supports all three AES sizes for *channel establishment*. The `securitydomain.PutSCP03Key` provisioning flow currently covers the AES-128 management profile; AES-192 / AES-256 PUT KEY shapes need a card and reference vectors to validate against.
- **SCP03 S16 hardware validation**. S16 is implemented and protocol-layer-verified against Samsung vectors; a card that issues S16 by default would let it move to a verified profile.
- **SCP11 HostID / CardGroupID wire behavior**. The Config fields exist and feed the KDF shared-info; the AUTHENTICATE parameter bit and the tag-`0x84` TLV are not yet wired, and `Open` fails closed if either field is set. Completing the wire-side encoding is in scope; tracking implementation work covering the AUTHENTICATE parameter bit, tag `0x84`, and matching KDF shared-info behavior.
- **Broader logical-channel behavior end-to-end**. The CLA-encoding helper supports basic channel (0–3) and logical channels 4–19 at the wrap layer; integration tests currently cover basic channel only because the in-tree mocks use channel 0. Real-card validation across multi-channel scenarios is the next step.
- **Additional Security Domain management profiles**. The `securitydomain` package is the first typed management profile and reflects the YubiKey-verified behavior. The package structure (typed config types, capability interfaces for OCE-auth and DEK provision, custom-session opt-in) is designed to support additional profiles for non-YubiKey cards without subclass-style proliferation.

---

## Quick start

```go
// SCP03 — symmetric keys
sess, err := scp03.Open(ctx, transport, &scp03.Config{
    Keys: scp03.StaticKeys{ENC: encKey, MAC: macKey, DEK: dekKey},
})

// SCP11b — ECDH key agreement, with X.509 card trust anchors
sess, err := scp11.Open(ctx, transport, &scp11.Config{
    Variant:         scp11.SCP11b,
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})

// SCP11a — mutual authentication with OCE certificate
sess, err := scp11.Open(ctx, transport, &scp11.Config{
    Variant:         scp11.SCP11a,
    OCEPrivateKey:   ocePrivateKey,
    OCECertificates: []*x509.Certificate{oceCert},
    OCEKeyReference: scp11.KeyRef{KID: 0x10, KVN: 0x03},
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})

// Both return scp.Session — same Transmit API
resp, err := sess.Transmit(ctx, myCommand)
sess.Close()
```

`scp11.Open` requires explicit trust configuration; see [SCP11 Usage](#scp11-usage) for the required fields and the test/lab escape hatch.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Your Application                    │
├──────────────────┬───────────────────────────────────┤
│  securitydomain  │  trust.Policy                     │
│  .Session        │  X.509 chain validation,          │
│  Key mgmt, certs │  CustomValidator extension hook   │
├──────────────────┴───────────────────────────────────┤
│  scp03.Open()            scp11.Open() (SCP11)      │
├──────────────────────────────────────────────────────┤
│  scp.Session (common interface)                       │
│  ┌────────────────────────────────────────────────┐   │
│  │  channel (secure messaging)                    │   │
│  │  AES-CBC encrypt, AES-CMAC, MAC chaining,      │   │
│  │  ISO 7816-4 CLA / logical-channel encoding     │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────┐  ┌────────┐  ┌─────┐  ┌──────┐           │
│  │  kdf   │  │  cmac  │  │ tlv │  │ apdu │           │
│  └────────┘  └────────┘  └─────┘  └──────┘           │
├──────────────────────────────────────────────────────┤
│              transport.Transport                      │
│  (PC/SC, NFC, gRPC relay, mock card, ...)            │
└──────────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `scp` | Common `Session` interface implemented by both protocols |
| `scp03` | SCP03 handshake: INITIALIZE UPDATE + EXTERNAL AUTHENTICATE; AES-128/192/256 |
| `scp11` | SCP11 handshake: ECDH key agreement (variants a/b/c) |
| `securitydomain` | First typed Security Domain management profile (YubiKey-verified); structure is designed for additional profiles over time |
| `trust` | SCP11 certificate-chain validation with configurable policy and `CustomValidator` extension |
| `channel` | Secure messaging shared by both protocols (encrypt, MAC, verify); ISO 7816-4 CLA / logical-channel helpers |
| `kdf` | Key derivation: X9.63 KDF (single-stage YubiKey/Samsung-vector-compatible profile), NIST SP 800-108 |
| `cmac` | AES-CMAC per NIST SP 800-38B |
| `tlv` | BER-TLV encoding / decoding for GP data structures |
| `apdu` | ISO 7816-4 command / response APDU types |
| `transport` | Transport interface, GET RESPONSE chaining, response collection caps |
| `transport/pcsc` | PC/SC transport for USB CCID and NFC readers (CGO; separate `go.mod`) |
| `piv` | YubiKey-flavored PIV command builders (APDU only — no PIV session layer; see package doc) |
| `mockcard` | In-memory SCP11 Security Domain for testing |

## Security Domain Management

The `securitydomain` package provides typed APIs for administering a GlobalPlatform Security Domain. It wraps an authenticated SCP channel and exposes the operations needed for real provisioning workflows. This is the **first typed management profile** in the library and currently reflects the YubiKey-verified behavior; the package structure is designed for additional GP Security Domain profiles over time.

```go
// Open an authenticated management session
sd, err := securitydomain.OpenSCP03(ctx, transport, &scp03.Config{
    Keys:       scp03.DefaultKeys,
    KeyVersion: 0xFF,
})
defer sd.Close()

// Inspect installed keys
keys, _ := sd.GetKeyInformation(ctx)

// Install a new SCP03 key set (replaces default).
// Note: PutSCP03Key currently covers the AES-128 management profile;
// AES-192 / AES-256 management is an expansion target.
ref := securitydomain.NewKeyReference(securitydomain.KeyIDSCP03, 0x01)
sd.PutSCP03Key(ctx, ref, newKeys, 0xFF)

// Generate an SCP11b key pair on the device
scp11Ref := securitydomain.NewKeyReference(securitydomain.KeyIDSCP11b, 0x01)
pubKey, _ := sd.GenerateECKey(ctx, scp11Ref, 0)

// Store certificates for the generated key
sd.StoreCertificates(ctx, scp11Ref, certChain)

// Configure SCP11a with OCE and CA issuer
oceRef := securitydomain.NewKeyReference(securitydomain.KeyIDOCE, 0x03)
sd.PutECPublicKey(ctx, oceRef, ocePublicKey, 0)
sd.StoreCaIssuer(ctx, oceRef, subjectKeyIdentifier)

// Build the allowlist from x509 certificate serials directly
var allowed []*big.Int
for _, c := range trustedCerts {
    allowed = append(allowed, c.SerialNumber)
}
sd.StoreAllowlist(ctx, oceRef, allowed)

// Factory reset (restores default keys)
sd.Reset(ctx)
```

The full API covers: `PutSCP03Key`, `GenerateECKey`, `PutECPrivateKey`, `PutECPublicKey`, `DeleteKey`, `Reset`, `GetKeyInformation`, `GetCardRecognitionData`, `GetSupportedCaIdentifiers`, `StoreCertificates`, `GetCertificates`, `StoreCaIssuer`, `StoreAllowlist`, `ClearAllowlist`, `StoreData`, `GetData`.

## Certificate Trust Validation

The `trust` package validates SCP11 certificate chains before trusting a card's identity. It is fail-closed: if trust anchors are configured and validation fails, the library will not fall back to raw key extraction.

### What "trust" means here

`trust.Policy` carries the X.509 trust configuration: roots, optional intermediates, EKU constraints, and optional SKI / serial allowlists. The session layer feeds the card's certificate chain through `Policy.Validate` before completing the SCP11 handshake. P-256 and ECDH-convertibility on the validated public key are protocol-level invariants and are enforced after `Validate` returns, regardless of how validation was performed.

### Custom validation for GP-proprietary SCP11 certificate stores

Some cards present SCP11 certificates in GP-proprietary formats rather than standard X.509. `trust.Policy.CustomValidator` is the supported extension point for those:

```go
policy := &trust.Policy{
    CustomValidator: func(rawChain []byte) (*trust.Result, error) {
        // Parse the GP-proprietary chain; return the leaf public key.
        pub, err := myVendorParser(rawChain)
        if err != nil {
            return nil, err
        }
        return &trust.Result{PublicKey: pub}, nil
    },
}
```

When `CustomValidator` is set, it owns the trust decision: roots, EKU, SKI, and serial-allowlist policy fields are not consulted (so don't set them and expect them to compose). What the protocol layer *does* enforce regardless is the curve invariant (P-256) and ECDH-convertibility — a custom validator returning a non-P-256 public key, or a key the standard library can't convert to `*ecdh.PublicKey`, is rejected at the SCP11 layer before any ECDH happens.

This is the path to take when integrating with vendor-specific certificate stores. Generic GP-proprietary parsers can be contributed as additional implementations of `Policy.CustomValidator`.

## SCP03 Usage

```go
// AES-128, AES-192, or AES-256 — all three are supported by scp03.Open
// at the protocol layer. AES-128 is verified against YubiKey hardware
// today; AES-192/256 are verified against Samsung OpenSCP-Java vectors
// at the protocol layer pending hardware validation.
sess, err := scp03.Open(ctx, transport, &scp03.Config{
    Keys: scp03.StaticKeys{ENC: encKey, MAC: macKey, DEK: dekKey},
})
```

`scp03.Config` accepts:

- **Keys** (required): `StaticKeys{ENC, MAC, DEK}`. All three must be the same length (16 / 24 / 32 bytes for AES-128/192/256). Mixed sizes are rejected. There is no silent default to `scp03.DefaultKeys` (the GP test keys); callers must explicitly opt in.
- **KeyVersion**: KVN to send in INITIALIZE UPDATE. Defaults to `0` (any version). `scp03.YubiKeyFactoryKeyVersion` (`0xFF`) is the YubiKey factory-reset KVN.
- **SecurityLevel**: `LevelFull` (`C-MAC | C-DEC | R-MAC | R-ENC`) is the default and the recommended profile. Partial security levels are rejected unless `InsecureAllowPartialSecurityLevel` is set; this gate exists for spec-conformance testing only.
- **HostChallenge**: optional 8 (S8) or 16 (S16) byte challenge. Random by default.
- **SelectAID** / **ApplicationAID**: control the SELECT / post-handshake SELECT.

### Factory and spec default keys

```go
// YubiKey factory reset
sess, err := scp03.Open(ctx, transport, scp03.FactoryYubiKeyConfig())

// GP spec test keys (DO NOT use in production)
sess, err := scp03.Open(ctx, transport, &scp03.Config{
    Keys: scp03.DefaultKeys,
})
```

| Profile | Helper | KVN | Notes |
|---|---|---|---|
| YubiKey factory reset | `FactoryYubiKeyConfig()` | `0xFF` | Default keys after `securitydomain.Reset` on YubiKey |
| GP spec test | `DefaultKeys` constant | any | All-`0x40 41 42 ...` test keys; never use in production |
| Custom keys | `Config{Keys: ...}` | caller | The realistic path |

## SCP11 Usage

```go
// SCP11b — one-way auth (card to host)
sess, err := scp11.Open(ctx, transport, &scp11.Config{
    Variant:         scp11.SCP11b,
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})

// SCP11a — mutual authentication with certificates
sess, err := scp11.Open(ctx, transport, &scp11.Config{
    Variant:         scp11.SCP11a,
    KeyID:           0x11,
    OCEPrivateKey:   myECDSAKey,
    OCECertificates: []*x509.Certificate{myOCECert}, // leaf-last; must correspond to OCEPrivateKey
    OCEKeyReference: scp11.KeyRef{KID: 0x10, KVN: 0x03}, // card-side OCE key slot (KID 0x10 is the YubiKey default)
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})
```

### Card authentication

`scp11.Open` fails closed unless one of these is set:

- `CardTrustPolicy` — preferred; full chain validation through the `trust` package, with P-256 enforcement and optional serial / SKI / EKU constraints. `CustomValidator` is the extension point for GP-proprietary certificate stores.
- `CardTrustAnchors` — full X.509 chain validation against a `*x509.CertPool`. Intermediates from the card's BF21 certificate store are picked up automatically.
- `InsecureSkipCardAuthentication` — escape hatch for tests and labs only. Without it, `scp11.Open` against a card that returns a self-signed or proprietary key is rejected before any ECDH.

This is intentional: an SCP11b session against an unauthenticated card is not authenticated key agreement — it is opportunistic encryption against whoever answered the SELECT.

### Applet selection

`scp11.Open` SELECTs `cfg.SelectAID` before the handshake. The applet at that AID is the one whose SCP key set the handshake authenticates against. On YubiKey, different applets hold different SCP key sets:

- Default: `AIDSecurityDomain` — Issuer Security Domain (`A0 00 00 01 51 00 00 00`).
- For applet-specific channels (PIV, OATH): set `cfg.SelectAID` to the applet AID and `cfg.ApplicationAID` (if needed for post-handshake re-SELECT) accordingly.

### Variant and curve support

| Variant | Auth | Card cert | OCE cert |
|---|---|---|---|
| SCP11a | Mutual | Required | Required |
| SCP11b | Card → host only | Required | None |
| SCP11c | Mutual (offline scripting) | Required | Required |

P-256 is the verified curve; AES-128 is the verified session-key size; S8 is the verified MAC mode. P-384, Brainpool P-256, AES-192/256 SCP11 sessions, and S16 16-byte MACs are out of scope for the SCP11 profile today (channel layer supports S16; the SCP11 session path is hardwired to S8).

### SCP11a/c key/certificate consistency

For mutual-auth variants, `Open` verifies that `OCEPrivateKey` corresponds to the leaf entry in `OCECertificates` before sending anything to the card. A mismatch is rejected immediately rather than discovered in the second ECDH.

### SCP11a/c transport requirements

OCE certificate upload (`PERFORM SECURITY OPERATION` in the SCP11a/c handshake) sends each cert as a single APDU. Real X.509 OCE certs run 300–800 bytes, so the transport must support **extended-length APDUs**. USB CCID and modern NFC readers handle this natively; some constrained NFC paths and legacy contact readers do not. This is a limit of the wire format, not the library.

## CLA encoding and logical channels

The `channel` package centralizes ISO 7816-4 §5.4.1 / GP Card Spec §11.1.4 CLA encoding so the secure-messaging stack works correctly across all classes a real GP card might use, not just basic-channel proprietary CLA.

| Class encoding | CLA range | SM bit | Logical channel |
|---|---|---|---|
| First interindustry | `0x00`–`0x3F` | `0x04` | bits 0–1 (channels 0–3) |
| Further interindustry | `0x40`–`0x7F` | `0x20` | bits 0–3 + 4 (channels 4–19) |
| Proprietary (GP convention) | `0x80`–`0xFE` | `0x04` | bits 0–1 (channels 0–3) |
| Reserved | `0xFF` | n/a | n/a |

Helpers:

- `channel.SecureMessagingCLA(cla)` — set the SM bit per class.
- `channel.ClearSecureMessagingCLA(cla)` — clear the SM bit per class (mirror).
- `channel.IsSecureMessaging(cla)` — class-aware detection.
- `channel.LogicalChannel(cla)` — decode 0–19.
- `channel.IsCommandChaining(cla)` — chaining bit (position `0x10` in both first- and further-interindustry encodings).

`Wrap` uses `SecureMessagingCLA` so the same call works for basic-channel YubiKey CLAs (`0x00`, `0x80`, `0x84`) and for further-interindustry CLAs that encode logical channels 4–19. Logical-channel end-to-end against real cards is an [expansion target](#expansion-targets) (the in-tree mocks use channel 0).

## Transports

The `transport.Transport` interface is the integration point for connecting to hardware:

```go
type Transport interface {
    Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
    TransmitRaw(ctx context.Context, raw []byte) ([]byte, error)
    Close() error
}
```

`Transmit` operates on parsed APDUs (the convenient host-side path). `TransmitRaw` is the same operation on opaque bytes — it exists so transports that already speak APDUs as raw bytes (PC/SC, gRPC relays) can avoid a parse / serialize round-trip in the hot path, and so the relay deployment model in [`docs/remote-apdu-transport.md`](docs/remote-apdu-transport.md) can carry SCP secure messaging through any byte pipe without parsing.

Built-in transports:

- `transport/pcsc` — PC/SC for USB CCID and NFC readers via `ebfe/scard`. Lives in a separate `go.mod` so the CGO dependency on libpcsclite is opt-in.
- `mockcard` — in-memory SCP11 Security Domain for testing. See [Testing](#testing).
- `scp03.MockCard` — in-memory SCP03 card for testing. See [Testing](#testing).

## Testing

```
go test ./...
```

The suite covers protocol behavior end-to-end (handshake, encrypted echo, MAC chain continuity, error paths) and security regressions (fail-closed trust, DEK validation, error-response R-MAC, resource limits on TLV decode and GET RESPONSE collection).

Conformance is checked against external references rather than only against this library's own mock card:

- **GlobalPlatformPro JCOP4** — real-card SCP03 INITIALIZE UPDATE and EXTERNAL AUTHENTICATE dump.
- **Samsung OpenSCP-Java** — full SCP03 transcript matrix: AES-128, AES-192, AES-256 × S8 and S16 modes (all six cells), each a byte-exact known-answer test using the static keys and host challenges from the Samsung test fixtures.
- **Yubico .NET SDK** — SCP03 KDF and channel MAC vectors; SCP11 reference test vectors; real Yubico OCE certificate chain.

These are byte-exact known-answer tests using a recording transport, so they catch regressions a mock card couldn't.

### Mock card fixtures

For tests and local development, the library ships with two in-memory mock cards. SCP03 and SCP11 have genuinely different setup needs (pre-shared symmetric keys vs. asymmetric key + certificate), so each protocol's mock lives next to its implementation rather than being conflated into a single either/or `Card` type:

- `mockcard.Card` (in [`mockcard/`](./mockcard)) — SCP11 mock (a, b, c). `mockcard.New()` returns a card with a fresh P-256 key and self-signed cert. `Variant` and `LegacySCP11bNoReceipt` fields tweak behavior for testing variants and pre-Amendment-F-v1.4 cards. Used by the relay tests, replay-rejection regression tests, and the `cmd/example` end-to-end demo.
- `scp03.MockCard` (in [`scp03/`](./scp03)) — SCP03 mock. `scp03.NewMockCard(keys)` configures with any `StaticKeys` (typically `scp03.DefaultKeys` for factory-fresh card emulation, or a generated set for key-rotation tests). Used by the SCP03 protocol tests.

Both expose a `Transport()` method returning something satisfying `transport.Transport`, so test code at session or Security Domain level can be parameterized over either when the test logic doesn't care which protocol is underneath.

These mocks are not reference implementations of GlobalPlatform card behavior — they cover the subset the host code exercises. For protocol conformance, rely on the byte-exact transcript tests above.

## Specification compliance

| Spec | Coverage |
|---|---|
| GP Card Spec v2.3.1 §11 | Security Domain APDU commands: PUT KEY, DELETE, STORE DATA, GET DATA |
| GP Amendment D (SCP03) v1.2 | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, session key derivation, secure messaging, S8 and S16 modes, AES-128/192/256 |
| GP Amendment F (SCP11) v1.3 / v1.4 (subset) | SCP11a, SCP11b, SCP11c; ECKA; X9.63 KDF (single-stage YubiKey/Samsung-vector-compatible profile); 8-byte cryptograms and MACs (S8); receipt verification required by default for all three variants. The receipt-required-for-SCP11b default tracks Amendment F v1.4 and modern YubiKey behavior; older v1.3 cards that omit the SCP11b receipt need `InsecureAllowSCP11bWithoutReceipt`. P-384 / Brainpool / S16 / partial security / HostID-CardGroupID auth-rule wire encoding are [expansion targets](#expansion-targets). |
| GP Card Spec v2.3 §10.8 | Secure messaging: C-MAC, C-ENC, R-MAC, R-ENC |
| ISO 7816-4 §5.4.1 | CLA encoding, logical channels (basic + further interindustry), command chaining |
| NIST SP 800-108 | KDF in counter mode with AES-CMAC |
| NIST SP 800-38B | AES-CMAC |
| BSI TR-03111 | ECDH with zero-point validation, X9.63 KDF |

External transcript validation: SCP03 byte-exact against GlobalPlatformPro and Samsung OpenSCP-Java AES-128/192/256 × S8/S16 vectors; SCP11a P-256/AES-128/S8 byte-exact against Samsung OpenSCP-Java end-to-end (handshake + wrapped command).

## License

Apache 2.0

## Related implementations

- [Yubico/Yubico.NET.SDK](https://github.com/Yubico/Yubico.NET.SDK) (Apache 2.0) — Reference .NET SDK with `SecurityDomainSession`. Source of cross-implementation test vectors.
- [Yubico/yubikey-manager](https://github.com/Yubico/yubikey-manager) (BSD 2-clause) — Python `yubikit.securitydomain` and SCP core. Source of OCE certificate test fixtures.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — Full SCP03 + SCP11 in Java. Source of SCP11 reference test vectors and full SCP03 AES × S8/S16 transcripts.
- [skythen/scp03](https://github.com/skythen/scp03) — Pure Go SCP03. Similar `Transmitter` interface pattern.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI. SCP01 / 02 / 03 with broad GP card coverage.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Card-side and host-side SCP11b in Java.
