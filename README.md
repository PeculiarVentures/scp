# scp

A Go implementation of the GlobalPlatform Secure Channel Protocols **SCP03** and **SCP11** for secure smart-card communication, plus a typed Security Domain management layer for key lifecycle, certificate provisioning, and trust validation.

This library opens an authenticated, encrypted channel to a smart card or secure element using one of GlobalPlatform's standard secure-channel protocols, then lets you drive the card over that channel. SCP03 uses pre-shared AES keys; SCP11 uses ECDH and X.509 certificates. Either way, once the handshake completes, every command you send is encrypted and MACed, and every response is verified before you see it. The `securitydomain` package layers typed administrator-facing operations on top: install or rotate keys, store certificates, reset back to factory state.

Reach for it when you're building PKI or device-management tooling against YubiKeys, YubiHSMs, JCOP cards, or any GlobalPlatform-conformant secure element. Concrete fits: programmatic PIV provisioning over SCP11, fleet-of-cards backends behind a relay, factory initialization with default keys, replacing a vendor SDK with a Go-native dependency that doesn't pull a Java or .NET runtime, and CA-side enrollment flows where the card's identity has to be validated against a pinned root before any operation runs.

What's different here: byte-exact verification against three independent references (Yubico .NET SDK, Samsung OpenSCP-Java, GlobalPlatformPro), not only against this library's own mock card; a deliberately narrow public API where session-key material is unreachable from the generic `Session` interface and every escape hatch is named `Insecure*`; transport as an interface, so the same code drives a local USB reader, an in-memory mock for tests, or a remote card over the gRPC CardRelay transport.

Unfamiliar terms in any of the docs are defined in [`docs/glossary.md`](docs/glossary.md). Wire-level reference traces from real hardware sessions live in [`docs/traces/`](docs/traces/) — useful when debugging a new card or firmware against a known-good capture, or when you want to see the actual byte sequence behind a protocol description rather than just the spec text.

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
- [Choosing between SCP03 and SCP11](#choosing-between-scp03-and-scp11)
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
| `cardrecognition` | Parser for GlobalPlatform Card Recognition Data (`GET DATA` tag `0x66`); decodes claimed GP version, SCP version + parameter, and identification OIDs |
| `aid` | Curated AID prefix database for SELECT-command annotation (GP, PIV, FIDO, OpenPGP, EMV, eID, health) |
| `transport` | Transport interface, GET RESPONSE chaining, response collection caps |
| `transport/pcsc` | PC/SC transport for USB CCID and NFC readers (CGO; separate `go.mod`) |
| `transport/grpc` | CardRelay gRPC transport — server wraps a real card, client implements `transport.Transport`. Separate `go.mod` so gRPC is opt-in. |
| `transport/trace` | Record/replay decorator for `transport.Transport`; SELECT exchanges auto-annotated with AID name; CRD captured into trace metadata |
| `piv` | YubiKey-flavored PIV command builders (APDU only — no PIV session layer; see package doc) |
| `mockcard` | In-memory SCP11 Security Domain for testing |

A separate hardware-validation binary lives in [`cmd/scpctl`](./cmd/scpctl). It exercises SCP03, SCP11b, and SCP11b-over-PIV against a real PC/SC card and prints PASS/FAIL/SKIP results. See its README for details.

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

### Trusting a YubiKey card

For SCP11b against a YubiKey, the production path is to validate the card's certificate chain against a pinned Yubico Secure Domain root. The chain a YubiKey 5.7+ presents on `GET DATA` tag `BF21` is rooted at a Yubico-issued CA; pinning it explicitly prevents a swap of the card from going unnoticed.

```go
import (
    "crypto/x509"
    "os"

    "github.com/PeculiarVentures/scp/scp11"
    "github.com/PeculiarVentures/scp/trust"
)

// Load the pinned Yubico SD root from disk. Replace the path with
// wherever you actually ship the PEM in your deployment.
rootPEM, err := os.ReadFile("yubico-sd-root.pem")
if err != nil {
    return err
}
roots := x509.NewCertPool()
if !roots.AppendCertsFromPEM(rootPEM) {
    return errors.New("trust: failed to parse Yubico SD root PEM")
}

cfg := scp11.YubiKeyDefaultSCP11bConfig()
cfg.CardTrustPolicy = &trust.Policy{
    Roots: roots,
    // Yubico SD certificates are P-256 ECDSA; the SCP11 layer
    // enforces this anyway, but stating it explicitly documents intent.
    // ExpectedEKUs / AllowedSerials / ExpectedSKI can pin further.
}

sess, err := scp11.Open(ctx, t, cfg)
```

A few points worth knowing for this profile specifically:

- **`InsecureSkipCardAuthentication` is the lab escape hatch, not a production option.** Setting it disables the Yubico-root check entirely; the SCP11b channel still establishes (the card still authenticates to the host with its private key) but you lose the binding between the channel and a particular Yubico-issued identity. Only set it when the goal is to separate "is the wire protocol working?" from "is trust bootstrap configured correctly?". The [`scpctl`](./cmd/scpctl) harness exposes this via `--lab-skip-scp11-trust` for exactly that purpose.

- **SCP11b is read-only against the Security Domain.** It authenticates the card to the host but not the host to the card, so `securitydomain.OpenSCP11` over SCP11b will refuse OCE-gated writes (key rotation, reset, etc.) regardless of how the trust policy is configured. SCP11a or SCP11c, with an OCE private key and matching trust material on the card, is the path for write authorization.

- **CRD is advisory.** The [`cardrecognition`](./cardrecognition) package will tell you what the card claims about itself before any authentication; this is useful for diagnostics but is not a substitute for cert-chain validation. A card that lies about its CRD is the card's bug, not a CLI bug, and the CRD is not a trust signal.

## Choosing between SCP03 and SCP11

SCP03 uses three pre-shared AES keys (ENC, MAC, DEK) that the host and the card both hold. Reach for it when those keys already exist on both sides: factory initialization with default keys, post-key-ceremony provisioning, local administration where the key custodian and the card are co-located. SCP03 is also supported on a broader range of cards than SCP11, so it's the path of least resistance against legacy hardware.

SCP11 uses ECDH key agreement and X.509 certificates. Reach for it when you don't want to distribute symmetric keys (or can't), when you need the card's identity to be cryptographically pinnable, or when the protocol state runs on a server distinct from the host with physical card access. The CardRelay deployment pattern in [`docs/remote-apdu-transport.md`](docs/remote-apdu-transport.md) only works with SCP11.

Within SCP11, three variants:

- **SCP11a** — mutual authentication; both card and off-card entity present certificates. Required for OCE-gated writes (key rotation, full reset).
- **SCP11b** — card-to-host authentication only. Read paths and PIN-gated operations work; OCE-gated writes are refused at the host-side gate. Useful when the host's identity is established by other means (a verified PIN, a vetted operator workstation, etc.).
- **SCP11c** — like SCP11a, with support for pre-computed scripts that can be replayed against a group of cards. Niche; reach for it only if you specifically need the offline scripting variant.

Both protocols return the same `scp.Session` interface, so once the handshake completes, the rest of your code doesn't care which one ran.

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
- `transport/grpc` — CardRelay network transport. Server wraps any local `transport.Transport` and exposes it over gRPC; client implements `transport.Transport`. Separate `go.mod` so the gRPC dependency tree is opt-in. See [transport/grpc/README.md](transport/grpc/README.md) for the threat model — CardRelay is transport infrastructure, not an authorization boundary.
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

These mocks are not reference implementations of GlobalPlatform card behavior — they cover the subset the host code exercises. Specifically, both mocks now answer `GET DATA` tag `0x66` (CRD) and `0x00E0` (key information) over secure messaging so host code that issues those reads can be exercised without a real card. For protocol conformance, rely on the byte-exact transcript tests above.

### Hardware verification

For end-to-end verification against an actual card, the [`cmd/scpctl`](./cmd/scpctl) binary runs a regression suite over a PC/SC reader. PASS/FAIL/SKIP per check, plus a `--json` flag for machine consumption. The current command set covers the read paths, the trust-bootstrap path, and PIV provisioning over an SCP-secured channel:

| Group | Subcommand | What it does |
|---|---|---|
| top-level | `readers` | List PC/SC readers visible to the host. |
| top-level | `probe` | Unauthenticated CRD probe — what the card claims to be before any session. |
| `test` | `scp03-sd-read` | Open SCP03 SD with factory keys; read key info + CRD over SM. |
| `test` | `scp11b-sd-read` | One-way auth (card-to-host); read-only over the SCP11b channel. |
| `test` | `scp11a-sd-read` | Mutual auth using a host OCE keypair + cert chain. Asserts the SCP11a-specific invariant `OCEAuthenticated() == true`. |
| `test` | `scp11b-piv-verify` | Open SCP11b targeting the PIV applet; `VERIFY PIN` over the wrapped channel. |
| `test` | `all` | Run probe + the SD/PIV reads in sequence with a single PASS/FAIL/SKIP summary. Provisioning commands are not in `test all` (they're destructive and sequencing-sensitive). |
| `sd` | `info` | Read CRD + key-info template; `--full` adds a GP §11.4.2 registry walk. |
| `sd` | `bootstrap-oce` | Day-1 provisioning: install OCE public key (and optionally cert chain + CA SKI) onto a card via SCP03 with factory keys. Destructive; gated by `--confirm-write` (dry-run otherwise). |
| `sd` | `bootstrap-scp11a` / `bootstrap-scp11a-sd` | Install the SCP11a SD ECDH key on a fresh card (with or without OCE in the same session). Destructive; `--confirm-write` gate. |
| `sd` | `reset` | Factory-reset SD key material. Destructive; `--confirm-write` gate. |
| `piv` | `provision` | Generate a PIV slot keypair, optionally install a cert and fetch attestation, all over an SCP11b session. Includes management-key mutual auth and cert-to-pubkey binding check. Destructive; `--confirm-write` gate. |
| `piv` | `reset` | Block PIN and PUK, then send the YubiKey PIV reset APDU. Erases ALL 24 PIV slots, certs, and resets PIN/PUK/management key to factory defaults. Destructive; gated by `--confirm-write` AND `--confirm-reset-piv`. |
| `piv` | `info` / `pin` / `puk` / `mgmt` / `key` / `cert` / `object` | Full PIV operator surface — see [`cmd/scpctl/README.md`](./cmd/scpctl/README.md). |

```
scpctl test all --reader "YubiKey" --pin 123456 --lab-skip-scp11-trust
```

The harness lives in its own Go submodule because PC/SC needs CGo; see its README for build prerequisites, the worked examples for each subcommand, and the safety-relevant notes about `--lab-skip-scp11-trust` and the `--confirm-write` destructive gate.

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

This library is the Go-native option, optimized for verified-against-references discipline, a narrow public API, and pluggable transports. Pick one of these instead if it fits your situation better:

- [Yubico/Yubico.NET.SDK](https://github.com/Yubico/Yubico.NET.SDK) (Apache 2.0) — vendor-supported .NET SDK with `SecurityDomainSession`. Pick this if you're already in the .NET ecosystem and want Yubico's own implementation. Source of cross-implementation test vectors used here.
- [Yubico/yubikey-manager](https://github.com/Yubico/yubikey-manager) (BSD 2-clause) — Python `yubikit.securitydomain` and SCP core. Pick this for Python projects or if you want the same library that powers `ykman`. Source of OCE certificate test fixtures used here.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — full SCP03 and SCP11 in Java. Pick this for JVM projects, especially if you need the SCP11 variants Samsung covers and we list as expansion targets (Brainpool, P-384, AES-192/256 SCP11). Source of byte-exact SCP03 transcripts and SCP11 vectors used here.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI covering SCP01, SCP02, and SCP03 with broad real-card coverage. Pick this if you need legacy SCP01/SCP02 support, mature Java tooling for applet loading, or the widest range of GP card vendors validated.
- [skythen/scp03](https://github.com/skythen/scp03) — pure-Go SCP03 with a similar `Transmitter` interface pattern. Pick this if you only need SCP03, no SCP11, and no Security Domain management layer.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Java implementation of both card-side and host-side SCP11b. Pick this if you need a card-side reference for testing or are implementing SCP11b in a JVM environment.
