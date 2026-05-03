# scp

A Go implementation of GlobalPlatform Secure Channel Protocols for establishing authenticated and encrypted communication with smart cards, plus a typed Security Domain management layer for key lifecycle, certificate provisioning, and trust validation.

Two protocols are supported through a unified API:

- **SCP03** (Amendment D) — Symmetric key protocol using pre-shared AES keys
- **SCP11** (Amendment F) — Asymmetric protocol using ECDH key agreement and X.509 certificates, with variants SCP11a, SCP11b, and SCP11c

Both protocols produce a `scp.Session` with the same `Transmit` method. The consumer writes protocol-agnostic code after the initial `Open` call.

## Quick Start

```go
// SCP03 — symmetric keys
sess, err := scp03.Open(ctx, transport, &scp03.Config{
    Keys: scp03.StaticKeys{ENC: encKey, MAC: macKey, DEK: dekKey},
})

// SCP11b — ECDH key agreement, with the card's trust anchors
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:          session.SCP11b,
    CardTrustPolicy:  &trust.Policy{Roots: rootPool},
})

// Both return scp.Session — same API from here on
resp, err := sess.Transmit(ctx, myCommand)
sess.Close()
```

`session.Open` requires explicit trust configuration; see [SCP11 Usage](#scp11-usage) below for the required fields and the "test/lab" escape hatch.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Your Application                    │
├──────────────────┬───────────────────────────────────┤
│  securitydomain  │  trust.ValidateSCP11Chain()       │
│  .Session        │  Chain validation, P-256, SKI,    │
│  Key mgmt, certs │  serial allowlists, fail-closed   │
├──────────────────┴───────────────────────────────────┤
│  scp03.Open()            session.Open() (SCP11)      │
├──────────────────────────────────────────────────────┤
│  scp.Session (common interface)                       │
│  ┌────────────────────────────────────────────────┐   │
│  │  channel (secure messaging)                    │   │
│  │  AES-CBC encrypt, AES-CMAC, MAC chaining       │   │
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
| `scp03` | SCP03 handshake: INITIALIZE UPDATE + EXTERNAL AUTHENTICATE |
| `session` | SCP11 handshake: ECDH key agreement (variants a/b/c) |
| `securitydomain` | Security Domain management: key lifecycle, certificates, allowlists, reset |
| `trust` | SCP11 certificate chain validation with configurable policy |
| `channel` | Secure messaging shared by both protocols (encrypt, MAC, verify) |
| `kdf` | Key derivation: X9.63 KDF, NIST SP 800-108 |
| `cmac` | AES-CMAC per NIST SP 800-38B |
| `tlv` | BER-TLV encoding/decoding for GP data structures |
| `apdu` | ISO 7816-4 command/response APDU types |
| `transport` | Transport interface and helpers |
| `piv` | YubiKey-flavored PIV command builders (APDU only — no PIV session layer; see package doc) |
| `mockcard` | Simulated SCP11 Security Domain for testing |

## Security Domain Management

The `securitydomain` package provides typed APIs for administering the YubiKey Security Domain. It wraps an authenticated SCP channel and exposes the operations needed for real provisioning workflows.

```go
// Open an authenticated management session
sd, err := securitydomain.Open(ctx, transport, scp03.DefaultKeys, 0x00)
defer sd.Close()

// Inspect installed keys
keys, _ := sd.GetKeyInformation(ctx)

// Install a new SCP03 key set (replaces default)
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
sd.StoreAllowlist(ctx, oceRef, []string{"serial1hex", "serial2hex"})

// Factory reset (restores default keys)
sd.Reset(ctx)
```

The full API covers: `PutSCP03Key`, `GenerateECKey`, `PutECPrivateKey`, `PutECPublicKey`, `DeleteKey`, `Reset`, `GetKeyInformation`, `GetCardRecognitionData`, `GetSupportedCaIdentifiers`, `StoreCertificates`, `GetCertificates`, `StoreCaIssuer`, `StoreAllowlist`, `ClearAllowlist`, `StoreData`, `GetData`.

APDU encoding has been validated against the [Yubico .NET SDK](https://github.com/Yubico/Yubico.NET.SDK) and [yubikey-manager](https://github.com/Yubico/yubikey-manager) Python SDK.

## Certificate Trust Validation

The `trust` package validates SCP11 certificate chains before trusting a card's identity. It is fail-closed: if trust anchors are configured and validation fails, the library will not fall back to raw key extraction.

```go
result, err := trust.ValidateSCP11Chain(certs, trust.Policy{
    Roots:         rootPool,
    Intermediates: intermediatePool,
    CurrentTime:   time.Now(),
    AllowedSerials: []string{"6b900288..."},  // optional
    ExpectedSKI:    skiBytes,                  // optional
})
// result.Leaf, result.PublicKey, result.Chain

// Or integrate directly into SCP11 session establishment:
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:         session.SCP11b,
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})
```

## SCP03 Usage

SCP03 uses pre-shared symmetric keys. Most cards ship with well-known default keys that must be replaced in production.

```go
sess, err := scp03.Open(ctx, transport, &scp03.Config{
    Keys:       scp03.DefaultKeys,  // TESTING ONLY
    KeyVersion: 0x01,
    SelectAID:  session.AIDSecurityDomain,
})
if err != nil {
    log.Fatal(err)
}
defer sess.Close()

resp, err := sess.Transmit(ctx, &apdu.Command{
    CLA: 0x00, INS: 0x47, P1: 0x00, P2: 0x9A,
    Data: []byte{0xAC, 0x03, 0x80, 0x01, 0x11},
})
```

## SCP11 Usage

SCP11 uses ECDH key agreement with X.509 certificates. Three variants:

```go
// SCP11b — card authenticates to host
// IMPORTANT: callers must configure trust. See "Card authentication" below.
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:         session.SCP11b,
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})

// SCP11a — mutual authentication with certificates
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:        session.SCP11a,
    KeyID:          0x11,
    OCEPrivateKey:  myECDSAKey,
    OCECertificate: myCert, // must correspond to OCEPrivateKey
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})
```

### Card authentication

`session.Open` fails closed unless one of these is set:

- `CardTrustPolicy` — preferred; full chain validation through the `trust` package, with P-256 enforcement and optional serial/SKI/EKU constraints.
- `CardTrustAnchors` — full X.509 chain validation against a `*x509.CertPool`. Intermediates from the card's BF21 certificate store are picked up automatically.
- `InsecureSkipCardAuthentication` — escape hatch for tests and labs only. Without it, `session.Open` against a card that returns a self-signed or proprietary key is rejected before any ECDH.

This is intentional: an SCP11b session against an unauthenticated card is not authenticated key agreement — it is opportunistic encryption against whoever answered the SELECT. Treat the difference as load-bearing.

GP-proprietary SCP11 certificates are *parsed* but not chain-validated. Cards that return GP-proprietary certs only authenticate when paired with `InsecureSkipCardAuthentication = true`, or when `CardTrustPolicy` is configured with a custom validator that handles them.

### Applet selection

`session.Open` SELECTs `cfg.SelectAID` before the handshake. The applet at that AID is the one whose SCP key set the handshake authenticates against. On YubiKey, different applets hold different SCP key sets:

- **Issuer Security Domain** — for Security Domain management. Default in `DefaultConfig()`.
- **PIV** — for PIV provisioning operations.
- **OATH, OTP, etc.** — applet-specific.

```go
// SCP11b against the PIV applet. This opens an authenticated, encrypted
// channel to PIV — but PIV provisioning operations (key generation,
// certificate writes, etc.) additionally require PIV management-key
// authentication, which is a multi-step GENERAL AUTHENTICATE
// challenge-response not provided by this library. The caller drives
// that themselves through the channel.
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:         session.SCP11b,
    SelectAID:       session.AIDPIV, // PIV holds its own SCP11 key set on YubiKey
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})
```

If `cfg.SelectAID` is `nil`, no SELECT is sent — useful when the caller has already SELECTed the target applet through some other path (a test harness, an applet-aware transport, manual setup).

`cfg.ApplicationAID` is a separate optional field that SELECTs a *second* applet through the secure channel after the handshake. Default is `nil`. On YubiKey this is a footgun — selecting a different applet through the channel terminates the SCP session. Set `SelectAID` to your target applet instead and leave `ApplicationAID` at `nil`. The field exists for non-YubiKey hardware that supports cross-applet SCP.

### Variant and curve support

This implementation targets YubiKey 5.x and similar P-256/AES-128 hardware. The supported profile is:

- SCP11a, SCP11b, SCP11c
- NIST P-256 only
- AES-128 session keys only
- Full security level (`C-MAC | C-DEC | R-MAC | R-ENC`) only

GP Amendment F also defines P-384, Brainpool P-256, AES-192/256, and partial security levels for SCP11. Those are out of scope for the SCP11 implementation here. SCP03 supports AES-128/192/256 in S8 and S16 modes; all six combinations are validated against external Samsung OpenSCP transcript vectors.

### SCP11a/c key/certificate consistency

For mutual-auth variants, `Open` verifies that `OCEPrivateKey` corresponds to `OCECertificate` before sending anything to the card. A mismatch is rejected immediately rather than discovered in the second ECDH.

## Implementing a Transport

The `transport.Transport` interface is the integration point for connecting to hardware:

```go
type Transport interface {
    Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
    TransmitRaw(ctx context.Context, raw []byte) ([]byte, error)
    Close() error
}
```

Both `scp03.Open` and `session.Open` accept any `Transport`. Whether it's a local PC/SC reader, a remote gRPC relay, or a mock card, the protocol code is identical.

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

## Specification Compliance

| Spec | Coverage |
|---|---|
| GP Card Spec v2.3.1 §11 | Security Domain APDU commands: PUT KEY, DELETE, STORE DATA, GET DATA |
| GP Amendment D (SCP03) v1.2 | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, session key derivation, secure messaging, S8 and S16 modes |
| GP Amendment F (SCP11) v1.3 | SCP11a, SCP11b, SCP11c; ECKA; X9.63 KDF; receipt verification |
| GP Card Spec v2.3 §10.8 | Secure messaging: C-MAC, C-ENC, R-MAC, R-ENC |
| NIST SP 800-108 | KDF in counter mode with AES-CMAC |
| NIST SP 800-38B | AES-CMAC |
| BSI TR-03111 | ECDH with zero-point validation |

## Known divergences from Yubico's implementation

These are wire-level differences vs Yubico's `yubikit` (Python) and `yubikit-android` (Java) reference implementations, surfaced by cross-referencing both. They are tracked for a follow-up alignment branch:

- **SCP11b receipt verification.** Yubico's `scp11_init` unpacks and verifies a receipt (TLV `0x86`) for *all* SCP11 variants including SCP11b, and seeds the MAC chain with the receipt. This implementation only verifies receipts for SCP11a/c; SCP11b leaves the MAC chain at zeros. If YubiKey's SCP11b returns a receipt and expects MAC chain = receipt, our SCP11b will not interoperate. To be confirmed against hardware or a yubikit byte trace.
- **Empty-data C-ENC behavior.** When C-DECRYPTION is active and the command data is empty, this implementation skips encryption (matching a literal reading of GP §6.2.4). Yubico's `ScpState.encrypt` instead pads empty data with `0x80 || 0x00*15` and encrypts a single block. The two interpretations diverge silently and one of them will fail against any given card; resolving this needs profile-specific behavior (or hardware confirmation).
- **SCP11a/c PSO P1/P2 layout.** This implementation sends PERFORM SECURITY OPERATION with `P1=0x00, P2=0x00` (with P1 high-bit set for chained chunks). Yubico sends `P1=oce_ref.kvn, P2=oce_ref.kid | 0x80` for intermediate certs, with the chain bit cleared on the final cert. Only the latter matches GP §7.5.2. Out-of-the-box SCP11a/c against real YubiKeys will likely fail until this is fixed.

These items are scoped to a focused follow-up branch using Yubico's open-source yubikit code as the reference, with Samsung OpenSCP transcripts validating the cryptographic core.

## License

Apache 2.0

## Related Implementations

- [Yubico/Yubico.NET.SDK](https://github.com/Yubico/Yubico.NET.SDK) (Apache 2.0) — Reference .NET SDK with SecurityDomainSession. Source of our cross-implementation test vectors.
- [Yubico/yubikey-manager](https://github.com/Yubico/yubikey-manager) (BSD 2-clause) — Python `yubikit.securitydomain` and SCP core. Source of OCE certificate test fixtures.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — Full SCP03 + SCP11 in Java. Source of SCP11 reference test vectors.
- [skythen/scp03](https://github.com/skythen/scp03) — Pure Go SCP03. Similar `Transmitter` interface pattern.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI. SCP01/02/03.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Card-side and host-side SCP11b in Java.
