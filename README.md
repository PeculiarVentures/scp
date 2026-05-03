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
| `piv` | PIV (NIST SP 800-73) command builders |
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
    Keys:              scp03.DefaultKeys,  // TESTING ONLY
    KeyVersion:        0x01,
    SecurityDomainAID: session.AIDSecurityDomain,
    ApplicationAID:    session.AIDPIV,
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

`session.Open` SELECTs `cfg.SecurityDomainAID` before the handshake — that's the AID that holds the SCP11 keys you want to authenticate against. On YubiKey, different applets hold different SCP11 key sets:

- **Issuer Security Domain** — for Security Domain management (the default, `session.AIDSecurityDomain`).
- **PIV** — for PIV provisioning operations. Set `cfg.SecurityDomainAID = session.AIDPIV`.

```go
// Open SCP11b against the PIV applet for PIV provisioning over SCP.
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:           session.SCP11b,
    SecurityDomainAID: session.AIDPIV, // PIV holds its own SCP11 key set on YubiKey
    CardTrustPolicy:   &trust.Policy{Roots: rootPool},
})
```

`DefaultConfig().ApplicationAID` is intentionally `nil`: a YubiKey SCP session is scoped to the SELECTed applet, so reselecting a different applet through the channel terminates the session. If you need to address two applets, open two sessions.

`SecurityDomainAID` is not the cleanest name for "the AID where the SCP keys live" (it predates first-class non-SD usage). Treat it as that pragmatic meaning until the API gets refactored.

### Variant and curve support

This implementation targets YubiKey 5.x and similar P-256/AES-128 hardware. The supported profile is:

- SCP11a, SCP11b, SCP11c
- NIST P-256 only
- AES-128 session keys only
- Full security level (`C-MAC | C-DEC | R-MAC | R-ENC`) only

GP Amendment F also defines P-384, Brainpool P-256, AES-192/256, and partial security levels. Those are out of scope for this implementation. SCP03 supports AES-128/192/256 in S8 and S16 modes, but only AES-128 is covered by the imported transcript vectors.

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
- **Samsung OpenSCP-Java AES-128, S8 and S16 modes** — full SCP03 transcripts including the EXTERNAL AUTHENTICATE wrapping.
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

## License

Apache 2.0

## Related Implementations

- [Yubico/Yubico.NET.SDK](https://github.com/Yubico/Yubico.NET.SDK) (Apache 2.0) — Reference .NET SDK with SecurityDomainSession. Source of our cross-implementation test vectors.
- [Yubico/yubikey-manager](https://github.com/Yubico/yubikey-manager) (BSD 2-clause) — Python `yubikit.securitydomain` and SCP core. Source of OCE certificate test fixtures.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — Full SCP03 + SCP11 in Java. Source of SCP11 reference test vectors.
- [skythen/scp03](https://github.com/skythen/scp03) — Pure Go SCP03. Similar `Transmitter` interface pattern.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI. SCP01/02/03.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Card-side and host-side SCP11b in Java.
