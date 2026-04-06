# scp

A Go implementation of GlobalPlatform Secure Channel Protocols for establishing authenticated and encrypted communication with smart cards, plus a typed Security Domain management layer for key lifecycle, certificate provisioning, and trust validation.

Two protocols are supported through a unified API:

- **SCP03** (Amendment D) — Symmetric key protocol using pre-shared AES keys
- **SCP11** (Amendment F) — Asymmetric protocol using ECDH key agreement and X.509 certificates, with variants SCP11a, SCP11b, and SCP11c

Both protocols produce a `scp.Session` with the same `Transmit` method. The consumer writes protocol-agnostic code after the initial `Open` call.

## Quick Start

```go
// SCP03 — symmetric keys
sess, _ := scp03.Open(ctx, transport, &scp03.Config{
    Keys: scp03.StaticKeys{ENC: encKey, MAC: macKey, DEK: dekKey},
})

// SCP11b — ECDH key agreement
sess, _ := session.Open(ctx, transport, session.DefaultConfig())

// Both return scp.Session — same API from here on
resp, _ := sess.Transmit(ctx, myCommand)
sess.Close()
```

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
// SCP11b — card authenticates to host (simplest)
sess, err := session.Open(ctx, transport, session.DefaultConfig())

// SCP11a — mutual authentication with certificates
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:        session.SCP11a,
    KeyID:          0x11,
    OCEPrivateKey:  myECDSAKey,
    OCECertificate: myCert,
})

// SCP11b with trust validation
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:         session.SCP11b,
    CardTrustPolicy: &trust.Policy{Roots: rootPool},
})
```

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

The test suite includes 118 tests covering:

- **SCP03 end-to-end:** Handshake, encrypted echo, multi-command MAC chain, wrong-key rejection, empty payload counter sync
- **SCP11 end-to-end:** SCP11b (no receipt), SCP11a (with receipt + cert chaining), PIV key generation, counter sync
- **Reference vector tests:** Byte-exact verification against published SCP11 test vectors
- **YubiKey compatibility tests:** APDU byte layout verification against YubiKey 5.7+ expectations
- **Cross-implementation vectors:** SCP03 KDF, channel MAC, and RMAC vectors from the Yubico .NET SDK
- **Security Domain management:** APDU construction, TLV parsing, KCV computation, DEK requirements, reset lockout dispatch
- **Trust validation:** Chain building, fail-closed behavior, serial allowlists, SKI matching, real Yubico OCE certificate chain

## Specification Compliance

| Spec | Coverage |
|---|---|
| GP Card Spec v2.3.1 §11 | Security Domain APDU commands: PUT KEY, DELETE, STORE DATA, GET DATA |
| GP Amendment D (SCP03) v1.2 | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, session key derivation, secure messaging |
| GP Amendment F (SCP11) v1.3 | All three variants (a/b/c), ECKA, X9.63 KDF, receipt verification, S8 and S16 modes |
| GP Card Spec v2.3 §10.8 | Secure messaging: C-MAC, C-ENC, R-MAC, R-ENC (shared by both protocols) |
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
