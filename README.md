# scp

A Go implementation of GlobalPlatform Secure Channel Protocols for establishing authenticated and encrypted communication with smart cards.

Two protocols are supported through a unified API:

- **SCP03** (Amendment D) — Symmetric key protocol using pre-shared AES keys
- **SCP11** (Amendment F) — Asymmetric protocol using ECDH key agreement and X.509 certificates, with variants SCP11a, SCP11b, and SCP11c

Both protocols produce a `scp.Session` with the same `Transmit` method. The consumer writes protocol-agnostic code after the initial `Open` call.

## Quick Start

```go
import (
    scp "github.com/PeculiarVentures/scp"
    "github.com/PeculiarVentures/scp/scp03"
    "github.com/PeculiarVentures/scp/session"  // SCP11
)

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

Run the included example: `go run ./cmd/example`

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Your Application                │
├────────────────────┬────────────────────────────┤
│  scp03.Open()      │  session.Open() (SCP11)    │
├────────────────────┴────────────────────────────┤
│  scp.Session (common interface)                  │
│  ┌──────────────────────────────────────────┐    │
│  │   channel (secure messaging)             │    │
│  │   AES-CBC encrypt, AES-CMAC, MAC chain   │    │
│  └──────────────────────────────────────────┘    │
│  ┌────────┐  ┌────────┐  ┌─────┐  ┌────┐        │
│  │  kdf   │  │  cmac  │  │ tlv │  │apdu│        │
│  └────────┘  └────────┘  └─────┘  └────┘        │
├──────────────────────────────────────────────────┤
│              transport.Transport                  │
│  (PC/SC, NFC, gRPC relay, mock card, ...)        │
└──────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `scp` | Common `Session` interface implemented by both protocols |
| `scp03` | SCP03 handshake: INITIALIZE UPDATE + EXTERNAL AUTHENTICATE |
| `session` | SCP11 handshake: ECDH key agreement (variants a/b/c) |
| `channel` | Secure messaging shared by both protocols (encrypt, MAC, verify) |
| `kdf` | Key derivation: X9.63 KDF, NIST SP 800-108 |
| `cmac` | AES-CMAC per NIST SP 800-38B |
| `tlv` | BER-TLV encoding/decoding for GP data structures |
| `apdu` | ISO 7816-4 command/response APDU types |
| `transport` | Transport interface and helpers |
| `piv` | PIV (NIST SP 800-73) command builders |
| `mockcard` | Simulated SCP11 Security Domain for testing |

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

// SCP11c — mutual auth with offline scripting
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:  session.SCP11c,
    KeyID:    0x15,
    // ...
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

The test suite includes 46 tests covering:

- **SCP03 end-to-end:** Handshake, encrypted echo, 10-command MAC chain, wrong-key rejection, empty payload counter sync
- **SCP11 end-to-end:** SCP11b (no receipt), SCP11a (with receipt + cert chaining), PIV key generation, counter sync
- **Reference vector tests:** Byte-exact verification against published SCP11 test vectors
- **YubiKey compatibility tests:** APDU byte layout verification against YubiKey 5.7+ expectations

## Specification Compliance

| Spec | Coverage |
|---|---|
| GP Amendment D (SCP03) v1.2 | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, session key derivation, secure messaging |
| GP Amendment F (SCP11) v1.3 | All three variants (a/b/c), ECKA, X9.63 KDF, receipt verification, S8 and S16 modes |
| GP Card Spec v2.3 §10.8 | Secure messaging: C-MAC, C-ENC, R-MAC, R-ENC (shared by both protocols) |
| NIST SP 800-108 | KDF in counter mode with AES-CMAC |
| NIST SP 800-38B | AES-CMAC |
| BSI TR-03111 | ECDH with zero-point validation |

## License

Apache 2.0

## Related Implementations

- [skythen/scp03](https://github.com/skythen/scp03) — Pure Go SCP03. Similar `Transmitter` interface pattern.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — Full SCP03 + SCP11 in Java. Source of reference test vectors.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI. SCP01/02/03.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Card-side and host-side SCP11b in Java.
- [kaoh/globalplatform](https://github.com/kaoh/globalplatform) — C library and GPShell CLI. SCP01/02/03.
- [Samsung/OpenSCP-Python](https://github.com/Samsung/OpenSCP-Python) — Python wrapper around OpenSCP-Java.
