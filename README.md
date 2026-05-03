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

- `CardTrustPolicy` — preferred; full chain validation through the `trust` package, with P-256 enforcement and optional serial/SKI constraints.
- `CardTrustAnchors` — minimal X.509 chain validation against a `*x509.CertPool`.
- `InsecureSkipCardAuthentication` — escape hatch for tests and labs only. Without it, `session.Open` against a card that returns a self-signed or proprietary key is rejected before any ECDH.

This is intentional: an SCP11b session against an unauthenticated card is not authenticated key agreement — it is opportunistic encryption against whoever answered the SELECT. Treat the difference as load-bearing.

### Applet selection

`DefaultConfig().ApplicationAID` is `nil`. SCP sessions on YubiKey are scoped to the currently selected applet, and selecting another applet terminates the session. The supported pattern is:

```go
// Caller selects the applet first, then opens SCP against it.
_, err := transport.Transmit(ctx, apdu.NewSelect(session.AIDPIV))
// ...check resp...
sess, err := session.Open(ctx, transport, cfg)
```

If you need to address two applets, open two sessions.

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

The test suite includes 135 tests covering:

- **SCP03 end-to-end:** Handshake, encrypted echo, multi-command MAC chain, wrong-key rejection, empty payload counter sync
- **SCP03 transcript vectors:** Byte-exact known-answer tests against GlobalPlatformPro JCOP4 (MAC-only) and Samsung OpenSCP-Java AES-128 in both S8 and S16 modes — these distinguish a correct EXTERNAL AUTHENTICATE wrap from one that encrypts the host cryptogram, and exercise the full S16 code path
- **SCP11 end-to-end:** SCP11b (no receipt), SCP11a (with receipt + cert chaining), PIV key generation, counter sync
- **SCP11 fail-closed regressions:** Reject card cert when no trust anchors and no opt-in; reject OCE private/certificate mismatches
- **Reference vector tests:** Byte-exact verification against published SCP11 test vectors
- **YubiKey compatibility tests:** APDU byte layout verification against YubiKey 5.7+ expectations
- **Cross-implementation vectors:** SCP03 KDF, channel MAC, and RMAC vectors from the Yubico .NET SDK
- **Security Domain management:** APDU construction, TLV parsing, KCV computation, DEK requirements (including all-zero rejection), STORE DATA application-level chaining (single block, multi-block fragmentation, ISO chaining rejection), reset lockout dispatch
- **Trust validation:** Chain building, fail-closed behavior, serial allowlists, SKI matching, real Yubico OCE certificate chain
- **Resource limits:** GET RESPONSE iteration and byte caps; BER-TLV decoder depth, node-count, and size bounds

## Specification Compliance

| Spec | Coverage |
|---|---|
| GP Card Spec v2.3.1 §11 | Security Domain APDU commands: PUT KEY, DELETE, STORE DATA (with §11.11 application-level chaining), GET DATA |
| GP Amendment D (SCP03) v1.2 | INITIALIZE UPDATE, EXTERNAL AUTHENTICATE (MAC-only, never C-ENC), session key derivation, secure messaging, S8 and S16 modes |
| GP Amendment F (SCP11) v1.3 | All three variants (a/b/c), ECKA, X9.63 KDF, receipt verification, fail-closed card authentication |
| GP Card Spec v2.3 §10.8 | Secure messaging: C-MAC, C-ENC, R-MAC, R-ENC (R-MAC verified on every response when negotiated, including errors) |
| NIST SP 800-108 | KDF in counter mode with AES-CMAC |
| NIST SP 800-38B | AES-CMAC |
| BSI TR-03111 | ECDH with zero-point validation |

## Conformance and hardening

Beyond the mock card, the test suite includes independent transcript vectors so the implementation is validated against external references:

- **GlobalPlatformPro JCOP4** — real-card SCP03 INITIALIZE UPDATE and EXTERNAL AUTHENTICATE dump with default keys.
- **Samsung OpenSCP-Java AES-128/S8** — full SCP03 transcript including the EXTERNAL AUTHENTICATE wrapping that distinguishes MAC-only from MAC-and-encrypt.
- **Samsung OpenSCP-Java AES-128/S16** — same in S16 mode (16-byte challenges, 16-byte cryptograms, 16-byte MACs).

These are byte-exact known-answer tests using a recording transport; they cannot pass against a mock card that mirrors the implementation's own behavior.

Hardening invariants enforced by the code and verified by tests:

- SCP03 EXTERNAL AUTHENTICATE is C-MACed but never C-ENC encrypted, regardless of the negotiated post-authentication security level.
- SCP03 supports both S8 (8-byte) and S16 (16-byte) modes, dispatched by the `i` parameter of INITIALIZE UPDATE.
- R-MAC is verified on every response under R-MAC-negotiated channels — including status-only and error responses.
- Secure-messaging C-MAC is computed over the same Lc encoding (1-byte short or 3-byte extended) that goes on the wire.
- SCP11 fails closed without `CardTrustPolicy`, `CardTrustAnchors`, or `InsecureSkipCardAuthentication`.
- SCP11a/c require both `OCEPrivateKey` and `OCECertificate`, and verify they correspond to each other before contact with the card.
- SCP11 `DefaultConfig` does not auto-SELECT a target applet (YubiKey scopes SCP to the selected applet).
- Security Domain refuses to use an all-zero session DEK.
- `STORE DATA` payloads above one APDU use GP §11.11 application-level chaining (sequential P2, last-block bit), not ISO 7816 CLA-bit chaining.
- `GET RESPONSE` collection is bounded by both iteration count and accumulated byte count.
- BER-TLV decoding is bounded by depth, node count, and total input size; resource-limit errors propagate rather than being absorbed by opaque-payload tolerance.

## License

Apache 2.0

## Related Implementations

- [Yubico/Yubico.NET.SDK](https://github.com/Yubico/Yubico.NET.SDK) (Apache 2.0) — Reference .NET SDK with SecurityDomainSession. Source of our cross-implementation test vectors.
- [Yubico/yubikey-manager](https://github.com/Yubico/yubikey-manager) (BSD 2-clause) — Python `yubikit.securitydomain` and SCP core. Source of OCE certificate test fixtures.
- [Samsung/OpenSCP-Java](https://github.com/Samsung/OpenSCP-Java) (Apache 2.0) — Full SCP03 + SCP11 in Java. Source of SCP11 reference test vectors.
- [skythen/scp03](https://github.com/skythen/scp03) — Pure Go SCP03. Similar `Transmitter` interface pattern.
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — Java library and CLI. SCP01/02/03.
- [ThothTrust/SCP11B](https://github.com/ThothTrustCom/SCP11B) (BSD-3) — Card-side and host-side SCP11b in Java.
