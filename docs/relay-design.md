# SCP11 Relay Architecture for Remote Smart Card Provisioning

## Problem

SCP11b and SCP11c require a live ECDH key agreement with the physical card. The card generates an ephemeral keypair during INTERNAL AUTHENTICATE, so the server cannot pre-compute encrypted APDUs. This rules out the existing job queue model (which works for SCP03's symmetric pre-shared keys) for the actual crypto handshake.

The solution is a real-time APDU relay: the server drives the SCP11 handshake and provisioning commands through a bidirectional stream to the client, which forwards them to the card via PC/SC.

## Architecture

```
┌──────────────────┐                           ┌──────────────────┐
│  goodkey-app     │   Job Queue (existing)     │  GoodKey Server  │
│  (PC/SC watcher  │◄── card ready signal ─────│  (SCP library    │
│   + relay agent) │                            │   + policy)      │
│                  │◄══ gRPC bidi stream ═══════╡                  │
└───────┬──────────┘   (APDU relay, mTLS)       └──────────────────┘
        │ PC/SC
   ┌────┴─────┐
   │  YubiKey  │
   └──────────┘
```

**Phase 1 — Signal:** The goodkey-app PCSC watcher detects a card, reads its ATR and serial. The existing `StartRunSmartCardJob` IPC triggers the flow.

**Phase 2 — Connect:** The server opens a gRPC stream to the client (or the client initiates it as part of the job).

**Phase 3 — Handshake:** The server calls `session.Open()` from the SCP library. The library sends SELECT, GET DATA, and INTERNAL AUTHENTICATE through the transport, which relays them to the card.

**Phase 4 — Provision:** The server sends PIV commands via `session.Transmit()`. Each command is automatically encrypted and MACed by the library before hitting the relay.

**Phase 5 — Teardown:** Session closes, result reported via `UpdateSCTask`.

## Integration with goodkey-app

The goodkey-app already has the client-side infrastructure:

- **`pcsc.Backend`** — manages `scard.Context`, provides `CardHandle` with `Transmit(ctx, apdu []byte) ([]byte, error)`
- **`pcsc.Provider`** — watches for card insertion, caches card state, emits events
- **`smartcard.CardManager`** — matches cards to products, manages lifecycle
- **Job/Task model** — `SCJobResponse` / `SCJobTaskResponse` with status tracking via `GetSCJobs` / `UpdateSCTask`

The SCP library's `transport.Transport` interface maps directly to the existing `pcsc.CardHandle`:

```go
// Adapter: pcsc.CardHandle → transport.Transport
type PCSCTransport struct {
    handle pcsc.CardHandle
}

func (t *PCSCTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
    raw, err := cmd.Encode()
    if err != nil {
        return nil, err
    }
    resp, err := t.handle.Transmit(ctx, raw)
    if err != nil {
        return nil, err
    }
    return apdu.ParseResponse(resp)
}

func (t *PCSCTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
    return t.handle.Transmit(ctx, raw)
}

func (t *PCSCTransport) Close() error {
    return t.handle.Disconnect()
}
```

## gRPC Relay Transport

For remote provisioning, the gRPC stream itself is the transport. The server wraps it so the SCP library sees a standard `Transport`:

```go
type GRPCTransport struct {
    stream pb.CardRelay_RelaySessionClient
}

func (t *GRPCTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
    raw, err := cmd.Encode()
    if err != nil {
        return nil, err
    }
    if err := t.stream.Send(&pb.ServerMessage{
        Payload: &pb.ServerMessage_Apdu{Apdu: raw},
    }); err != nil {
        return nil, err
    }
    msg, err := t.stream.Recv()
    if err != nil {
        return nil, err
    }
    switch p := msg.Payload.(type) {
    case *pb.ClientMessage_Response:
        return apdu.ParseResponse(p.Response)
    case *pb.ClientMessage_CardError:
        return nil, fmt.Errorf("card error: %s", p.CardError.Description)
    default:
        return nil, errors.New("unexpected message type")
    }
}

func (t *GRPCTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
    return t.handle.Transmit(ctx, raw) // delegate to Transmit
}

func (t *GRPCTransport) Close() error { return nil }
```

## Server-Side Provisioning

The server code is straightforward once the transport is wired:

```go
func (s *ProvisioningServer) HandleJob(
    ctx context.Context,
    cardSerial string,
    stream pb.CardRelay_RelaySessionClient,
) error {
    transport := &GRPCTransport{stream: stream}

    // The SCP library handles the entire handshake:
    // SELECT SD → GET DATA → ECDH → key derivation → SELECT PIV
    sess, err := session.Open(ctx, transport, &session.Config{
        Variant:           session.SCP11b,
        SecurityDomainAID: session.AIDSecurityDomain,
        ApplicationAID:    session.AIDPIV,
        KeyID:             0x13,
        KeyVersion:        0x01,
        CardTrustAnchors:  s.cardTrustAnchor,
    })
    if err != nil {
        return fmt.Errorf("SCP11 handshake: %w", err)
    }
    defer sess.Close()

    // All commands are now encrypted + MACed automatically.
    // Generate a key in PIV slot 9A:
    resp, err := sess.Transmit(ctx, &apdu.Command{
        CLA: 0x00, INS: 0x47, P1: 0x00, P2: 0x9A,
        Data: []byte{0xAC, 0x03, 0x80, 0x01, 0x11}, // EC P-256
    })
    if err != nil {
        return err
    }
    if !resp.IsSuccess() {
        return fmt.Errorf("generate key: SW=%04X", resp.StatusWord())
    }

    // Inject a large post-quantum certificate using extended length encoding.
    // A single APDU instead of ~20 chained round trips over the relay.
    resp, err = sess.Transmit(ctx, &apdu.Command{
        CLA:            0x00,
        INS:            0xDB,
        P1:             0x3F,
        P2:             0xFF,
        Data:           buildPutDataPayload(pqCertDER), // ~5KB ML-DSA cert
        ExtendedLength: true,
    })
    // ...

    return nil
}
```

## Client-Side Relay Agent

The client side is minimal — it relays bytes without any cryptographic knowledge. In the goodkey-app context, this would be implemented as a handler that runs within the existing `StartRunSmartCardJob` flow:

```go
func (h *RelayHandler) ExecuteTask(
    ctx context.Context,
    card pcsc.CardHandle,
    stream pb.CardRelay_RelaySessionServer,
) error {
    for {
        msg, err := stream.Recv()
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }

        switch p := msg.Payload.(type) {
        case *pb.ServerMessage_Apdu:
            resp, err := card.Transmit(ctx, p.Apdu)
            if err != nil {
                stream.Send(&pb.ClientMessage{
                    Payload: &pb.ClientMessage_CardError{
                        CardError: &pb.CardError{Description: err.Error()},
                    },
                })
                return err
            }
            stream.Send(&pb.ClientMessage{
                Payload: &pb.ClientMessage_Response{Response: resp},
            })

        case *pb.ServerMessage_SessionEnd:
            return nil
        }
    }
}
```

## Protobuf Definitions

```protobuf
syntax = "proto3";
package relay;

service CardRelay {
  rpc RelaySession(stream ServerMessage) returns (stream ClientMessage);
}

message ServerMessage {
  oneof payload {
    bytes      apdu         = 1;
    SessionEnd session_end  = 2;
  }
}

message ClientMessage {
  oneof payload {
    bytes     response   = 1;
    CardError card_error = 2;
  }
}

message SessionEnd {
  bool   success = 1;
  string reason  = 2;
}

message CardError {
  string description = 1;
  bool   recoverable = 2;
}
```

## Security Considerations

### Channel Integrity

The SCP library terminates the session immediately if an R-MAC verification failure occurs during `Transmit()`. All session keys are zeroed before the error is returned to the caller. This prevents MAC oracle attacks where an adversary probes the channel by sending crafted responses and observing whether the session continues.

### Transport Security (mTLS)

The gRPC relay stream must use mutual TLS (mTLS) with client certificates. While SCP11 encrypts the APDU payloads end-to-end (server ↔ card), an attacker on the relay stream cannot read the data but can:

- Drop APDUs to force session teardown
- Reorder APDUs to desynchronize MAC chaining (causes session termination)
- Inject garbage APDUs to trigger repeated handshake failures

mTLS prevents all three by authenticating both endpoints of the relay.

### Rate Limiting on Job Queue

The ECDH key agreement is computationally expensive compared to SCP03's symmetric handshake. A compromised client or malicious actor flooding the job queue with `CardReadyEvent` payloads could exhaust server resources (CPU for P-256 ECDH, HSM capacity for key operations).

Mitigations:
- Rate limit the queue consumer per `client_id` (e.g., max 5 concurrent sessions per client)
- Enforce an aggressive timeout on the initial handshake phase (e.g., 10 seconds from stream open to `session.Open()` completion)
- Validate the card serial against the organization's registered inventory before starting the ECDH handshake

### Key Material in Memory

The SCP library zeroes all session keys on `Close()` using `go:noinline` pragmas to prevent the compiler from optimizing away the zeroing. Intermediate ECDH shared secrets are zeroed immediately after key derivation. Pre-allocated buffers avoid `append` reallocations that would leave ghost copies in the GC heap.

Go's garbage collector can still create copies of byte slices during compaction. For the server side, restrict memory dumps and core dumps on the provisioning container. For defense in depth, the server's OCE static key should live in an HSM (PKCS#11 or cloud KMS) rather than in process memory.

## Extended Length APDUs

The SCP library supports ISO 7816-4 extended length encoding, where Lc is encoded as 3 bytes (0x00 || high || low), allowing payloads up to 65,535 bytes in a single APDU.

This matters for post-quantum certificates. A Dilithium/ML-DSA-65 certificate is roughly 4-5KB (signature ~3,300 bytes + public key ~1,952 bytes). Composite certificates (ML-DSA + ECDSA) can exceed 6KB.

| Certificate type | Size | Short encoding (chained) | Extended encoding |
|---|---|---|---|
| ECDSA P-256 | ~500 bytes | 2 APDUs | 1 APDU |
| RSA-2048 | ~1.2KB | 5 APDUs | 1 APDU |
| ML-DSA-65 | ~5KB | 20 APDUs | 1 APDU |
| Composite (ML-DSA + ECDSA) | ~6KB | 24 APDUs | 1 APDU |

Over a relay with 50ms per round trip, a 5KB certificate via chaining takes ~1 second. Extended length does it in one round trip.

To use extended length:

```go
sess.Transmit(ctx, &apdu.Command{
    CLA: 0x00, INS: 0xDB, P1: 0x3F, P2: 0xFF,
    Data:           largeCertPayload,
    ExtendedLength: true,             // Use 3-byte Lc encoding
})
```

The library's secure messaging layer (`channel.Wrap`) auto-promotes to extended length when the encrypted + MACed payload exceeds 255 bytes. YubiKey 5 series firmware 5.7+ supports extended length over CCID.

For transports that do not support extended length, command chaining (`apdu.ChainCommands`) is still available as a fallback.

## Hardware Quirks

### PC/SC Timeouts on Key Generation

RSA key generation on a YubiKey can take several seconds (RSA 2048 is typically 5-15s). If the gRPC relay adds network latency on top of this, the PC/SC layer on the client may time out before the card responds.

Mitigations:
- The `pcsc.CardHandle.Transmit` in the goodkey-app should use a generous timeout for key generation commands
- The gRPC stream should have per-RPC deadlines set via `context.WithTimeout`, not a single stream-level deadline
- Consider implementing an application-level keepalive on the gRPC stream for operations expected to exceed 5 seconds

### ATR Matching

YubiKey ATRs vary by firmware version and enabled USB interfaces (FIDO, CCID, OTP). The goodkey-app's `pcsc.Provider` should use ATR masking (matching on historical bytes) rather than exact string comparison to avoid brittle deployments when firmware is updated.

### SCP11b vs SCP11a Selection

SCP11b provides one-way authentication (card authenticates to server). For environments where the card must also verify the server's identity, use SCP11a with an OCE certificate:

```go
sess, err := session.Open(ctx, transport, &session.Config{
    Variant:        session.SCP11a,
    KeyID:          0x11,
    OCEPrivateKey:  oceKey,       // Server's static ECDSA key (from HSM)
    OCECertificate: oceCert,      // Server's certificate
    CardTrustAnchors: cardRoots,  // Trust anchors for card cert validation
})
```

## SCP Library Reference

The SCP library (`github.com/PeculiarVentures/scp`) provides both SCP03 and SCP11 through a unified `scp.Session` interface:

```go
// SCP11b — asymmetric (ECDH)
sess, err := session.Open(ctx, transport, session.DefaultConfig())

// SCP03 — symmetric (pre-shared keys)
sess, err := scp03.Open(ctx, transport, &scp03.Config{Keys: myKeys})

// Both return scp.Session — identical Transmit API
resp, err := sess.Transmit(ctx, myCommand)
```

The library includes mock cards for both protocols (`mockcard.New()` for SCP11, `scp03.NewMockCard()` for SCP03) that perform real cryptography on the card side. This enables end-to-end testing of the relay without hardware:

```go
card, _ := mockcard.New()
sess, _ := session.Open(ctx, card.Transport(), session.DefaultConfig())
// Full handshake + encrypted commands work against the mock
```

## Implementation Order

1. **PC/SC adapter** — wrap `pcsc.CardHandle` as `transport.Transport` (shown above). Verify `session.Open()` works against a local YubiKey 5.7+.
2. **gRPC relay** — implement the protobuf service with mTLS. Test by running `session.Open()` through the relay against the mock card on the other end.
3. **Job integration** — connect to the existing `StartRunSmartCardJob` flow. The relay handler becomes a new handler type registered in the `handlers.Registry`.
4. **Server provisioning logic** — build the provisioning plan from the job/task model, execute via `sess.Transmit()`. Use `ExtendedLength: true` for certificate injection.
5. **Rate limiting + timeouts** — add per-client rate limits on the queue consumer and per-operation timeouts on the gRPC stream.
