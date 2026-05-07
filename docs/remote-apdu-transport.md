# Remote APDU Transport

This document describes how the SCP library is intended to be used in
deployments where the smart card is physically attached to one machine
(an *endpoint agent*) and the SCP protocol is driven from another
(a *server-side controller*). It is a deployment guide, not an API
specification: the library does not implement, mandate, or know
anything about the wire protocol between the two sides. It exposes
[`transport.Transport`][transport-godoc] as the integration boundary
and lets the caller decide what it wraps.

[transport-godoc]: https://pkg.go.dev/github.com/PeculiarVentures/scp/transport

## Why this pattern matters for SCP11

SCP03 is symmetric: whichever side runs the protocol must hold the
static AES keys. There is no way to split SCP03 such that one side
holds the keys and another forwards traffic. SCP03 belongs near the
key custodian.

SCP11 is asymmetric. The Off-Card Entity (OCE) holds an EC private
key; nothing about the protocol requires the OCE to be co-located
with the card. A relay-style deployment where:

* the **server-side controller** holds the OCE private key, the trust
  policy, and the SCP11 protocol state, and
* the **endpoint agent** holds only physical access to the card and
  forwards APDUs

is a natural fit for SCP11 specifically. The endpoint never sees the
OCE private key, the SCP11 ECDH shared secret, the derived session
keys, the receipt verification state, or the SCP11-derived DEK. A
compromised endpoint can refuse to forward, replay traffic to a
detectable extent (see "Transport requirements" below), or attempt to
present a different card — but it cannot sign as the OCE, decrypt past
SCP11 traffic, or fabricate authenticated PUT KEY commands.

## Architecture

```text
┌────────────────────────────────────────┐
│  Server-side controller                │
│                                        │
│  • Authorization / policy              │
│  • Card trust validation               │
│  • OCE private key + cert chain        │
│  • scp11.Open(ctx, T, cfg)           │
│  • securitydomain.OpenSCP11(...)       │
│  • Audit / evidence                    │
│                  │                     │
│                  ▼                     │
│            transport.Transport (T)     │
│                  │                     │
└──────────────────┼─────────────────────┘
                   │  ↑↓ APDU bytes
                   │     (over your bus:
                   │      gRPC stream, message queue,
                   │      WebSocket, mTLS tunnel, etc.)
                   ▼
┌────────────────────────────────────────┐
│  Endpoint agent                        │
│                                        │
│  • Receives raw APDU bytes             │
│  • Calls local card I/O                │
│      (PC/SC, NFC, USB CCID, ...)       │
│  • Returns raw response bytes          │
│  • Reports card removal / I/O errors   │
│                                        │
│  Holds NO cryptographic material.      │
└──────────────────┬─────────────────────┘
                   │
                   ▼
              Smart card / SE
```

The server's `transport.Transport` implementation is a thin wrapper
over whatever bidirectional bus the deployment uses to talk to the
endpoint. The endpoint's job is reduced to "read APDU bytes from the
bus, write them to the card, send the response back." The library
runs only on the server.

## SCP11 is response-driven

The server cannot precompute a static APDU sequence and ship it to
the endpoint for replay. The card contributes live ephemeral material
during the handshake (specifically: GET DATA returns the card's
ephemeral certificate, then INTERNAL/EXTERNAL AUTHENTICATE drives
ECDH against an ephemeral OCE key). Each APDU after SELECT depends on
the response to the previous one. The relay has to be a real-time
request/response channel; a job-queue model with batched APDUs does
not work for SCP11.

## Server-side wiring

The server opens a session against a `transport.Transport` exactly
the same way it would for a local card — the difference is what
`Transport` wraps. A sketch:

```go
import (
    "github.com/PeculiarVentures/scp/apdu"
    "github.com/PeculiarVentures/scp/securitydomain"
    "github.com/PeculiarVentures/scp/scp11"
    "github.com/PeculiarVentures/scp/transport"
    "github.com/PeculiarVentures/scp/trust"
)

// Your transport, talking to the endpoint over whatever bus you use.
type relayTransport struct {
    stream apduStream // gRPC bidi, NATS request/reply, WebSocket — your choice
}

func (r *relayTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
    raw, err := cmd.Encode()
    if err != nil {
        return nil, err
    }
    respBytes, err := r.stream.Exchange(ctx, raw)
    if err != nil {
        return nil, err
    }
    return apdu.ParseResponse(respBytes)
}

func (r *relayTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
    return r.stream.Exchange(ctx, raw)
}

func (r *relayTransport) Close() error { return r.stream.Close() }

// Drive SCP11b end-to-end against the relay.
func adminAgainstRemoteCard(ctx context.Context, stream apduStream, oceTrustRoots *x509.CertPool) error {
    t := &relayTransport{stream: stream}

    cfg := yubikey.SCP11bConfig()
    cfg.SelectAID = securitydomain.AIDSecurityDomain
    cfg.CardTrustPolicy = &trust.Policy{Roots: oceTrustRoots}

    sd, err := securitydomain.OpenSCP11(ctx, t, cfg)
    if err != nil {
        return fmt.Errorf("SCP11 open: %w", err)
    }
    defer sd.Close()

    // SCP11-derived DEK is plumbed through automatically; PUT KEY,
    // GENERATE EC KEY, etc. work over SCP11a/c sessions.
    // SCP11b is read-only from a card-management standpoint —
    // OCE-gated operations will be rejected at the host-side gate
    // because SCP11b does not authenticate the OCE to the card.
    return nil
}
```

The same code runs whether `stream` is a gRPC bidi against a remote
endpoint or a local in-process channel against a test mock — that's
the point of keeping the library at the `transport.Transport` seam.

## Endpoint responsibilities

The endpoint:

* Accepts APDU bytes from the bus.
* Calls the local card driver (PC/SC `SCardTransmit`, Android
  `IsoDep.transceive`, USB CCID, NFC) once per APDU.
* Returns the raw response bytes back over the bus.
* Reports card-presence changes and I/O errors as out-of-band events.
* Does not parse, classify, log, or interpret the APDU contents.

The endpoint never receives:

* SCP03 static keys (the symmetric model is for caller-near-card use,
  not relay).
* OCE private keys (those stay on the controller).
* SCP11 ephemeral keys, ECDH shared secrets, S-ENC/S-MAC/S-RMAC, the
  receipt chain, or the SCP11-derived DEK.

## Transport requirements

The library does not police the bus between the server and the
endpoint. Implementations of `transport.Transport` that wrap a remote
bus MUST provide the following properties; if they don't, the SCP11
handshake or secure messaging may silently misbehave:

1. **One outstanding APDU at a time.** SCP11 secure messaging is
   strictly request/response with monotonic counters (`encCounter`).
   Pipelining or parallelism breaks the counter contract.

2. **Strict request/response correlation.** If the bus can re-order
   replies, the transport must restore order before returning to the
   library. A response delivered to the wrong request will fail MAC
   verification and tear down the session, but only after the
   damage is done.

3. **Timeout and cancellation.** `Transmit` must respect
   `ctx.Done()`. A hung relay must be observable from the server.

4. **Card removal / I/O error reporting.** A card removed mid-session
   should surface as an error from `Transmit`, not as a hang. The
   library will close and zero session keys on error return.

5. **Duplicate / replayed response rejection.** A bus that replays
   stale responses can mislead the protocol. Sequence numbers,
   request IDs, or a strict request/response invariant on the bus
   protocol are sufficient.

6. **Authenticated, confidential endpoint-to-server transport.**
   APDUs going from server to endpoint after the SCP11 handshake are
   ENC+MAC-protected by the library, but the SELECT, GET DATA, and
   any application-level traffic before the secure channel is open
   are plaintext. The bus itself must provide authentication,
   confidentiality, and integrity (mTLS or equivalent). Treating the
   bus as untrusted invites traffic-analysis and presence-of-card
   attacks even when the SCP11 payload itself is unforgeable.

7. **Session teardown on bus failure.** When the bus drops, the
   library's `Session.Close` must be called (or the session must be
   discarded) so key material is zeroed. Reconnect logic on the bus
   should not silently resume a session — a new SCP11 handshake is
   required.

## What the library does not do

The library is a **protocol engine**, not a deployment runtime. It
does not implement, and will not grow, any of:

* a job queue, scheduler, or workflow system,
* an endpoint identity layer or device registry,
* a tenant or organization model,
* a policy engine beyond `trust.Policy` for card identity,
* a message broker, queue, or streaming protocol,
* an audit sink,
* product-specific task or job names.

The calling system owns those concerns. The library answers a single
question:

> Given a `transport.Transport` that can send APDUs and return raw
> responses, can I safely open SCP03/SCP11 and manage a card?

The calling system answers:

> Which endpoint, card, policy, workflow, broker session, tenant
> boundary, and audit context are authorized to provide that
> transport?

## SCP03 over a remote bus

SCP03 is supported as a `Transport` like any other, but the SCP03
session must run on whichever side holds the static keys. If you ship
the static keys to the endpoint, the endpoint runs the protocol and
the bus carries higher-level commands (or just status). If you keep
the static keys on the server, the server runs the protocol and the
bus carries APDUs — but at that point the endpoint sees no benefit
over the SCP11 model, and you give up the asymmetric-key advantage.

The SCP11 relay model is the recommended pattern for server-driven
remote administration. SCP03 is the recommended pattern for local
administration, factory initialization, lab tooling, and any flow
where the caller is co-located with the card.

## See also

* `transport.Transport` — the integration boundary.
* `transport/pcsc` — a local PC/SC implementation, useful as a
  reference for what an endpoint-side wrapper looks like.
* `yubikey.SCP11bConfig`, `yubikey.SCP11aConfig`, `yubikey.SCP11cConfig` —
  starting points for `scp11.Config` with the right security level and
  validation defaults.
* `securitydomain.OpenSCP11` — Security Domain wrapper that captures
  the SCP11-derived DEK for PUT KEY without exposing it to callers.
* `trust.Policy` — `Roots`, `AllowedSerials`, `ExpectedSKI`,
  `ExpectedEKUs`, `CustomValidator`. These are the controls a
  server-side controller uses to validate the card's identity before
  trusting the relay.
