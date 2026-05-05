# transport/grpc — CardRelay

Network transport for the [scp](../..) protocol engine. Server side wraps an existing `transport.Transport` (typically a real PC/SC card via [`transport/pcsc`](../pcsc)) and exposes it over gRPC. Client side implements `transport.Transport`, so any code that takes a transport — `scp03.Open`, `scp11.Open`, `securitydomain.OpenSCP11`, `cmd/scpctl` — runs against a remote card with no source changes.

## Wire model

One bidirectional gRPC stream per card session. Stream open = card acquired on the server. Stream close = card released. Inside the stream:

```
client → server: Hello {reader, protocol_version}
server → client: HelloResponse {reader, protocol_version}
client → server: TransmitRequest {apdu | raw}    ┐ repeated for the
server → client: TransmitResponse {apdu | raw}   ┘ life of the session
client closes stream → server releases card
```

No session ID. No multiplexing. Multiple readers = multiple streams.

The `apdu` vs `raw` choice on TransmitRequest is intentional: parsed APDUs are convenient for the common case, but if the **client** is doing the secure-channel work (SCP03/SCP11) and the server is just relaying already-wrapped APDUs, `raw` is the right path. The server sees ciphertext, never plaintext APDUs or SCP keys, so a server compromise yields MAC-authenticated wrapped traffic but not the underlying operation semantics.

## Threat model

CardRelay is **transport infrastructure, not an authorization boundary.** Three things to internalize:

**1. The server has no built-in authorization.** Anyone who can reach the gRPC port and pass mTLS can drive any APDU at the card, including signing operations once the PIN has been verified. If you want per-operation authorization (and you should), pair CardRelay with a separate layer — capability tokens, attested workload identity, out-of-band policy evaluation. This is exactly the problem the [Authority Gap](https://www.unmitigatedrisk.com/) framing is about.

**2. mTLS is mandatory for any deployment.** The library defaults to insecure credentials when none are passed (so the in-process tests work), but production code MUST pass `grpc.WithTransportCredentials(credentials.NewTLS(...))`. Without TLS the network sees plaintext APDU traffic; the PIN, the responses, the wrapped session bytes, all of it.

**3. PIN-verified state crosses the wire.** After a successful VERIFY PIN APDU on a YubiKey PIV applet, subsequent signing APDUs don't re-prompt for the PIN — the card holds the verified state until reset or applet de-select. CardRelay forwards that state automatically. If the network can reach the relay, the network gets a signing oracle for the duration of the session. The `Apdu raw` mode mitigates this only if the SCP keys live on the client (the server can't decrypt the wrapped APDUs); but a server that controls the SCP handshake itself sees plaintext.

## Use cases this fits

- **Fleet-of-cards backend.** A datacenter has N USB hubs full of HSMs/YubiKeys, each running CardRelay. Application servers across the fleet open streams to the relay closest to a needed card, run their PKI operation, close the stream. The cards aren't tied to any specific application server.

- **Developer ergonomics.** Developer's YubiKey is plugged into their laptop; their CI pipeline running in the cloud needs to test code paths that touch a real card. CardRelay forwards the laptop's reader to the cloud worker over a Tailscale tunnel.

- **Offline relay.** An air-gapped signing host with HSMs talks to an online dispatcher over a one-way diode → reverse-CardRelay topology where the dispatcher initiates streams but the air-gapped host has no Internet. (This one needs the auth layer because the threat model is exactly "limit what the dispatcher can ask for.")

## Use cases this does NOT fit

- **Browser → card.** The wire format is gRPC, not gRPC-Web; even with gRPC-Web, browsers can't usefully sign with a remote card without a host-side authorization layer mediating *which* signing operations are allowed.

- **Untrusted server.** If the relay host can't be trusted (e.g. a shared corporate workstation forwarding a colleague's plugged-in card), you want SCP keys on the client and `TransmitRaw` mode only. The relay host still sees the SM-wrapped traffic but not the contents.

- **PIN entry confidence.** CardRelay forwards APDUs; it doesn't have an opinion about how the PIN got into the APDU. Production setups that care about "does the PIN come from a TPM-attested keyboard" need that confidence enforced at the client, not the relay.

## Examples

The [`example/`](./example) directory has runnable server and client binaries demonstrating a working session:

```bash
# Terminal 1: server with a YubiKey plugged in
cd example/server
go build -o /tmp/cardrelay-server .
/tmp/cardrelay-server -listen :7777 -reader "YubiKey"

# Terminal 2: client (could be on a different machine)
cd example/client
go build -o /tmp/cardrelay-client .
/tmp/cardrelay-client -target localhost:7777
# expected output: SELECT PIV ok, FCI <N> bytes
```

Both binaries currently use insecure credentials; for a real deployment the example/README documents the mTLS configuration to drop in.

## Status

- Wire protocol v1 stable for `Apdu` and `raw` round-trips.
- Server-side handler tested end-to-end against the SCP-aware mock card via in-process bufconn.
- Hardware testing planned alongside `cmd/scp-smoke` validation on YubiKey 5.7.2+.
- mTLS configuration left to the caller deliberately — no library-defined defaults that could become the wrong default.

Not yet:
- gRPC interceptors for capability-token authorization (the example just shows how to plug them in).
- Client-side connection pooling for multi-card-multi-stream workloads.
- Reverse-CardRelay topology (server initiates the connection).

## API

```go
// Server: wraps any transport.Transport behind a gRPC service.
factory := func(ctx context.Context, readerHint string) (transport.Transport, error) {
    return pcsc.OpenReader(readerHint) // or any other transport
}
srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
pb.RegisterCardRelayServer(srv, scpgrpc.NewServer(factory))
srv.Serve(listener)

// Client: implements transport.Transport.
client, err := scpgrpc.Dial(ctx, scpgrpc.DialOptions{
    Target: "card-relay.example.internal:443",
    Reader: "YubiKey",
    GRPCDialOptions: []grpc.DialOption{
        grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
    },
})
defer client.Close()

// Use it like any other transport — same SCP11 stack as a local card.
sd, err := securitydomain.OpenSCP11(ctx, client, scp11.YubiKeyDefaultSCP11bConfig())
```
