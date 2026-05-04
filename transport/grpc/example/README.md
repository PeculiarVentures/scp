# cardrelay example: server + client

Runnable demonstration of [`transport/grpc`](..). The server exposes a locally-attached PC/SC card (USB CCID YubiKey, etc.) over gRPC; the client connects to it and runs a SELECT PIV round-trip to prove the wire path works.

## Quick start (development, no TLS)

```bash
cd example/server
go build -o /tmp/cardrelay-server .

cd ../client
go build -o /tmp/cardrelay-client .

# Terminal 1
/tmp/cardrelay-server -listen :7777 -reader "YubiKey"

# Terminal 2
/tmp/cardrelay-client -target localhost:7777
```

Expected client output:
```
SELECT PIV ok, FCI <N> bytes:
4F 0B A0 00 00 03 08 00 00 10 00 01 00 ...

Round-trip through CardRelay succeeded.
```

This default uses insecure transport credentials. **Do not use this configuration for anything beyond local development.** The server has no authentication, and the network sees plaintext APDU bytes including PINs.

## Production: mTLS

Both binaries are intentionally short and the TLS configuration is left for the deployer to fill in. The minimum changes needed:

**Server**

```go
// Replace `srv := grpc.NewServer()` with:
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    clientCAs,
    MinVersion:   tls.VersionTLS13,
}
srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
```

**Client**

```go
// Replace the bare scpgrpc.Dial(...) call with:
client, err := scpgrpc.Dial(ctx, scpgrpc.DialOptions{
    Target: *target,
    Reader: *reader,
    GRPCDialOptions: []grpc.DialOption{
        grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
            RootCAs:      serverCAs,
            Certificates: []tls.Certificate{clientCert},
            MinVersion:   tls.VersionTLS13,
        })),
    },
})
```

This gives you transport security (encrypted channel) and mutual authentication (server verifies the client's cert, client verifies the server's cert). It does NOT give you authorization — see the next section.

## Production: authorization layer

mTLS bounds **who can talk to the server.** It does not bound **what they can ask for.** A client cert authenticated as `app-frontend.prod` can still issue VERIFY PIN followed by GENERAL AUTHENTICATE for a signing operation against any PIV slot. If your deployment cares about which workloads can drive which APDUs (it should), wire up a gRPC interceptor that inspects the request and checks an authorization token before letting it through:

```go
import "google.golang.org/grpc"

func authInterceptor(ctx context.Context, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
    // 1. Extract caller identity from peer cert / metadata.
    // 2. Inspect the first message on the stream; reject if the
    //    caller's policy doesn't permit the requested reader or APDU.
    // 3. Optionally wrap the stream to inspect every TransmitRequest
    //    and apply per-APDU policy.
    return handler(srv, wrappedStream)
}

srv := grpc.NewServer(
    grpc.Creds(credentials.NewTLS(tlsCfg)),
    grpc.StreamInterceptor(authInterceptor),
)
```

This is exactly the kind of per-operation capability scoping the [Authority Gap](https://www.unmitigatedrisk.com/) writeup is about: the cert proves you ARE someone, the policy decides what someone of your kind is allowed to ASK FOR. Two different problems, two different layers.

## Other knobs

- **Unix sockets.** `-listen unix:///var/run/cardrelay.sock` works for local same-machine use; combine with file-system permissions on the socket for an out-of-band authorization story.
- **Reader selection.** The server's `-reader` flag is a default. Clients can override per-stream by passing a reader name to `scpgrpc.Dial` — useful when one server hosts multiple cards.
- **Health checks.** Not built in. The standard `google.golang.org/grpc/health` package plugs in directly if your load balancer needs it.
