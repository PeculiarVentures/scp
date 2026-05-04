// Command cardrelay-server exposes a locally-attached PC/SC card
// (USB CCID or NFC) over gRPC so a remote client can drive APDUs
// at it.
//
// Usage:
//
//	cardrelay-server [-listen :7777] [-reader "YubiKey"]
//
// This is a development binary. Threat-model notes are in the
// transport/grpc package doc comment and in the example/README.md;
// the short version: this server has NO authorization layer of its
// own. Run it on a trusted network, behind mTLS, and pair it with
// a separate authorization layer for any real deployment.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/PeculiarVentures/scp/transport"
	scpgrpc "github.com/PeculiarVentures/scp/transport/grpc"
	pb "github.com/PeculiarVentures/scp/transport/grpc/proto/cardrelayv1"
	"github.com/PeculiarVentures/scp/transport/pcsc"
)

func main() {
	listen := flag.String("listen", ":7777",
		"Address to listen on (e.g. :7777, unix:///tmp/cardrelay.sock).")
	defaultReader := flag.String("reader", "",
		"Default reader substring match. Clients can override per-Hello.")
	flag.Parse()

	lis, err := listenOn(*listen)
	if err != nil {
		log.Fatalf("listen %q: %v", *listen, err)
	}

	srv := grpc.NewServer()
	pb.RegisterCardRelayServer(srv, scpgrpc.NewServer(
		makePCSCFactory(*defaultReader),
	))

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down")
		srv.GracefulStop()
	}()

	log.Printf("CardRelay listening on %s (default reader %q)", *listen, *defaultReader)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// makePCSCFactory returns a TransportFactory that opens the local
// PC/SC reader. The reader hint from the client overrides the
// command-line default; if both are empty, OpenFirstReader is used.
func makePCSCFactory(defaultReader string) scpgrpc.TransportFactory {
	return func(_ context.Context, hint string) (transport.Transport, error) {
		picked := hint
		if picked == "" {
			picked = defaultReader
		}
		if picked == "" {
			return pcsc.OpenFirstReader()
		}
		return pcsc.OpenReader(picked)
	}
}

// listenOn handles both TCP-style ("host:port") and unix-socket-style
// ("unix:///path") listen addresses.
func listenOn(addr string) (net.Listener, error) {
	if len(addr) > 7 && addr[:7] == "unix://" {
		return net.Listen("unix", addr[7:])
	}
	return net.Listen("tcp", addr)
}
