package grpc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
	pb "github.com/PeculiarVentures/scp/transport/grpc/proto/cardrelayv1"
)

// startTestServer spins up a CardRelay gRPC server backed by the
// given factory on an in-process bufconn listener. Returns a Client
// already connected to it. The test cleans up via t.Cleanup.
func startTestServer(t *testing.T, factory TransportFactory) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterCardRelayServer(srv, NewServer(factory))

	var srvWG sync.WaitGroup
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.GracefulStop()
		srvWG.Wait()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewClient(ctx, conn, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestClientServer_RoundTripsRawAPDUs is the smallest end-to-end:
// the server's factory returns a fresh mockcard transport; the
// client sends a raw SELECT and gets the expected SW=9000 back.
//
// Without the gRPC layer working correctly — proto encoding,
// streaming framing, server-side dispatch — this test fails.
func TestClientServer_RoundTripsRawAPDUs(t *testing.T) {
	mock, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	client := startTestServer(t, func(_ context.Context, _ string) (transport.Transport, error) {
		return mock.Transport(), nil
	})

	// SELECT the security domain — a SELECT with the SD AID is
	// the simplest APDU the mock recognizes.
	selectCmd := &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
		Le:   -1,
	}
	resp, err := client.Transmit(context.Background(), selectCmd)
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
		t.Errorf("expected SW=9000, got %02X%02X", resp.SW1, resp.SW2)
	}
}

// TestClientServer_TransmitRaw_AlsoWorks confirms the raw-bytes mode
// (where the client has already encoded the APDU itself) works
// alongside the parsed-APDU mode. Same round-trip, different oneof
// branch on both sides.
func TestClientServer_TransmitRaw_AlsoWorks(t *testing.T) {
	mock, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	client := startTestServer(t, func(_ context.Context, _ string) (transport.Transport, error) {
		return mock.Transport(), nil
	})

	// Hand-encoded SELECT: 00 A4 04 00 08 A0000001510000 00
	rawSelect := []byte{0x00, 0xA4, 0x04, 0x00, 0x08,
		0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	rawResp, err := client.TransmitRaw(context.Background(), rawSelect)
	if err != nil {
		t.Fatalf("TransmitRaw: %v", err)
	}
	if len(rawResp) < 2 {
		t.Fatalf("response too short: %x", rawResp)
	}
	sw1, sw2 := rawResp[len(rawResp)-2], rawResp[len(rawResp)-1]
	if sw1 != 0x90 || sw2 != 0x00 {
		t.Errorf("expected SW=9000, got %02X%02X", sw1, sw2)
	}
}

// TestClientServer_FullSCP11bSession is the integration test that
// proves the whole stack: client opens a CardRelay session, then
// uses that as the transport layer for a real SCP11b handshake
// against the mock card. If the gRPC plumbing dropped a single byte,
// the SCP11b MAC would fail and Open would error out. So this
// passing means the wire protocol is byte-faithful end-to-end.
func TestClientServer_FullSCP11bSession(t *testing.T) {
	mock, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	client := startTestServer(t, func(_ context.Context, _ string) (transport.Transport, error) {
		return mock.Transport(), nil
	})

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true // mock cert isn't pinned

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sd, err := securitydomain.OpenSCP11(ctx, client, cfg)
	if err != nil {
		t.Fatalf("OpenSCP11 over gRPC: %v", err)
	}
	defer sd.Close()

	// Read the card's key information template under the SCP11b
	// secure channel. Round-trips an SM-wrapped APDU through the
	// gRPC layer and back.
	keyInfo, err := sd.GetKeyInformation(ctx)
	if err != nil {
		t.Fatalf("GetKeyInformation: %v", err)
	}
	if len(keyInfo) == 0 {
		t.Error("empty key info template")
	}
}

// TestClientServer_FactoryError is what happens when the server-side
// factory refuses to open a card — for example, because the
// requested reader doesn't exist. The client should surface this as
// a stream-establishment failure, not a successful Hello followed by
// later confusion.
func TestClientServer_FactoryError(t *testing.T) {
	failingFactory := func(_ context.Context, _ string) (transport.Transport, error) {
		return nil, errFactoryRefused
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterCardRelayServer(srv, NewServer(failingFactory))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.GracefulStop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewClient(ctx, conn, "any-reader")
	if err == nil {
		t.Fatal("expected NewClient to fail when factory refuses")
	}
}

var errFactoryRefused = errFactory("factory refused for test")

type errFactory string

func (e errFactory) Error() string { return string(e) }

// TestNewServer_PanicsOnNilFactory pins the fail-closed contract.
func TestNewServer_PanicsOnNilFactory(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewServer(nil) should panic")
		}
	}()
	_ = NewServer(nil)
}

// TestDial_RejectsEmptyTarget pins the other fail-closed contract.
func TestDial_RejectsEmptyTarget(t *testing.T) {
	_, err := Dial(context.Background(), DialOptions{})
	if err == nil {
		t.Fatal("Dial with empty Target should fail")
	}
}
