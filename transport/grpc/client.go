package grpc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
	pb "github.com/PeculiarVentures/scp/transport/grpc/proto/cardrelayv1"
)

// Client is a transport.Transport that proxies APDUs to a remote
// CardRelay server. The underlying gRPC stream represents the card
// session: opened by Dial / NewClient, closed by Close.
//
// Client is safe for concurrent Transmit/TransmitRaw calls — they
// serialize internally via the stream send/recv mutex. A single
// Client maps to a single card session on the server, and the
// server forwards APDUs to its locally-attached card in the order
// the client sent them.
//
// Dial is the one-line "give me a working transport" entry point;
// NewClient takes an already-established *grpc.ClientConn for tests
// or for callers that want to manage connection lifetime themselves.
type Client struct {
	conn   *grpc.ClientConn
	owns   bool // true if Close should also close conn
	stream pb.CardRelay_SessionClient
	cancel context.CancelFunc

	// mu serializes Send/Recv pairs on the stream so concurrent
	// Transmit calls don't interleave wire bytes. The gRPC docs
	// allow concurrent SendMsg+RecvMsg from different goroutines
	// but require external synchronization for "two SendMsgs at
	// once" — which is exactly what concurrent Transmit would
	// produce without the lock.
	mu sync.Mutex
}

// DialOptions controls how Dial establishes the gRPC connection.
type DialOptions struct {
	// Target is the gRPC target string (e.g. "host:port", "unix:///path").
	// Required.
	Target string

	// Reader, if non-empty, is the substring match the server uses
	// to pick which physical reader to bind the session to. Empty
	// = server's default.
	Reader string

	// GRPCDialOptions are passed through to grpc.NewClient. The
	// canonical production use is grpc.WithTransportCredentials(
	// credentials.NewTLS(...)) for mTLS. If empty, Dial uses
	// insecure credentials, which is fine for tests and the local
	// example but is NOT acceptable for any real deployment —
	// CardRelay relies entirely on transport security to bound
	// who can drive APDUs at the card.
	GRPCDialOptions []grpc.DialOption
}

// Dial connects to a CardRelay server and opens a card session.
// The returned Client implements transport.Transport.
//
// Insecure dial behavior: when GRPCDialOptions is empty, Dial uses
// insecure credentials. This is intentional for the smoke-test path
// (the example/server runs over plain TCP for local development).
// Any deployment beyond that must pass explicit credentials — there
// is no default mTLS configuration that would be both secure AND
// not surprising; the choice belongs to the caller.
func Dial(ctx context.Context, opts DialOptions) (*Client, error) {
	if opts.Target == "" {
		return nil, errors.New("grpc.Dial: Target is required")
	}
	dialOpts := opts.GRPCDialOptions
	if len(dialOpts) == 0 {
		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	}
	conn, err := grpc.NewClient(opts.Target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient %q: %w", opts.Target, err)
	}
	c, err := newClient(ctx, conn, opts.Reader)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.owns = true
	return c, nil
}

// NewClient builds a Client over an already-established gRPC
// connection. The caller retains ownership of conn — Client.Close
// will tear down the stream but leave conn open.
func NewClient(ctx context.Context, conn *grpc.ClientConn, readerHint string) (*Client, error) {
	return newClient(ctx, conn, readerHint)
}

func newClient(ctx context.Context, conn *grpc.ClientConn, readerHint string) (*Client, error) {
	// The stream's context outlives the caller's ctx — it lives
	// until Close(). The caller's ctx only bounds the initial
	// Hello round-trip via per-call deadline below. Without this
	// decoupling, a caller passing a request-scoped ctx to
	// NewClient would see the stream die as soon as that context
	// cancelled, even though the Client object is still in use.
	streamCtx, cancel := context.WithCancel(context.Background())
	stub := pb.NewCardRelayClient(conn)
	stream, err := stub.Session(streamCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open Session stream: %w", err)
	}

	// Send Hello and consume the HelloResponse so the stream is
	// known-good before we return. If the caller's ctx has a
	// deadline, honor it for this initial exchange via a
	// best-effort deadline check after Recv.
	if err := stream.Send(&pb.ClientMessage{
		Body: &pb.ClientMessage_Hello{Hello: &pb.HelloRequest{
			Reader:          readerHint,
			ProtocolVersion: ProtocolVersion,
		}},
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("send hello: %w", err)
	}

	// Race the Recv against the caller's ctx so a slow server
	// doesn't hold us forever. If caller's ctx fires first we
	// cancel the stream.
	type recvResult struct {
		msg *pb.ServerMessage
		err error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		msg, err := stream.Recv()
		recvCh <- recvResult{msg, err}
	}()
	var resp *pb.ServerMessage
	select {
	case r := <-recvCh:
		if r.err != nil {
			cancel()
			return nil, fmt.Errorf("recv hello response: %w", r.err)
		}
		resp = r.msg
	case <-ctx.Done():
		cancel()
		return nil, fmt.Errorf("hello: %w", ctx.Err())
	}

	switch body := resp.Body.(type) {
	case *pb.ServerMessage_Hello:
		if body.Hello.ProtocolVersion != 0 && body.Hello.ProtocolVersion != ProtocolVersion {
			cancel()
			return nil, fmt.Errorf("server speaks protocol_version=%d, client expects %d",
				body.Hello.ProtocolVersion, ProtocolVersion)
		}
	case *pb.ServerMessage_Error:
		cancel()
		return nil, fmt.Errorf("server rejected hello: %s (kind=%s)",
			body.Error.Message, body.Error.Kind)
	default:
		cancel()
		return nil, fmt.Errorf("server sent unexpected first message type %T", resp.Body)
	}

	return &Client{
		conn:   conn,
		stream: stream,
		cancel: cancel,
	}, nil
}

// Transmit forwards a parsed APDU to the server and returns the
// response. Implements transport.Transport.
func (c *Client) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.stream.Send(&pb.ClientMessage{
		Body: &pb.ClientMessage_Transmit{Transmit: &pb.TransmitRequest{
			Body: &pb.TransmitRequest_Apdu{Apdu: apduToProto(cmd)},
		}},
	}); err != nil {
		return nil, fmt.Errorf("grpc.Transmit send: %w", err)
	}
	resp, err := c.stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("grpc.Transmit recv: %w", err)
	}
	return interpretTransmitResponseAPDU(resp)
}

// TransmitRaw forwards already-encoded APDU bytes to the server and
// returns the raw response bytes. Implements transport.Transport.
//
// This is the right entry point when the client is doing its own
// secure-channel work (SCP03/SCP11) and the server is just relaying
// already-wrapped APDUs. The server doesn't see plaintext APDUs in
// that mode; it sees the SCP-wrapped ciphertext, so a server compromise
// gets the attacker MAC-authenticated wrapped APDUs but not their
// plaintext or the SCP keys.
func (c *Client) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.stream.Send(&pb.ClientMessage{
		Body: &pb.ClientMessage_Transmit{Transmit: &pb.TransmitRequest{
			Body: &pb.TransmitRequest_Raw{Raw: raw},
		}},
	}); err != nil {
		return nil, fmt.Errorf("grpc.TransmitRaw send: %w", err)
	}
	resp, err := c.stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("grpc.TransmitRaw recv: %w", err)
	}
	return interpretTransmitResponseRaw(resp)
}

// Close releases the card session on the server and (if Dial-ed)
// the underlying gRPC connection. Idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		// CloseSend tells the server we're done sending; cancel
		// then forces the gRPC machinery to release the stream.
		_ = c.stream.CloseSend()
		c.cancel()
		c.cancel = nil
	}
	var err error
	if c.owns && c.conn != nil {
		err = c.conn.Close()
		c.conn = nil
	}
	return err
}

// Compile-time check: *Client implements transport.Transport.
var _ transport.Transport = (*Client)(nil)

// interpretTransmitResponseAPDU pulls an apdu.Response out of a
// TransmitResponse, surfacing server errors as Go errors.
func interpretTransmitResponseAPDU(msg *pb.ServerMessage) (*apdu.Response, error) {
	switch body := msg.Body.(type) {
	case *pb.ServerMessage_Transmit:
		switch tbody := body.Transmit.Body.(type) {
		case *pb.TransmitResponse_Apdu:
			return apduResponseFromProto(tbody.Apdu), nil
		default:
			return nil, fmt.Errorf("grpc.Transmit: server returned %T, expected APDU response", tbody)
		}
	case *pb.ServerMessage_Error:
		return nil, fmt.Errorf("server error: %s (kind=%s)", body.Error.Message, body.Error.Kind)
	default:
		return nil, fmt.Errorf("grpc.Transmit: unexpected server message %T", msg.Body)
	}
}

// interpretTransmitResponseRaw is the raw-bytes counterpart.
func interpretTransmitResponseRaw(msg *pb.ServerMessage) ([]byte, error) {
	switch body := msg.Body.(type) {
	case *pb.ServerMessage_Transmit:
		switch tbody := body.Transmit.Body.(type) {
		case *pb.TransmitResponse_Raw:
			return tbody.Raw, nil
		default:
			return nil, fmt.Errorf("grpc.TransmitRaw: server returned %T, expected raw response", tbody)
		}
	case *pb.ServerMessage_Error:
		return nil, fmt.Errorf("server error: %s (kind=%s)", body.Error.Message, body.Error.Kind)
	default:
		return nil, fmt.Errorf("grpc.TransmitRaw: unexpected server message %T", msg.Body)
	}
}

// apduToProto serializes an apdu.Command for the wire.
func apduToProto(c *apdu.Command) *pb.Apdu {
	return &pb.Apdu{
		Cla:            uint32(c.CLA),
		Ins:            uint32(c.INS),
		P1:             uint32(c.P1),
		P2:             uint32(c.P2),
		Data:           c.Data,
		Le:             int32(c.Le),
		ExtendedLength: c.ExtendedLength,
	}
}

// apduResponseFromProto deserializes a wire APDU response.
func apduResponseFromProto(p *pb.ApduResponse) *apdu.Response {
	return &apdu.Response{
		Data: p.Data,
		SW1:  byte(p.Sw1),
		SW2:  byte(p.Sw2),
	}
}

// TrustBoundary reports that this transport relays APDUs across a
// network boundary (gRPC). The relay sees every APDU on the wire
// in cleartext unless the caller wraps it with a secure-channel
// layer (SCP11b, etc.). Raw destructive PIV operations against a
// gRPC-relayed card are exactly the case --raw-local-ok must
// refuse: the host running scpctl is NOT in the same trust
// boundary as the card.
func (c *Client) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryRelay
}
