// Package grpc provides a gRPC-based network transport for the scp
// protocol engine. It has two halves that can be used independently:
//
//   - Server: a gRPC service implementation that wraps an existing
//     transport.Transport (typically a real PC/SC card) and exposes
//     it on the wire. See NewServer.
//
//   - Client: a transport.Transport implementation that proxies APDUs
//     to a remote CardRelay service. See Dial / NewClient.
//
// Wire model: one bidirectional stream per card session. Stream
// open = card acquired, stream close = card released. Inside the
// stream the client sends an optional Hello to pick a reader and
// then a sequence of TransmitRequests; the server responds with a
// matching sequence of TransmitResponses.
//
// Threat model:
//
// CardRelay is transport infrastructure, not an authorization
// boundary. A client that can reach the gRPC port and authenticate
// at the transport layer (mTLS) can drive any APDU at the card,
// including signing operations once the PIN has been verified.
// Production deployments must layer per-operation authorization on
// top — capability tokens, attested workload identity, audit-by-
// out-of-band-evaluator. Without that layer, exposing a PIN-verified
// PIV applet over CardRelay is equivalent to handing the network a
// signing oracle.
//
// Run the server with mTLS (grpc.Creds(credentials.NewTLS(...)));
// the example/ directory shows the minimum viable production setup.
// The plain-TCP examples in tests are for development only.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
	pb "github.com/PeculiarVentures/scp/transport/grpc/proto/cardrelayv1"
)

// ProtocolVersion is the wire-protocol version this package speaks.
// Servers reject Hello messages whose version doesn't match.
const ProtocolVersion uint32 = 1

// TransportFactory opens a transport.Transport for the given reader
// hint. The server calls this once per Session stream — when the
// client sends Hello, the server invokes the factory with the
// requested reader name (or "" for default), uses the resulting
// transport for the lifetime of the stream, and closes it on stream
// teardown.
//
// A factory that returns an error causes the server to send an
// ErrorResponse and close the stream; the client surfaces this as
// a stream-establishment failure.
//
// The two common factories:
//
//   - For production: a closure over pcsc.OpenReader / pcsc.OpenFirstReader,
//     mapping the reader hint to a real card. The example/server uses
//     this pattern.
//
//   - For tests: a closure over a mockcard.Card.Transport(), ignoring
//     the reader hint. The package's own tests use this.
type TransportFactory func(ctx context.Context, readerHint string) (transport.Transport, error)

// Server is the gRPC service implementation. Embeds the generated
// UnimplementedCardRelayServer so future RPCs added to the .proto
// don't break existing servers at compile time.
type Server struct {
	pb.UnimplementedCardRelayServer

	factory TransportFactory
}

// NewServer constructs a CardRelay server backed by the given
// transport factory. Register the result with a *grpc.Server via
// pb.RegisterCardRelayServer.
func NewServer(factory TransportFactory) *Server {
	if factory == nil {
		// Fail-closed at construction: a nil factory would let
		// streams open and immediately error, which is worse than
		// refusing to start.
		panic("grpc.NewServer: TransportFactory must not be nil")
	}
	return &Server{factory: factory}
}

// Session implements the bidi-streaming RPC. One call = one card
// session.
func (s *Server) Session(stream pb.CardRelay_SessionServer) error {
	ctx := stream.Context()

	// Phase 1: receive Hello (or first Transmit, with implicit
	// default reader).
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil // client closed before sending anything
		}
		return fmt.Errorf("recv first message: %w", err)
	}

	var readerHint string
	switch body := first.Body.(type) {
	case *pb.ClientMessage_Hello:
		if body.Hello.ProtocolVersion != 0 && body.Hello.ProtocolVersion != ProtocolVersion {
			return sendError(stream, pb.ErrorResponse_PROTOCOL_VERSION,
				fmt.Sprintf("server speaks protocol_version=%d, client sent %d",
					ProtocolVersion, body.Hello.ProtocolVersion))
		}
		readerHint = body.Hello.Reader
	case *pb.ClientMessage_Transmit:
		// No Hello sent — open with the default reader and treat
		// this first Transmit as the actual first APDU.
		t, openErr := s.openTransport(ctx, "")
		if openErr != nil {
			return openErr
		}
		defer t.Close()
		if err := s.handleTransmit(ctx, stream, t, body.Transmit); err != nil {
			return err
		}
		return s.runStream(ctx, stream, t)
	default:
		return sendError(stream, pb.ErrorResponse_INVALID_REQUEST,
			"first message must be Hello or Transmit")
	}

	// Phase 2: open the underlying transport and acknowledge.
	t, err := s.openTransport(ctx, readerHint)
	if err != nil {
		return err
	}
	defer t.Close()

	if err := stream.Send(&pb.ServerMessage{
		Body: &pb.ServerMessage_Hello{Hello: &pb.HelloResponse{
			Reader:          readerHint, // best-effort echo; real impl can override
			ProtocolVersion: ProtocolVersion,
		}},
	}); err != nil {
		return fmt.Errorf("send hello response: %w", err)
	}

	// Phase 3: pump APDUs until the client closes the stream or
	// the underlying transport errors out.
	return s.runStream(ctx, stream, t)
}

// openTransport calls the factory, mapping any factory error into
// an appropriate ErrorResponse on the stream.
func (s *Server) openTransport(ctx context.Context, hint string) (transport.Transport, error) {
	t, err := s.factory(ctx, hint)
	if err != nil {
		return nil, fmt.Errorf("open transport (reader %q): %w", hint, err)
	}
	if t == nil {
		return nil, fmt.Errorf("transport factory returned nil for reader %q", hint)
	}
	return t, nil
}

// runStream reads transmits from the client and forwards them.
// Returns nil on clean client-side close, or an error otherwise.
func (s *Server) runStream(
	ctx context.Context,
	stream pb.CardRelay_SessionServer,
	t transport.Transport,
) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		body, ok := msg.Body.(*pb.ClientMessage_Transmit)
		if !ok {
			if err := sendError(stream, pb.ErrorResponse_INVALID_REQUEST,
				"only Transmit allowed after Hello"); err != nil {
				return err
			}
			continue
		}
		if err := s.handleTransmit(ctx, stream, t, body.Transmit); err != nil {
			return err
		}
	}
}

// handleTransmit forwards one APDU and writes the response back on
// the stream.
func (s *Server) handleTransmit(
	ctx context.Context,
	stream pb.CardRelay_SessionServer,
	t transport.Transport,
	req *pb.TransmitRequest,
) error {
	switch body := req.Body.(type) {
	case *pb.TransmitRequest_Apdu:
		cmd := apduFromProto(body.Apdu)
		resp, err := t.Transmit(ctx, cmd)
		if err != nil {
			return sendError(stream, pb.ErrorResponse_TRANSPORT, err.Error())
		}
		return stream.Send(&pb.ServerMessage{
			Body: &pb.ServerMessage_Transmit{Transmit: &pb.TransmitResponse{
				Body: &pb.TransmitResponse_Apdu{Apdu: apduResponseToProto(resp)},
			}},
		})
	case *pb.TransmitRequest_Raw:
		raw, err := t.TransmitRaw(ctx, body.Raw)
		if err != nil {
			return sendError(stream, pb.ErrorResponse_TRANSPORT, err.Error())
		}
		return stream.Send(&pb.ServerMessage{
			Body: &pb.ServerMessage_Transmit{Transmit: &pb.TransmitResponse{
				Body: &pb.TransmitResponse_Raw{Raw: raw},
			}},
		})
	default:
		return sendError(stream, pb.ErrorResponse_INVALID_REQUEST,
			"TransmitRequest.body must be apdu or raw")
	}
}

func sendError(stream pb.CardRelay_SessionServer, kind pb.ErrorResponse_Kind, msg string) error {
	return stream.Send(&pb.ServerMessage{
		Body: &pb.ServerMessage_Error{Error: &pb.ErrorResponse{
			Message: msg,
			Kind:    kind,
		}},
	})
}

// apduFromProto converts a wire APDU to the apdu.Command form used
// by the rest of the library.
func apduFromProto(p *pb.Apdu) *apdu.Command {
	return &apdu.Command{
		CLA:            byte(p.Cla),
		INS:            byte(p.Ins),
		P1:             byte(p.P1),
		P2:             byte(p.P2),
		Data:           p.Data,
		Le:             int(p.Le),
		ExtendedLength: p.ExtendedLength,
	}
}

// apduResponseToProto serializes an apdu.Response into its wire form.
func apduResponseToProto(r *apdu.Response) *pb.ApduResponse {
	return &pb.ApduResponse{
		Data: r.Data,
		Sw1:  uint32(r.SW1),
		Sw2:  uint32(r.SW2),
	}
}
