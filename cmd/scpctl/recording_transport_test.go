package main

import (
	"context"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// recordingTransport wraps a transport and records every command
// sent through it. Tests use it to assert that flags like
// --sd-aid produce APDUs with the expected wire bytes (e.g. that
// the first SELECT carries the operator-supplied AID rather than
// the default).
//
// Lives in cmd/scpctl tests rather than the transport package
// because the recording shape is test-specific (commands kept
// in memory, accessor returns a snapshot). Callers wrap the
// returned transport.Transport from a mock card and pass it to
// the command-under-test via env.connect.
type recordingTransport struct {
	inner transport.Transport
	cmds  []*apdu.Command
}

func newRecordingTransport(inner transport.Transport) *recordingTransport {
	return &recordingTransport{inner: inner}
}

func (rt *recordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	rt.cmds = append(rt.cmds, cmd)
	return rt.inner.Transmit(ctx, cmd)
}

func (rt *recordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return rt.inner.TransmitRaw(ctx, raw)
}

func (rt *recordingTransport) Close() error { return rt.inner.Close() }
func (rt *recordingTransport) TrustBoundary() transport.TrustBoundary {
	return rt.inner.TrustBoundary()
}

// firstSelect returns the first SELECT command (INS=0xA4) the
// transport saw, or nil if none was sent. Used by --sd-aid tests
// to assert the operator-supplied AID reached the wire.
func (rt *recordingTransport) firstSelect() *apdu.Command {
	for _, c := range rt.cmds {
		if c.INS == 0xA4 {
			return c
		}
	}
	return nil
}
