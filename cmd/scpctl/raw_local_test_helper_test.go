package main

import (
	"context"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// rawLocalAcknowledgedTransport wraps an inner transport.Transport
// and overrides its TrustBoundary() to return TrustBoundaryLocalPCSC.
//
// This exists because the production --raw-local-ok gate requires
// the transport itself to report TrustBoundaryLocalPCSC, and the
// mock card returns TrustBoundaryUnknown by design (mocks are test
// fixtures, not real transports; they should not pretend to be in
// any particular trust boundary). Tests that exercise the raw
// channel-mode path against the mock route the mock's transport
// through this wrapper to make the explicit assertion that the
// test environment is treating the mock as if it were local-PCSC.
//
// Production code never reaches this wrapper because pcscConnect
// is the only transport factory wired into main, and pcsc.Transport
// returns TrustBoundaryLocalPCSC natively. The wrapper is a test-
// only override and should never be used outside _test.go files.
type rawLocalAcknowledgedTransport struct {
	inner transport.Transport
}

func (r *rawLocalAcknowledgedTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return r.inner.Transmit(ctx, cmd)
}

func (r *rawLocalAcknowledgedTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *rawLocalAcknowledgedTransport) Close() error {
	return r.inner.Close()
}

func (r *rawLocalAcknowledgedTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryLocalPCSC
}

// asLocal wraps t in a rawLocalAcknowledgedTransport. Tests that
// want to exercise the --raw-local-ok end-to-end path against the
// mock card use this to make the wrapping intent obvious at the
// call site. Calling code looks like:
//
//	connect: func(ctx, name) { return asLocal(card.Transport()), nil }
//
// The function is also where readers searching for "how do I make
// a mock test work with --raw-local-ok" land first, so the answer
// is colocated with the wrapper itself.
func asLocal(t transport.Transport) transport.Transport {
	return &rawLocalAcknowledgedTransport{inner: t}
}
