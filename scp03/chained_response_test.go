package scp03_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// splitInboundTransport wraps an inner transport and forces every
// non-empty 9000 response to be split across SW=61xx chunks. The
// host-side path being exercised:
//
//  1. Inner mock card returns a normal 9000 + N bytes
//  2. This wrapper intercepts and rewrites that response as
//     "first half + 61xx" — pretending the card said "more data
//     follows"
//  3. The host is forced to issue GET RESPONSE; the wrapper
//     replies with the second half + 9000
//
// Without the SCP03 Session.Transmit drain fix, this scenario would
// pass the partial first chunk to channel.Unwrap and fail R-MAC
// verification — terminating the session. With the fix,
// DrainGetResponse reassembles before Unwrap and the response
// decrypts cleanly.
type splitInboundTransport struct {
	inner   transport.Transport
	pending []byte // remaining bytes if a GET RESPONSE is expected
	active  bool   // when false, pass everything through unchanged
}

func (s *splitInboundTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// If the host issued GET RESPONSE (INS=0xC0), serve the
	// remainder we held back from the previous response.
	if cmd.INS == 0xC0 && s.pending != nil {
		data := s.pending
		s.pending = nil
		return &apdu.Response{Data: data, SW1: 0x90, SW2: 0x00}, nil
	}

	// Forward to the inner transport.
	resp, err := s.inner.Transmit(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Pass-through during the SCP handshake; only force-chain
	// after the session is open. INITIALIZE UPDATE / EXTERNAL
	// AUTHENTICATE happen pre-channel and Session.Transmit's
	// drain doesn't cover them — splitting their responses
	// would break the handshake before the bug under test ever
	// has a chance to fire.
	if !s.active {
		return resp, nil
	}

	// Only split successful responses with non-trivial bodies.
	// Errors and warning SWs pass through unchanged so this
	// wrapper doesn't perturb the session-error code paths.
	if resp.SW1 != 0x90 || resp.SW2 != 0x00 || len(resp.Data) <= 16 {
		return resp, nil
	}

	half := len(resp.Data) / 2
	first := append([]byte(nil), resp.Data[:half]...)
	s.pending = append([]byte(nil), resp.Data[half:]...)

	// SW2 is the card's hint to the host for the next GET
	// RESPONSE Le. 0x00 means "as much as available."
	return &apdu.Response{Data: first, SW1: 0x61, SW2: 0x00}, nil
}

func (s *splitInboundTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return s.inner.TransmitRaw(ctx, raw)
}

func (s *splitInboundTransport) Close() error { return s.inner.Close() }
func (s *splitInboundTransport) TrustBoundary() transport.TrustBoundary {
	return s.inner.TrustBoundary()
}

// TestSCP03_Transmit_DrainsChainedResponseBeforeUnwrap is the
// regression test for the chained-response R-MAC bug surfaced by
// hardware verification on YubiKey 5.7.4 ATTEST. Before the fix,
// any SCP-secured response that exceeded the short-Le bound forced
// the card to split the encrypted payload across multiple APDUs
// (61xx + GET RESPONSE → 9000), and Session.Transmit would invoke
// channel.Unwrap on the partial first chunk — failing R-MAC and
// tearing down the session.
//
// The test forces every authenticated GET DATA response through
// a splitter that emulates that 61xx flow on every response,
// regardless of size. Without the drain fix in scp03.Session.
// Transmit, this test fails with "unwrap response (session
// terminated): ... MAC verification failed". With the fix, the
// drained payload unwraps to the expected CRD bytes.
func TestSCP03_Transmit_DrainsChainedResponseBeforeUnwrap(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	wrapper := &splitInboundTransport{inner: mock.Transport()}

	sess, err := scp03.Open(context.Background(), wrapper, &scp03.Config{
		Keys: scp03.DefaultKeys,
	})
	if err != nil {
		t.Fatalf("scp03.Open: %v", err)
	}
	defer sess.Close()

	// Activate the splitter now that the handshake is done. From
	// this point every successful response gets force-chained
	// across 61xx + GET RESPONSE so the integration exercises
	// the drain path inside Session.Transmit.
	wrapper.active = true

	// GET DATA tag 0x0066 — Card Recognition Data. The mock
	// returns 51 bytes; the splitter forces it across two
	// responses with an intervening GET RESPONSE.
	cmd := &apdu.Command{
		CLA: 0x00,
		INS: 0xCA,
		P1:  0x00,
		P2:  0x66,
		Le:  -1,
	}
	resp, err := sess.Transmit(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Transmit (post-drain): %v", err)
	}
	if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
		t.Fatalf("expected SW=9000, got %02X%02X", resp.SW1, resp.SW2)
	}
	// Sanity-check the assembled CRD by looking for the GP RID
	// OID encoding (a fixed 9-byte sequence). If the unwrapped
	// data contains it, R-MAC + R-DEC succeeded on the full
	// reassembled payload.
	gpRID := []byte{0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01}
	if !bytes.Contains(resp.Data, gpRID) {
		t.Errorf("unwrapped CRD missing GP RID OID; got % X", resp.Data)
	}
}
