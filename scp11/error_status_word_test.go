package scp11_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11_ErrorStatusWord_NoMACVerification covers the GP SCP03
// §6.2.4 rule that R-MAC and R-ENC are applied only to responses
// with SW 9000 or warning 62XX/63XX. Error status words (6Axx, 6Bxx,
// ...) are returned by the card without secure-messaging protection
// and must NOT be MAC-verified host-side — otherwise:
//
//  1. Legitimate card errors look like MAC failures, masking the
//     real SW from the caller.
//  2. The session is needlessly torn down and key material zeroed,
//     forcing a full re-handshake to recover from an ordinary card
//     error.
//  3. Any transport-layer attacker can DoS the channel by injecting
//     an unprotected error status, since the host treats that as
//     tampering and closes.
//
// This test runs SCP11b end-to-end against mockcard and issues a
// command (INS=0x99, unrecognized) that the mock returns 6D00 for.
// With the fix in place: the error status is returned to the caller
// and the session stays open. Without the fix: Transmit would return
// "R-MAC verification failed" and Close the session.
func TestSCP11_ErrorStatusWord_NoMACVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	// Wrap mockcard's transport in a recording transport so we can
	// assert the response on the wire really does carry no R-MAC for
	// the error case, and only the SW for the unprotected error.
	rec := &errorPassThroughRecorder{inner: card.Transport()}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	sess, err := scp11.Open(ctx, rec, cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
	}

	// INS=0x99 is unrecognized by mockcard's processPlain switch and
	// will return SW=6D00. Unwrap MUST be skipped on this response.
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x00, INS: 0x99, P1: 0x00, P2: 0x00,
	})
	if err != nil {
		t.Fatalf("Transmit returned an error on a benign card error SW; the library "+
			"should pass it through, not treat it as MAC failure. Got: %v", err)
	}
	if resp == nil {
		t.Fatal("Transmit returned nil response with no error")
	}
	if resp.SW1 != 0x6D || resp.SW2 != 0x00 {
		t.Errorf("expected SW=6D00 from card; got %02X%02X", resp.SW1, resp.SW2)
	}

	// Critical post-condition: the session is STILL OPEN. The
	// previous behavior would have called Close() on an unwrap
	// failure; with the fix, an error SW is just an error SW.
	resp2, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x00, INS: 0xFD, P1: 0x00, P2: 0x00, Data: []byte{0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatalf("follow-up Transmit failed — session was incorrectly torn down "+
			"by the previous error response. Got: %v", err)
	}
	if resp2.SW1 != 0x90 || resp2.SW2 != 0x00 {
		t.Errorf("follow-up Transmit SW = %02X%02X, want 9000", resp2.SW1, resp2.SW2)
	}

	sess.Close()
}

// errorPassThroughRecorder forwards to an inner transport unchanged
// and exists only as a place to hang the SCP test machinery's
// expectations.
type errorPassThroughRecorder struct {
	inner transport.Transport
}

func (r *errorPassThroughRecorder) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return r.inner.Transmit(ctx, cmd)
}
func (r *errorPassThroughRecorder) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}
func (r *errorPassThroughRecorder) Close() error { return r.inner.Close() }

var _ transport.Transport = (*errorPassThroughRecorder)(nil)
var _ = errors.New // keep imports stable if we add error checks later

func (r *errorPassThroughRecorder) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
