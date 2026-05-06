package securitydomain_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// selectiveTransport answers SELECT only for AIDs in the accept
// set; everything else returns SW=6A82. Covers DiscoverISD's
// retry-on-6A82 path against a controlled fixture rather than
// the full mockcard stack.
type selectiveTransport struct {
	accept [][]byte
}

func (t *selectiveTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS != 0xA4 {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	for _, a := range t.accept {
		if bytes.Equal(a, cmd.Data) {
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		}
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil
}

func (t *selectiveTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*selectiveTransport) Close() error                          { return nil }
func (*selectiveTransport) TrustBoundary() transport.TrustBoundary { return transport.TrustBoundaryUnknown }

func TestDiscoverISD_FirstCandidateMatches(t *testing.T) {
	first := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	tt := &selectiveTransport{accept: [][]byte{first}}

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	defer sess.Close()
	if !bytes.Equal(match.AID, first) {
		t.Errorf("matched AID = %X, want %X", match.AID, first)
	}
}

func TestDiscoverISD_FallsThroughToSecondCandidate(t *testing.T) {
	// Only accept the second AID in ISDDiscoveryAIDs.
	second := gp.ISDDiscoveryAIDs[1].AID
	tt := &selectiveTransport{accept: [][]byte{second}}

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	defer sess.Close()
	if !bytes.Equal(match.AID, second) {
		t.Errorf("matched AID = %X, want %X (second candidate)", match.AID, second)
	}
}

func TestDiscoverISD_NoneMatch_ReturnsSentinel(t *testing.T) {
	tt := &selectiveTransport{accept: nil} // accepts nothing

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs)
	if err == nil {
		t.Fatal("expected error when no candidate matches")
	}
	if !errors.Is(err, securitydomain.ErrNoISDFound) {
		t.Errorf("err = %v, want wrap of ErrNoISDFound", err)
	}
}

// TestDiscoverISD_NonRetryableSWAborts: a non-6A82 SW (e.g. 6985
// security state, 6982 conditions not satisfied) is real card
// behavior we should not silently retry against every other AID
// — it would mask a real problem.
func TestDiscoverISD_NonRetryableSWAborts(t *testing.T) {
	tt := &abortingTransport{sw: 0x6985}

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs)
	if err == nil {
		t.Fatal("expected non-6A82 SW to abort discovery")
	}
	if errors.Is(err, securitydomain.ErrNoISDFound) {
		t.Errorf("non-6A82 should NOT surface as ErrNoISDFound: %v", err)
	}
	var ae *securitydomain.APDUError
	if !errors.As(err, &ae) || ae.SW != 0x6985 {
		t.Errorf("err should wrap APDUError with SW=6985: %v", err)
	}
	if tt.calls > 1 {
		t.Errorf("non-6A82 should abort after first probe; got %d calls", tt.calls)
	}
}

// abortingTransport returns the configured SW for every SELECT.
type abortingTransport struct {
	sw    uint16
	calls int
}

func (t *abortingTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS == 0xA4 {
		t.calls++
		return &apdu.Response{SW1: byte(t.sw >> 8), SW2: byte(t.sw)}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}
func (t *abortingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*abortingTransport) Close() error                          { return nil }
func (*abortingTransport) TrustBoundary() transport.TrustBoundary { return transport.TrustBoundaryUnknown }

// TestDiscoverISD_RealMockCardCompatible: end-to-end against the
// SCP03+GP combined mock, which currently answers 9000 to any
// SELECT. The default GP ISD AID (first candidate) matches.
func TestDiscoverISD_RealMockCardCompatible(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	sess, match, err := securitydomain.DiscoverISD(context.Background(), mc.Transport(), gp.ISDDiscoveryAIDs)
	if err != nil {
		t.Fatalf("DiscoverISD against mock: %v", err)
	}
	defer sess.Close()
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(match.AID, want) {
		t.Errorf("matched AID = %X, want first candidate %X", match.AID, want)
	}
}
