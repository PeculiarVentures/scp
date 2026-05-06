package securitydomain_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
func (*selectiveTransport) Close() error { return nil }
func (*selectiveTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

func TestDiscoverISD_FirstCandidateMatches(t *testing.T) {
	first := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	tt := &selectiveTransport{accept: [][]byte{first}}

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
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

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
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

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err == nil {
		t.Fatal("expected error when no candidate matches")
	}
	if !errors.Is(err, securitydomain.ErrNoISDFound) {
		t.Errorf("err = %v, want wrap of ErrNoISDFound", err)
	}
}

// TestDiscoverISD_NoneMatch_ErrorIncludesEachAID asserts the
// exhaustion-path error message is operator-actionable: it
// must list every AID that was attempted (so the operator
// knows what was tried), include each AID's SW, and point to
// --sd-aid as the next step. Reviewer item #4: "make the
// failure message point directly to --sd-aid and include the
// tried AIDs."
//
// We pin the literal phrases the operator would grep for in a
// support transcript, plus a hex check on each AID. If a future
// refactor changes the error wording, this test fails loudly so
// the audit-log shape stays predictable.
func TestDiscoverISD_NoneMatch_ErrorIncludesEachAID(t *testing.T) {
	tt := &selectiveTransport{accept: nil}

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()

	// Must mention --sd-aid by literal flag name so an operator
	// reading the message knows the next step without consulting
	// docs.
	if !strings.Contains(msg, "--sd-aid") {
		t.Errorf("error message must mention --sd-aid; got %q", msg)
	}
	// Must list each curated default AID by its hex
	// representation. Iterates ISDDiscoveryAIDs so adding a new
	// candidate in gp/discovery.go automatically extends what
	// this test asserts.
	for _, c := range gp.ISDDiscoveryAIDs {
		if c.AID == nil {
			// Empty SELECT should render as a recognizable token.
			if !strings.Contains(msg, "(empty SELECT)") {
				t.Errorf("error message must mention empty SELECT candidate; got %q", msg)
			}
			continue
		}
		hexStr := strings.ToUpper(hex.EncodeToString(c.AID))
		if !strings.Contains(strings.ToUpper(msg), hexStr) {
			t.Errorf("error message must include tried AID %s; got %q", hexStr, msg)
		}
	}
	// Must announce the count up front — automation parsing
	// the message can use this as an anchor.
	if !strings.Contains(msg, "tried ") || !strings.Contains(msg, " AIDs") {
		t.Errorf("error message must announce 'tried N AIDs'; got %q", msg)
	}
}

// TestDiscoverISD_NonRetryableSWAborts: a non-6A82 SW (e.g. 6985
// security state, 6982 conditions not satisfied) is real card
// behavior we should not silently retry against every other AID
// — it would mask a real problem.
func TestDiscoverISD_NonRetryableSWAborts(t *testing.T) {
	tt := &abortingTransport{sw: 0x6985}

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
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
func (*abortingTransport) Close() error { return nil }
func (*abortingTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// TestDiscoverISD_RealMockCardCompatible: end-to-end against the
// SCP03+GP combined mock, which currently answers 9000 to any
// SELECT. The default GP ISD AID (first candidate) matches.
func TestDiscoverISD_RealMockCardCompatible(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	sess, match, err := securitydomain.DiscoverISD(context.Background(), mc.Transport(), gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD against mock: %v", err)
	}
	defer sess.Close()
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(match.AID, want) {
		t.Errorf("matched AID = %X, want first candidate %X", match.AID, want)
	}
}

// TestDiscoverISD_LockedSDProducesErrLockedISD covers the 6283
// path. SW=6283 ("selected file/application invalidated") means
// the SD exists at this AID but is in TERMINATED/LOCKED state —
// distinct from "not found." Discovery aborts at this candidate
// rather than continue probing because the operator's discovery
// list is correct; the card needs out-of-band recovery.
func TestDiscoverISD_LockedSDProducesErrLockedISD(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000": {SW1: 0x62, SW2: 0x83}, // locked
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "GP-default"},
	}
	_, _, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, nil)
	if err == nil {
		t.Fatal("expected ErrLockedISD")
	}
	if !errors.Is(err, securitydomain.ErrLockedISD) {
		t.Errorf("err should wrap ErrLockedISD: %v", err)
	}
}

// TestDiscoverISD_6A87TreatedAsNotFound: SmartJac/SafeNet variants
// answer 6A87 instead of 6A82 when the AID is unknown. Discovery
// must continue to the next candidate rather than abort.
func TestDiscoverISD_6A87TreatedAsNotFound(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000":   {SW1: 0x6A, SW2: 0x87}, // SmartJac "not found" variant
			"select:A000000003000000": {SW1: 0x90, SW2: 0x00}, // matches the second candidate
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "GP-default"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, Source: "vendor-X"},
	}
	_, match, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, nil)
	if err != nil {
		t.Fatalf("DiscoverISD should fall through 6A87 to next candidate: %v", err)
	}
	if match.Source != "vendor-X" {
		t.Errorf("expected vendor-X match, got %q", match.Source)
	}
}

// TestDiscoverISD_TraceCallbackInvokedPerAttempt: the trace
// callback must fire for every probe, including the matching
// one (Selected=true). Lets a CLI emit per-AID diagnostic lines
// the reviewer asked for.
func TestDiscoverISD_TraceCallbackInvokedPerAttempt(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000":   {SW1: 0x6A, SW2: 0x82}, // not found
			"select:A000000018434D00": {SW1: 0x6A, SW2: 0x87}, // 6A87 variant
			"select:A000000003000000": {SW1: 0x90, SW2: 0x00}, // match
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "first"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00}, Source: "second"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, Source: "third"},
	}
	var attempts []securitydomain.DiscoveryAttempt
	trace := func(a securitydomain.DiscoveryAttempt) {
		attempts = append(attempts, a)
	}
	_, _, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, trace)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected 3 attempts traced, got %d", len(attempts))
	}
	// First two should be non-selected with their respective SWs.
	if attempts[0].Selected || attempts[0].SW != 0x6A82 {
		t.Errorf("attempt[0]: Selected=%v SW=%04X want false / 6A82", attempts[0].Selected, attempts[0].SW)
	}
	if attempts[1].Selected || attempts[1].SW != 0x6A87 {
		t.Errorf("attempt[1]: Selected=%v SW=%04X want false / 6A87", attempts[1].Selected, attempts[1].SW)
	}
	// Third should be the selected one.
	if !attempts[2].Selected || attempts[2].SW != 0x9000 {
		t.Errorf("attempt[2]: Selected=%v SW=%04X want true / 9000", attempts[2].Selected, attempts[2].SW)
	}
}

// scriptedTransport answers SELECT APDUs from a precomputed map
// keyed on "select:<aid-hex>". Used to drive DiscoverISD through
// specific SW responses without standing up a full mockcard.
type scriptedTransport struct {
	responses map[string]apdu.Response
}

func (s *scriptedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS != 0xA4 {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	key := fmt.Sprintf("select:%X", cmd.Data)
	if r, ok := s.responses[key]; ok {
		return &r, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil // default not-found
}

func (s *scriptedTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("scriptedTransport: TransmitRaw not implemented")
}
func (s *scriptedTransport) Close() error { return nil }
func (s *scriptedTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
