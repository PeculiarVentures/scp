package transport

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// chunkingTransport is a synthetic transport that always replies with
// "still more data" (61 xx) to drive TransmitCollectAll into the
// GET RESPONSE loop. It records how many calls have been made so the
// test can verify the iteration cap fires as expected.
type chunkingTransport struct {
	calls    int
	chunkLen int
}

func (c *chunkingTransport) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	c.calls++
	data := make([]byte, c.chunkLen)
	return &apdu.Response{Data: data, SW1: 0x61, SW2: 0xFF}, nil
}

func (c *chunkingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

func (c *chunkingTransport) Close() error { return nil }

// TestTransmitCollectAll_IterationCap confirms a card that keeps signaling
// "more data" forever cannot loop the host indefinitely.
func TestTransmitCollectAll_IterationCap(t *testing.T) {
	c := &chunkingTransport{chunkLen: 0}
	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x00}

	_, err := TransmitCollectAll(context.Background(), c, cmd)
	if err == nil {
		t.Fatal("expected error when card signals more data forever")
	}
	if !strings.Contains(err.Error(), "iterations") {
		t.Errorf("expected iteration-cap error, got: %v", err)
	}
	// The cap should fire by MaxGetResponseIterations + 1 calls (1 initial
	// + iterations of GET RESPONSE).
	if c.calls > MaxGetResponseIterations+2 {
		t.Errorf("transport invoked %d times; expected ~%d", c.calls, MaxGetResponseIterations+1)
	}
}

// TestTransmitCollectAll_ByteCap confirms a card that keeps returning
// large chunks cannot exhaust host memory via accumulated response data.
func TestTransmitCollectAll_ByteCap(t *testing.T) {
	// 8 KiB chunks; 1 MiB cap means ~128 chunks should suffice to trip it.
	c := &chunkingTransport{chunkLen: 8 * 1024}
	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x00}

	_, err := TransmitCollectAll(context.Background(), c, cmd)
	if err == nil {
		t.Fatal("expected error when accumulated response exceeds byte cap")
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("expected byte-cap error, got: %v", err)
	}
}

func (c *chunkingTransport) TrustBoundary() TrustBoundary { return TrustBoundaryUnknown }

// scriptedDrainTransport plays back a fixed list of responses
// in order, regardless of what command was sent. The test sets
// up the script with the initial 61xx responses followed by the
// final 9000 — DrainGetResponse should consume them all and
// return the assembled body.
type scriptedDrainTransport struct {
	responses []*apdu.Response
	calls     []*apdu.Command
}

func (s *scriptedDrainTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	s.calls = append(s.calls, cmd)
	if len(s.calls) > len(s.responses) {
		return nil, fmt.Errorf("scripted transport exhausted at call %d", len(s.calls))
	}
	return s.responses[len(s.calls)-1], nil
}

func (s *scriptedDrainTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

func (s *scriptedDrainTransport) Close() error                 { return nil }
func (s *scriptedDrainTransport) TrustBoundary() TrustBoundary { return TrustBoundaryUnknown }

// TestDrainGetResponse_NoOpOnFinalSW pins that DrainGetResponse
// returns the input unchanged when the initial response has a
// terminal SW (anything other than 61xx). No GET RESPONSE round
// trips are issued. This is the common case for SCP commands
// whose response fits in one APDU; the helper must be cheap.
func TestDrainGetResponse_NoOpOnFinalSW(t *testing.T) {
	tr := &scriptedDrainTransport{}
	initial := &apdu.Response{
		Data: []byte{0x01, 0x02, 0x03},
		SW1:  0x90,
		SW2:  0x00,
	}
	got, err := DrainGetResponse(context.Background(), tr, initial)
	if err != nil {
		t.Fatalf("DrainGetResponse: %v", err)
	}
	if got != initial {
		t.Errorf("expected unchanged input on terminal SW; got new pointer")
	}
	if len(tr.calls) != 0 {
		t.Errorf("expected zero round trips; got %d", len(tr.calls))
	}
}

// TestDrainGetResponse_AssemblesSplitPayload pins the central
// behavior: a card that returns SW=61xx + partial data forces
// the host to issue GET RESPONSE until the card signals 9000.
// All collected data must be concatenated in order. The bug
// this test guards against (SCP11b R-MAC failure on ATTEST,
// surfaced during YubiKey 5.7.4 hardware verification) was the
// session passing the partial first-chunk data to channel.Unwrap
// instead of waiting for the assembled payload.
func TestDrainGetResponse_AssemblesSplitPayload(t *testing.T) {
	chunkA := bytes.Repeat([]byte{0xAA}, 256)
	chunkB := bytes.Repeat([]byte{0xBB}, 256)
	chunkC := bytes.Repeat([]byte{0xCC}, 100)

	initial := &apdu.Response{Data: chunkA, SW1: 0x61, SW2: 0x80}
	tr := &scriptedDrainTransport{
		responses: []*apdu.Response{
			{Data: chunkB, SW1: 0x61, SW2: 0x10},
			{Data: chunkC, SW1: 0x90, SW2: 0x00},
		},
	}
	got, err := DrainGetResponse(context.Background(), tr, initial)
	if err != nil {
		t.Fatalf("DrainGetResponse: %v", err)
	}
	wantLen := len(chunkA) + len(chunkB) + len(chunkC)
	if len(got.Data) != wantLen {
		t.Errorf("assembled length = %d, want %d", len(got.Data), wantLen)
	}
	want := append(append([]byte(nil), chunkA...), append(chunkB, chunkC...)...)
	if !bytes.Equal(got.Data, want) {
		t.Errorf("assembled bytes mismatch (length matched but content differs)")
	}
	if got.SW1 != 0x90 || got.SW2 != 0x00 {
		t.Errorf("final SW = %02X%02X, want 9000", got.SW1, got.SW2)
	}
	if len(tr.calls) != 2 {
		t.Errorf("expected 2 GET RESPONSE calls (one per pending chunk); got %d", len(tr.calls))
	}
	for i, c := range tr.calls {
		if c.INS != 0xC0 {
			t.Errorf("call %d: INS = 0x%02X, want 0xC0 (GET RESPONSE)", i, c.INS)
		}
	}
}

// TestDrainGetResponse_IterationCap confirms a card that keeps
// signaling "more data" forever cannot loop the host indefinitely
// — same protection TransmitCollectAll provides, applied to the
// drain helper used by the SCP session paths.
func TestDrainGetResponse_IterationCap(t *testing.T) {
	c := &chunkingTransport{chunkLen: 0}
	initial := &apdu.Response{SW1: 0x61, SW2: 0xFF}
	_, err := DrainGetResponse(context.Background(), c, initial)
	if err == nil {
		t.Fatal("expected error when card signals more data forever")
	}
}

// scriptedTransport replays a list of canned responses in order
// and records all the commands sent through it. Used to drive
// TransmitCollectAll through specific 6Cxx and 6Cxx-then-61xx flows
// against a Treasury Gemalto-shaped fixture.
type scriptedTransport struct {
	responses []*apdu.Response
	idx       int
	sent      []*apdu.Command
}

func (s *scriptedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// Copy the command so later mutations by the helper don't change
	// what the test inspects.
	c := *cmd
	s.sent = append(s.sent, &c)
	if s.idx >= len(s.responses) {
		return nil, fmt.Errorf("scriptedTransport: out of canned responses")
	}
	r := s.responses[s.idx]
	s.idx++
	return r, nil
}

func (s *scriptedTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}
func (s *scriptedTransport) Close() error                 { return nil }
func (s *scriptedTransport) TrustBoundary() TrustBoundary { return TrustBoundaryUnknown }

// TestTransmitCollectAll_6Cxx_RetriesWithCorrectedLe is the
// regression for the 2012-vintage federal Gemalto PIV test card
// captured May 2026: empty-AID default-SELECT returned SW=6C67
// ("Le incorrect; correct length is 0x67 / 103 bytes"). Pre-fix,
// discovery aborted at 6C67 because openSelectAIDLiteral threaded
// any non-9000/non-6Axx SW up as a hard error. Post-fix, the
// helper retries with Le=0x67 and surfaces the second response.
func TestTransmitCollectAll_6Cxx_RetriesWithCorrectedLe(t *testing.T) {
	body := make([]byte, 103)
	for i := range body {
		body[i] = byte(i ^ 0xA5)
	}
	tr := &scriptedTransport{
		responses: []*apdu.Response{
			{SW1: 0x6C, SW2: 0x67}, // "wrong Le; correct is 0x67"
			{Data: body, SW1: 0x90, SW2: 0x00},
		},
	}
	cmd := &apdu.Command{INS: 0xA4, P1: 0x04, P2: 0x00, Le: 0}
	resp, err := TransmitCollectAll(context.Background(), tr, cmd)
	if err != nil {
		t.Fatalf("TransmitCollectAll: %v", err)
	}
	if len(tr.sent) != 2 {
		t.Fatalf("sent %d APDUs, want 2 (original + Le-corrected retry)", len(tr.sent))
	}
	if got := tr.sent[1].Le; got != 0x67 {
		t.Errorf("retry Le = %d, want 0x67 (103) per the SW2 hint", got)
	}
	if resp.StatusWord() != 0x9000 {
		t.Errorf("SW = %04X, want 9000", resp.StatusWord())
	}
	if !bytes.Equal(resp.Data, body) {
		t.Errorf("Data mismatch; len=%d want 103", len(resp.Data))
	}
}

// TestTransmitCollectAll_6C00_IsTreatedAs256: per ISO 7816-4 §5.3.4
// the 6Cxx hint byte 0x00 means 256 (max short-form Le), not zero.
// A retry with Le=0 would re-trigger the same situation; the helper
// must encode the hint correctly.
func TestTransmitCollectAll_6C00_IsTreatedAs256(t *testing.T) {
	body := make([]byte, 256)
	tr := &scriptedTransport{
		responses: []*apdu.Response{
			{SW1: 0x6C, SW2: 0x00},
			{Data: body, SW1: 0x90, SW2: 0x00},
		},
	}
	cmd := &apdu.Command{INS: 0xA4, P1: 0x04, P2: 0x00, Le: 0}
	if _, err := TransmitCollectAll(context.Background(), tr, cmd); err != nil {
		t.Fatalf("TransmitCollectAll: %v", err)
	}
	if got := tr.sent[1].Le; got != 256 {
		t.Errorf("retry Le = %d, want 256 (per ISO 7816-4 §5.3.4)", got)
	}
}

// TestTransmitCollectAll_6CxxThen61xx pins the composed case: the
// card returns 6Cxx originally, then 61xx on the retry, then 9000
// on the GET RESPONSE step. All three recovery paths must compose
// in order.
func TestTransmitCollectAll_6CxxThen61xx(t *testing.T) {
	tr := &scriptedTransport{
		responses: []*apdu.Response{
			{SW1: 0x6C, SW2: 0x10}, // wrong Le, hint 0x10
			{Data: []byte{0xAA, 0xBB, 0xCC, 0xDD}, SW1: 0x61, SW2: 0x03},
			{Data: []byte{0xEE, 0xFF, 0x11}, SW1: 0x90, SW2: 0x00},
		},
	}
	cmd := &apdu.Command{INS: 0xCA}
	resp, err := TransmitCollectAll(context.Background(), tr, cmd)
	if err != nil {
		t.Fatalf("TransmitCollectAll: %v", err)
	}
	if len(tr.sent) != 3 {
		t.Fatalf("sent %d APDUs, want 3 (original + Le-retry + GET RESPONSE)", len(tr.sent))
	}
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11}
	if !bytes.Equal(resp.Data, want) {
		t.Errorf("Data = %X, want %X", resp.Data, want)
	}
	if resp.StatusWord() != 0x9000 {
		t.Errorf("SW = %04X, want 9000", resp.StatusWord())
	}
}
