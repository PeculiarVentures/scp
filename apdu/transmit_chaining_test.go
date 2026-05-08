package apdu_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// TestTransmitWithChaining_NoChain confirms a one-shot 9000 response
// passes through unchanged with no extra APDUs sent. This is the
// path most APDUs take, so the helper must not be measurably more
// expensive than a raw Transmit when no chaining is needed.
func TestTransmitWithChaining_NoChain(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0xDE, 0xAD, 0x90, 0x00},
		},
	}
	resp, err := apdu.TransmitWithChaining(context.Background(), tr, &apdu.Command{INS: 0xCB})
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	if len(tr.sent) != 1 {
		t.Errorf("sent %d APDUs, want 1", len(tr.sent))
	}
	if string(resp.Data) != string([]byte{0xDE, 0xAD}) {
		t.Errorf("Data = %X, want DEAD", resp.Data)
	}
	if resp.StatusWord() != 0x9000 {
		t.Errorf("SW = %04X, want 9000", resp.StatusWord())
	}
}

// TestTransmitWithChaining_TwoSteps drives one GET RESPONSE round.
// The card returns SW=6105 with 4 bytes, then 9000 with 5 more bytes.
func TestTransmitWithChaining_TwoSteps(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x01, 0x02, 0x03, 0x04, 0x61, 0x05},
			{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x90, 0x00},
		},
	}
	resp, err := apdu.TransmitWithChaining(context.Background(), tr, &apdu.Command{INS: 0xF9})
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	if len(tr.sent) != 2 {
		t.Fatalf("sent %d APDUs, want 2", len(tr.sent))
	}

	// APDU 2 must be GET RESPONSE (00 C0 00 00 ..). Le carries
	// SW2 from the first response = 0x05.
	got := tr.sent[1]
	if got.CLA != 0x00 || got.INS != 0xC0 || got.P1 != 0x00 || got.P2 != 0x00 {
		t.Errorf("APDU 2 not GET RESPONSE: %+v", got)
	}
	if got.Le != 0x05 {
		t.Errorf("APDU 2 Le = %d, want 5 (from SW2 of first response)", got.Le)
	}

	want := []byte{0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	if string(resp.Data) != string(want) {
		t.Errorf("Data = %X, want %X", resp.Data, want)
	}
}

// TestTransmitWithChaining_SW2ZeroPasses verifies SW=6100 (SW2 = 0,
// "amount unspecified") flows through correctly. The next GET
// RESPONSE goes out with Le=0, which the wire layer interprets as
// "ask for the maximum".
func TestTransmitWithChaining_SW2ZeroPasses(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x61, 0x00},
			{0x42, 0x90, 0x00},
		},
	}
	_, err := apdu.TransmitWithChaining(context.Background(), tr, &apdu.Command{INS: 0xF9})
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	if tr.sent[1].Le != 0 {
		t.Errorf("GET RESPONSE Le = %d, want 0 (passthrough of SW2=0)", tr.sent[1].Le)
	}
}

// TestTransmitWithChaining_StepError surfaces a wire failure on the
// nth GET RESPONSE rather than returning partial data as success.
func TestTransmitWithChaining_StepError(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0xAA, 0x61, 0x05},
		},
		errOnCall: 2, // fail the second call (the GET RESPONSE)
	}
	_, err := apdu.TransmitWithChaining(context.Background(), tr, &apdu.Command{INS: 0xF9})
	if err == nil {
		t.Fatal("TransmitWithChaining succeeded; wanted wire error")
	}
	if !strings.Contains(err.Error(), "GET RESPONSE step 1") {
		t.Errorf("error doesn't identify the failing step: %v", err)
	}
}

// TestTransmitWithChaining_RunawayCard pins the safety bound. A card
// that returns 61xx forever must not lock up the host.
func TestTransmitWithChaining_RunawayCard(t *testing.T) {
	tr := &fakeTransmitter{
		// Every Transmit() returns one byte plus 6101 — the
		// fakeTransmitter hits its cycle-on-exhaust mode below.
		responses: [][]byte{
			{0x01, 0x61, 0x01},
		},
		cycleOnExhaust: true,
	}
	_, err := apdu.TransmitWithChaining(context.Background(), tr, &apdu.Command{INS: 0xF9})
	if err == nil {
		t.Fatal("TransmitWithChaining on runaway card succeeded; ceiling failed")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error doesn't mention the bound: %v", err)
	}
	if tr.calls > apdu.MaxResponseChainSteps+2 {
		t.Errorf("transport called %d times; ceiling failed to bound the loop", tr.calls)
	}
}

// fakeTransmitter records APDUs and replays canned response bytes.
// errOnCall is 1-based: first Transmit, second, etc. cycleOnExhaust
// makes the responses slice replay forever instead of failing once
// exhausted (used to model a runaway card).
type fakeTransmitter struct {
	responses      [][]byte
	idx            int
	calls          int
	sent           []*apdu.Command
	errOnCall      int
	cycleOnExhaust bool
}

func (f *fakeTransmitter) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	f.calls++
	f.sent = append(f.sent, cmd)
	if f.errOnCall > 0 && f.calls == f.errOnCall {
		return nil, errors.New("simulated wire error")
	}
	if f.idx >= len(f.responses) {
		if !f.cycleOnExhaust {
			return nil, errors.New("fakeTransmitter: out of canned responses")
		}
		f.idx = 0 // wrap
	}
	raw := f.responses[f.idx]
	f.idx++
	return apdu.ParseResponse(raw)
}

// TestTransmitWithChaining_6Cxx_RetriesWithCorrectedLe pins the
// behavior added for the 2012-vintage federal Gemalto PIV test card
// captured May 2026: empty-AID default-SELECT returned SW=6C67
// ("Le incorrect; correct length is 0x67 / 103 bytes"). The helper
// must retry the SAME command with Le=0x67 and surface the second
// response, not bail.
func TestTransmitWithChaining_6Cxx_RetriesWithCorrectedLe(t *testing.T) {
	// First response: SW=6C67, no data ("ask again with Le=0x67").
	// Second response: 103 bytes followed by 9000.
	body := make([]byte, 103)
	for i := range body {
		body[i] = byte(i ^ 0xA5)
	}
	resp2 := append(append([]byte(nil), body...), 0x90, 0x00)
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x6C, 0x67},
			resp2,
		},
	}
	cmd := &apdu.Command{INS: 0xA4, P1: 0x04, P2: 0x00, Le: 0}
	resp, err := apdu.TransmitWithChaining(context.Background(), tr, cmd)
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
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
	if string(resp.Data) != string(body) {
		t.Errorf("Data length = %d, want 103", len(resp.Data))
	}
}

// TestTransmitWithChaining_6C00_IsTreatedAs256: per ISO 7816-4 §5.3.4
// the 6Cxx hint byte 0x00 means 256 (max short-form Le), not zero.
// A retry with Le=0 would re-trigger the same situation; the helper
// must encode the hint correctly.
func TestTransmitWithChaining_6C00_IsTreatedAs256(t *testing.T) {
	body := make([]byte, 256)
	resp2 := append(append([]byte(nil), body...), 0x90, 0x00)
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x6C, 0x00},
			resp2,
		},
	}
	cmd := &apdu.Command{INS: 0xA4, P1: 0x04, P2: 0x00, Le: 0}
	if _, err := apdu.TransmitWithChaining(context.Background(), tr, cmd); err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	if got := tr.sent[1].Le; got != 256 {
		t.Errorf("retry Le = %d, want 256 (per ISO 7816-4 §5.3.4)", got)
	}
}

// TestTransmitWithChaining_6CxxThen61xx pins the composed case:
// the card responds 6Cxx to the original command, then on the
// Le-corrected retry responds 61xx, beginning a chain. Both
// recovery paths must compose without one shadowing the other.
func TestTransmitWithChaining_6CxxThen61xx(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x6C, 0x10},                         // original: wrong Le, hint 0x10
			{0xAA, 0xBB, 0xCC, 0xDD, 0x61, 0x03}, // retry: 4 bytes, 3 more pending
			{0xEE, 0xFF, 0x11, 0x90, 0x00},       // GET RESPONSE: final 3 bytes
		},
	}
	cmd := &apdu.Command{INS: 0xCA}
	resp, err := apdu.TransmitWithChaining(context.Background(), tr, cmd)
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	if len(tr.sent) != 3 {
		t.Fatalf("sent %d APDUs, want 3 (original + Le-retry + GET RESPONSE)", len(tr.sent))
	}
	if string(resp.Data) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11}) {
		t.Errorf("Data = %X, want concatenated AABBCCDDEEFF11", resp.Data)
	}
	if resp.StatusWord() != 0x9000 {
		t.Errorf("SW = %04X, want 9000", resp.StatusWord())
	}
}

// TestTransmitWithChaining_6Cxx_DoubleHintDoesNotLoop: a misbehaving
// card that responds 6Cxx twice in a row must NOT trigger an infinite
// loop. The helper retries once; if the second response is also 6Cxx
// (or anything other than 9000/61xx), it surfaces it as-is.
func TestTransmitWithChaining_6Cxx_DoubleHintDoesNotLoop(t *testing.T) {
	tr := &fakeTransmitter{
		responses: [][]byte{
			{0x6C, 0x10},
			{0x6C, 0x20}, // misbehaving: still claims wrong Le
		},
	}
	cmd := &apdu.Command{INS: 0xCA}
	resp, err := apdu.TransmitWithChaining(context.Background(), tr, cmd)
	if err != nil {
		t.Fatalf("TransmitWithChaining: %v", err)
	}
	// The second 6Cxx is surfaced to the caller — not retried again.
	if resp.StatusWord() != 0x6C20 {
		t.Errorf("SW = %04X, want 6C20 (passthrough of second hint)", resp.StatusWord())
	}
	if len(tr.sent) != 2 {
		t.Errorf("sent %d APDUs, want 2 (no infinite loop)", len(tr.sent))
	}
}
