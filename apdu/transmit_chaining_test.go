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
