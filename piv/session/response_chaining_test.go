package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// TestTransmit_ResponseChaining_SingleStep covers the simplest chain
// case: card returns SW=6105 (5 more bytes available) on the first
// response, then 9000 with the remaining 5 bytes on GET RESPONSE.
// Caller must see one logical response with both halves concatenated
// and the final SW=9000.
func TestTransmit_ResponseChaining_SingleStep(t *testing.T) {
	first := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	rest := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xFE}

	tr := &chainTransport{
		responses: [][]byte{
			append(append([]byte{}, first...), 0x61, byte(len(rest))),
			append(append([]byte{}, rest...), 0x90, 0x00),
		},
	}
	s := &Session{tx: tr}

	resp, err := s.transmit(context.Background(), "TEST", &apdu.Command{INS: 0xCB})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}

	// Two APDUs sent: the original, then GET RESPONSE.
	if len(tr.sent) != 2 {
		t.Fatalf("sent %d APDUs, want 2", len(tr.sent))
	}
	if !isGetResponse(tr.sent[1]) {
		t.Errorf("second APDU not GET RESPONSE: %X", tr.sent[1])
	}

	want := append(append([]byte{}, first...), rest...)
	if string(resp.Data) != string(want) {
		t.Errorf("Data = %X, want %X", resp.Data, want)
	}
	if resp.StatusWord() != 0x9000 {
		t.Errorf("final SW = %04X, want 9000", resp.StatusWord())
	}
}

// TestTransmit_ResponseChaining_MultiStep verifies the loop runs more
// than once when the card keeps returning 61xx. ATTEST against a
// retail YubiKey 5.7+ does this — the cert chain is large enough to
// span several frames.
func TestTransmit_ResponseChaining_MultiStep(t *testing.T) {
	chunkA := []byte{0x01, 0x02, 0x03}
	chunkB := []byte{0x04, 0x05, 0x06}
	chunkC := []byte{0x07, 0x08, 0x09, 0x0A}

	tr := &chainTransport{
		responses: [][]byte{
			append(append([]byte{}, chunkA...), 0x61, byte(len(chunkB))),
			append(append([]byte{}, chunkB...), 0x61, byte(len(chunkC))),
			append(append([]byte{}, chunkC...), 0x90, 0x00),
		},
	}
	s := &Session{tx: tr}

	resp, err := s.transmit(context.Background(), "ATTEST", &apdu.Command{INS: 0xF9})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}

	// 3 APDUs sent: original, then two GET RESPONSEs.
	if len(tr.sent) != 3 {
		t.Fatalf("sent %d APDUs, want 3", len(tr.sent))
	}
	if !isGetResponse(tr.sent[1]) || !isGetResponse(tr.sent[2]) {
		t.Errorf("expected APDUs 2 and 3 to be GET RESPONSE; got %X, %X",
			tr.sent[1], tr.sent[2])
	}

	want := append(append(append([]byte{}, chunkA...), chunkB...), chunkC...)
	if string(resp.Data) != string(want) {
		t.Errorf("Data = %X, want %X", resp.Data, want)
	}
}

// TestTransmit_ResponseChaining_SW2Zero verifies the SW=6100 case
// (SW2 == 0 = "amount unspecified"). Le on the GET RESPONSE is 0,
// which the underlying transport interprets as "ask for the max".
// This is the exact symptom Ryan saw against the YubiKey: ATTEST
// returned SW=6100 and scpctl treated it as terminal.
func TestTransmit_ResponseChaining_SW2Zero(t *testing.T) {
	rest := []byte{0xAA, 0xBB, 0xCC}
	tr := &chainTransport{
		responses: [][]byte{
			{0x61, 0x00}, // SW=6100, no body, "ask GET RESPONSE for more"
			append(append([]byte{}, rest...), 0x90, 0x00),
		},
	}
	s := &Session{tx: tr}

	resp, err := s.transmit(context.Background(), "ATTEST", &apdu.Command{INS: 0xF9})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}

	if len(tr.sent) != 2 {
		t.Fatalf("sent %d APDUs, want 2", len(tr.sent))
	}
	getResp := tr.sent[1]
	// GET RESPONSE Le byte sits at the position determined by the
	// command's encoded length. For a no-data command with Le=0
	// the encoding is "00 C0 00 00 00".
	if !isGetResponse(getResp) {
		t.Errorf("APDU 2 not GET RESPONSE: %X", getResp)
	}
	if string(resp.Data) != string(rest) {
		t.Errorf("Data = %X, want %X", resp.Data, rest)
	}
}

// TestTransmit_ResponseChaining_ErrorFromGetResponse verifies that a
// transport error mid-chain is surfaced cleanly with the step number,
// and the caller doesn't see partial data presented as success.
func TestTransmit_ResponseChaining_ErrorFromGetResponse(t *testing.T) {
	tr := &chainTransport{
		responses: [][]byte{
			{0xDE, 0xAD, 0x61, 0x05},
		},
		errAfterIdx: 1, // error on the second Transmit call (the GET RESPONSE)
	}
	s := &Session{tx: tr}

	_, err := s.transmit(context.Background(), "ATTEST", &apdu.Command{INS: 0xF9})
	if err == nil {
		t.Fatal("transmit succeeded; wanted transport error")
	}
	if !strings.Contains(err.Error(), "GET RESPONSE") {
		t.Errorf("error doesn't mention GET RESPONSE: %v", err)
	}
}

// TestTransmit_ResponseChaining_RunawayCard pins the safety bound:
// a card that returns 61xx forever must not lock up the host. The
// chain loop has a finite step ceiling and reports it clearly.
func TestTransmit_ResponseChaining_RunawayCard(t *testing.T) {
	tr := &runawayTransport{}
	s := &Session{tx: tr}

	_, err := s.transmit(context.Background(), "ATTEST", &apdu.Command{INS: 0xF9})
	if err == nil {
		t.Fatal("transmit on runaway-card succeeded; expected step ceiling to fire")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error doesn't mention the step bound: %v", err)
	}
	if tr.calls > apdu.MaxResponseChainSteps+2 {
		t.Errorf("transport called %d times; ceiling failed to bound the loop",
			tr.calls)
	}
}

// TestTransmit_NoChain_PassthroughError confirms the chain wrapper
// doesn't change behavior for terminal non-success status words.
// SW=6A82 (file/applet not found) must still surface as a CardError.
func TestTransmit_NoChain_PassthroughError(t *testing.T) {
	tr := &chainTransport{
		responses: [][]byte{
			{0x6A, 0x82},
		},
	}
	s := &Session{tx: tr}

	_, err := s.transmit(context.Background(), "TEST", &apdu.Command{INS: 0xCB})
	if err == nil {
		t.Fatal("transmit on 6A82 succeeded; expected CardError")
	}
	if !strings.Contains(err.Error(), "6A82") {
		t.Errorf("error doesn't mention 6A82: %v", err)
	}
	// And exactly one APDU sent — no spurious GET RESPONSE for a
	// non-61xx final.
	if len(tr.sent) != 1 {
		t.Errorf("sent %d APDUs on 6A82, want 1", len(tr.sent))
	}
}

// chainTransport is a Transmitter that replays canned responses and
// records every APDU sent. errAfterIdx (1-based) makes the
// errAfterIdx-th call return a transport error instead of consulting
// responses[].
type chainTransport struct {
	responses   [][]byte
	idx         int
	sent        [][]byte
	errAfterIdx int
}

func (c *chainTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	c.sent = append(c.sent, encoded)
	if c.errAfterIdx > 0 && len(c.sent) >= c.errAfterIdx+1 {
		return nil, errors.New("simulated transport error")
	}
	if c.idx >= len(c.responses) {
		return nil, errors.New("chainTransport: out of canned responses")
	}
	raw := c.responses[c.idx]
	c.idx++
	return apdu.ParseResponse(raw)
}

func (c *chainTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	c.sent = append(c.sent, raw)
	if c.idx >= len(c.responses) {
		return nil, errors.New("chainTransport: out of canned responses")
	}
	resp := c.responses[c.idx]
	c.idx++
	return resp, nil
}

func (c *chainTransport) Close() error { return nil }
func (c *chainTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// runawayTransport always returns SW=6101 with one body byte. Used
// to verify the chain has a finite ceiling.
type runawayTransport struct {
	calls int
}

func (r *runawayTransport) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	r.calls++
	return apdu.ParseResponse([]byte{0xAA, 0x61, 0x01})
}

func (r *runawayTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	r.calls++
	return []byte{0xAA, 0x61, 0x01}, nil
}

func (r *runawayTransport) Close() error { return nil }
func (r *runawayTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// isGetResponse reports whether the encoded APDU is INS=0xC0 (GET
// RESPONSE). CLA, P1, P2 are checked too; production GET RESPONSE
// is always 00 C0 00 00 ...
func isGetResponse(encoded []byte) bool {
	if len(encoded) < 4 {
		return false
	}
	return encoded[0] == 0x00 && encoded[1] == 0xC0 && encoded[2] == 0x00 && encoded[3] == 0x00
}
