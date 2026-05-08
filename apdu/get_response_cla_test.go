package apdu

import (
	"context"
	"testing"
)

// TestGetResponseCLA pins the CLA bits that GET RESPONSE preserves
// from the originating command's CLA, per ISO 7816-4 §5.3.2 ("the
// CLA of the GET RESPONSE command shall reference the same logical
// channel as the preceding command").
//
// The two encodings the spec defines for logical channels need
// independent verification because the bit layouts differ:
//
//   - First-interindustry (CLA 0x00-0x3F) and proprietary (CLA
//     0x80-0xFE) encode channels 0-3 in CLA bits 0-1.
//
//   - Further-interindustry (CLA 0x40-0x7F) encodes channels 4-19
//     in CLA bits 0-3 (channel = 4 + bit_value).
//
// The reserved CLA 0xFF has no defined channel and we fall back to
// basic channel 0.
//
// The pre-2026 behavior hardcoded CLA=0x00 on every GET RESPONSE,
// which is correct for basic-channel commands (the typical case)
// and silently wrong for any logical channel. This test pins both
// the correctness for the typical case (basic channel 0) and the
// correctness for the cases the previous code broke (channels 1+).
func TestGetResponseCLA(t *testing.T) {
	cases := []struct {
		name    string
		prevCLA byte
		want    byte
	}{
		// First-interindustry, all four channels.
		{"first-interindustry channel 0", 0x00, 0x00},
		{"first-interindustry channel 1", 0x01, 0x01},
		{"first-interindustry channel 2", 0x02, 0x02},
		{"first-interindustry channel 3", 0x03, 0x03},

		// First-interindustry with secure messaging set; SM bit
		// (0x04 / 0x08 in this class) should NOT propagate.
		{"first-interindustry channel 0 + SM-bit-04", 0x04, 0x00},
		{"first-interindustry channel 0 + SM-bit-08", 0x08, 0x00},
		{"first-interindustry channel 0 + SM-bit-0C", 0x0C, 0x00},
		{"first-interindustry channel 1 + SM-bit-04", 0x05, 0x01},

		// First-interindustry with command chaining (0x10) set;
		// the chaining bit should NOT propagate.
		{"first-interindustry channel 0 + chaining", 0x10, 0x00},
		{"first-interindustry channel 2 + chaining + SM", 0x1E, 0x02},

		// Proprietary CLA (0x80-0xFE). GET RESPONSE on a proprietary
		// command's response is itself a STANDARD ISO 7816 command
		// and is encoded as first-interindustry. So a proprietary
		// CLA 0x80 yields GET RESPONSE CLA 0x00, not 0x80.
		{"proprietary 0x80 (basic channel)", 0x80, 0x00},
		{"proprietary 0x81 (channel 1)", 0x81, 0x01},
		{"proprietary 0x82 (channel 2)", 0x82, 0x02},
		{"proprietary 0x83 (channel 3)", 0x83, 0x03},
		{"proprietary 0x84 (channel 0 + SM)", 0x84, 0x00},
		{"YubiKey-typical 0x80 (basic, GP MANAGE CHANNEL)", 0x80, 0x00},

		// Further-interindustry, channels 4-19. The 0x40 class bit
		// stays set; the channel offset (bits 0-3) is preserved.
		{"further-interindustry channel 4", 0x40, 0x40},
		{"further-interindustry channel 5", 0x41, 0x41},
		{"further-interindustry channel 8", 0x44, 0x44},
		{"further-interindustry channel 19 (max)", 0x4F, 0x4F},

		// Further-interindustry with SM bit (0x20) and chaining
		// bit (0x10) set; neither propagates.
		{"further-interindustry channel 4 + SM", 0x60, 0x40},
		{"further-interindustry channel 8 + SM + chaining", 0x74, 0x44},

		// Reserved CLA: no defined channel.
		{"reserved 0xFF", 0xFF, 0x00},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GetResponseCLA(tc.prevCLA)
			if got != tc.want {
				t.Errorf("GetResponseCLA(%#02X) = %#02X, want %#02X",
					tc.prevCLA, got, tc.want)
			}
		})
	}
}

// TestNewGetResponseForCLA pins that the constructor produces
// CLA, INS, P1, P2, Le exactly as expected. The wire bytes here
// are what cards see; getting any byte wrong corrupts the
// continuation request.
func TestNewGetResponseForCLA(t *testing.T) {
	cases := []struct {
		cla, le byte
	}{
		{0x00, 0x00},
		{0x00, 0xFF},
		{0x01, 0x10},
		{0x40, 0x80},
		{0x4F, 0xFF},
	}
	for _, tc := range cases {
		cmd := NewGetResponseForCLA(tc.cla, tc.le)
		if cmd.CLA != tc.cla {
			t.Errorf("CLA(%#02X, %#02X): got CLA=%#02X, want %#02X",
				tc.cla, tc.le, cmd.CLA, tc.cla)
		}
		if cmd.INS != 0xC0 {
			t.Errorf("CLA(%#02X, %#02X): got INS=%#02X, want 0xC0",
				tc.cla, tc.le, cmd.INS)
		}
		if cmd.P1 != 0x00 || cmd.P2 != 0x00 {
			t.Errorf("CLA(%#02X, %#02X): got P1=%#02X P2=%#02X, want 0x00 0x00",
				tc.cla, tc.le, cmd.P1, cmd.P2)
		}
		if cmd.Le != int(tc.le) {
			t.Errorf("CLA(%#02X, %#02X): got Le=%d, want %d",
				tc.cla, tc.le, cmd.Le, tc.le)
		}
		if len(cmd.Data) != 0 {
			t.Errorf("CLA(%#02X, %#02X): got Data len=%d, want 0",
				tc.cla, tc.le, len(cmd.Data))
		}
	}
}

// TestNewGetResponse_BackwardCompatibility pins that the legacy
// constructor produces CLA=0x00 (basic channel), so callers that
// have not been updated to the CLA-aware variant get byte-identical
// pre-2026 behavior on basic-channel commands.
func TestNewGetResponse_BackwardCompatibility(t *testing.T) {
	cmd := NewGetResponse(0x42)
	if cmd.CLA != 0x00 {
		t.Errorf("NewGetResponse(0x42): got CLA=%#02X, want 0x00 (legacy basic-channel default)", cmd.CLA)
	}
	if cmd.Le != 0x42 {
		t.Errorf("NewGetResponse(0x42): got Le=%d, want 66", cmd.Le)
	}
}

// TestTransmitWithChaining_PreservesChannelInGetResponse pins the
// load-bearing assertion: when an originating command rides on a
// non-zero logical channel, every GET RESPONSE the chaining loop
// emits MUST carry the same channel reference. Pre-2026 behavior
// hardcoded CLA=0x00 here, which a real card on logical channel 1+
// would either reject (referenced channel not active) or, worse,
// silently route to channel 0 — the kind of cross-channel bug the
// CLA-encoding helper exists to prevent.
//
// The script is the smallest one that exercises the bug:
//
//  1. Issue the originating command on channel 1 (CLA=0x01).
//  2. Card returns 6103 (3 more bytes available).
//  3. Issue GET RESPONSE — must be CLA=0x01, not 0x00.
//  4. Card returns the 3 bytes plus 9000.
//
// The fixture's script-driven Transmit asserts the GET RESPONSE
// CLA inline; if the chaining loop forgot to thread CLA, the
// assertion fires and the test fails with a clear message.
func TestTransmitWithChaining_PreservesChannelInGetResponse(t *testing.T) {
	cases := []struct {
		name string
		cla  byte
	}{
		{"basic channel (regression for the legacy default)", 0x00},
		{"first-interindustry channel 1", 0x01},
		{"first-interindustry channel 3 (max for first-interindustry)", 0x03},
		{"further-interindustry channel 4", 0x40},
		{"further-interindustry channel 19 (max)", 0x4F},
		// Proprietary CLA: GET RESPONSE goes out as first-
		// interindustry (CLA=0x00 for channel 0). This pins that
		// proprietary doesn't echo back on the GET RESPONSE.
		{"proprietary 0x80 (channel 0)", 0x80},
		{"proprietary 0x81 (channel 1)", 0x81},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectedGetRespCLA := GetResponseCLA(tc.cla)
			tx := &chainScriptedTransmitter{
				t:                  t,
				expectedGetRespCLA: expectedGetRespCLA,
				// Originating command response: 3 bytes + SW=6103
				// (3 more bytes pending).
				responses: []*Response{
					{Data: []byte{0xAA, 0xBB, 0xCC}, SW1: 0x61, SW2: 0x03},
					// GET RESPONSE: final 3 bytes + 9000.
					{Data: []byte{0xDD, 0xEE, 0xFF}, SW1: 0x90, SW2: 0x00},
				},
			}
			cmd := &Command{CLA: tc.cla, INS: 0xCA, P1: 0x00, P2: 0x66, Le: 0}
			resp, err := TransmitWithChaining(context.Background(), tx, cmd)
			if err != nil {
				t.Fatalf("TransmitWithChaining: %v", err)
			}
			wantBody := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
			if string(resp.Data) != string(wantBody) {
				t.Errorf("body = %X, want %X", resp.Data, wantBody)
			}
			if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
				t.Errorf("SW = %02X%02X, want 9000", resp.SW1, resp.SW2)
			}
		})
	}
}

// chainScriptedTransmitter is a minimal Transmitter that asserts
// every GET RESPONSE (INS=0xC0) carries the expected CLA, then
// returns the next scripted response.
type chainScriptedTransmitter struct {
	t                  *testing.T
	expectedGetRespCLA byte
	responses          []*Response
	calls              int
}

func (s *chainScriptedTransmitter) Transmit(_ context.Context, cmd *Command) (*Response, error) {
	defer func() { s.calls++ }()
	// Skip the originating command (calls == 0); only assert the
	// GET RESPONSE CLA bytes (calls >= 1).
	if s.calls > 0 {
		if cmd.INS != 0xC0 {
			s.t.Errorf("call %d: expected GET RESPONSE (INS=0xC0), got INS=%#02X",
				s.calls, cmd.INS)
		}
		if cmd.CLA != s.expectedGetRespCLA {
			s.t.Errorf("call %d: GET RESPONSE CLA = %#02X, want %#02X",
				s.calls, cmd.CLA, s.expectedGetRespCLA)
		}
	}
	if s.calls >= len(s.responses) {
		s.t.Fatalf("script exhausted at call %d (had %d scripted responses)",
			s.calls, len(s.responses))
	}
	return s.responses[s.calls], nil
}
