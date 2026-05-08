package transport

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// TestTransmitCollectAll_PreservesChannelInGetResponse pins that
// TransmitCollectAll's response-chaining path (introduced in #159
// for 6Cxx + 61xx composability) emits GET RESPONSE on the same
// channel as the originating command. Before the post-2026 CLA
// preservation fix, every GET RESPONSE here went out on basic
// channel 0, regardless of the originating command's channel — a
// silent cross-channel routing bug that current GP/PIV flows don't
// hit because they don't use logical channels but that any future
// caller would.
func TestTransmitCollectAll_PreservesChannelInGetResponse(t *testing.T) {
	cases := []struct {
		name string
		cla  byte
	}{
		{"basic channel (regression for the legacy default)", 0x00},
		{"first-interindustry channel 1", 0x01},
		{"further-interindustry channel 4", 0x40},
		{"further-interindustry channel 19 (max)", 0x4F},
		{"proprietary 0x81 (channel 1)", 0x81},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectedGetRespCLA := apdu.GetResponseCLA(tc.cla)
			tr := &chainScriptedTransport{
				t:                  t,
				expectedGetRespCLA: expectedGetRespCLA,
				responses: []*apdu.Response{
					// Originating command response: data + 6103.
					{Data: []byte{0xAA, 0xBB, 0xCC}, SW1: 0x61, SW2: 0x03},
					// GET RESPONSE: final 3 bytes + 9000.
					{Data: []byte{0xDD, 0xEE, 0xFF}, SW1: 0x90, SW2: 0x00},
				},
			}
			cmd := &apdu.Command{CLA: tc.cla, INS: 0xCA, P1: 0x00, P2: 0x66, Le: 0}
			resp, err := TransmitCollectAll(context.Background(), tr, cmd)
			if err != nil {
				t.Fatalf("TransmitCollectAll: %v", err)
			}
			wantBody := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
			if string(resp.Data) != string(wantBody) {
				t.Errorf("body = %X, want %X", resp.Data, wantBody)
			}
		})
	}
}

// TestDrainGetResponseForCLA pins the parallel assertion for the
// raw drain path used by scp03/scp11 Transmit (where GET RESPONSE
// must run on the underlying transport rather than through the
// secure channel).
func TestDrainGetResponseForCLA(t *testing.T) {
	cases := []struct {
		name string
		cla  byte
	}{
		{"basic channel", 0x00},
		{"first-interindustry channel 2", 0x02},
		{"further-interindustry channel 8", 0x44},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectedGetRespCLA := apdu.GetResponseCLA(tc.cla)
			tr := &chainScriptedTransport{
				t:                  t,
				expectedGetRespCLA: expectedGetRespCLA,
				responses: []*apdu.Response{
					// Only GET RESPONSE here; the drain takes an
					// already-issued initial response.
					{Data: []byte{0x99}, SW1: 0x90, SW2: 0x00},
				},
			}
			initial := &apdu.Response{
				Data: []byte{0x88},
				SW1:  0x61,
				SW2:  0x01,
			}
			resp, err := DrainGetResponseForCLA(context.Background(), tr, expectedGetRespCLA, initial)
			if err != nil {
				t.Fatalf("DrainGetResponseForCLA: %v", err)
			}
			if string(resp.Data) != "\x88\x99" {
				t.Errorf("body = %X, want 8899", resp.Data)
			}
			if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
				t.Errorf("SW = %02X%02X, want 9000", resp.SW1, resp.SW2)
			}
		})
	}
}

// TestDrainGetResponse_BackwardCompatibility pins that the legacy
// DrainGetResponse (no CLA argument) still issues GET RESPONSE on
// basic channel 0. Existing callers continue to get byte-identical
// pre-2026 behavior on basic-channel commands.
func TestDrainGetResponse_BackwardCompatibility(t *testing.T) {
	tr := &chainScriptedTransport{
		t:                  t,
		expectedGetRespCLA: 0x00, // legacy default
		responses: []*apdu.Response{
			{Data: []byte{0x99}, SW1: 0x90, SW2: 0x00},
		},
	}
	initial := &apdu.Response{
		Data: []byte{0x88},
		SW1:  0x61,
		SW2:  0x01,
	}
	resp, err := DrainGetResponse(context.Background(), tr, initial)
	if err != nil {
		t.Fatalf("DrainGetResponse: %v", err)
	}
	if string(resp.Data) != "\x88\x99" {
		t.Errorf("body = %X, want 8899", resp.Data)
	}
}

// chainScriptedTransport is a Transport that asserts every
// GET RESPONSE (INS=0xC0) carries the expected CLA, then returns
// the next scripted response. Originating command (calls == 0) is
// not asserted because the test fixture sets cmd.CLA explicitly.
type chainScriptedTransport struct {
	t                  *testing.T
	expectedGetRespCLA byte
	responses          []*apdu.Response
	calls              int
}

func (s *chainScriptedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	defer func() { s.calls++ }()
	// Skip the originating command (calls == 0); only assert
	// GET RESPONSE bytes (calls >= 1) — but for DrainGetResponse
	// the caller passes the initial response in directly, so
	// calls == 0 is already a GET RESPONSE there.
	if cmd.INS == 0xC0 {
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

func (s *chainScriptedTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	s.t.Fatalf("TransmitRaw not used in this test")
	return nil, nil
}
func (s *chainScriptedTransport) Close() error                 { return nil }
func (s *chainScriptedTransport) TrustBoundary() TrustBoundary { return TrustBoundaryUnknown }
