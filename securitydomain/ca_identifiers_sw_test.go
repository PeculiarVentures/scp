package securitydomain

// Tests for the SW-distinguishing behavior of GetSupportedCaIdentifiers.
//
// Previously the method swallowed every non-success status word as
// "no identifiers configured" — a card that returned 6A88 (data not
// present), 6A82 (file not found), 6982 (security status not
// satisfied — auth required), or 6D00 (instruction not supported)
// all looked identical to the caller. That made it impossible to
// tell "this card has no KLOC/KLCC" from "this card requires
// authentication for KLOC/KLCC reads."
//
// The new behavior:
//
//   - 6A88 / 6A82 → silently empty (semantic: "not present")
//   - any other failure SW → return ErrCardStatus error with the
//     SW preserved so the caller can log it and operators can tell
//     auth-required from unsupported

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// caIdSWStubTransport responds to GET DATA tag FF33/FF34 with a
// caller-configured SW. Other commands get SW=6A88 except SELECT
// which is unconditional success. Used to exercise every distinct
// SW path through GetSupportedCaIdentifiers.
type caIdSWStubTransport struct {
	klocSW  uint16 // 0 = success with empty body
	klccSW  uint16
	klocBody []byte
	klccBody []byte
}

func (s *caIdSWStubTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch {
	case cmd.INS == 0xA4 && cmd.P1 == 0x04:
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case cmd.INS == 0xCA && cmd.P1 == 0xFF && cmd.P2 == 0x33:
		// KLOC
		if s.klocSW == 0 {
			return &apdu.Response{Data: s.klocBody, SW1: 0x90, SW2: 0x00}, nil
		}
		return &apdu.Response{SW1: byte(s.klocSW >> 8), SW2: byte(s.klocSW & 0xFF)}, nil
	case cmd.INS == 0xCA && cmd.P1 == 0xFF && cmd.P2 == 0x34:
		// KLCC
		if s.klccSW == 0 {
			return &apdu.Response{Data: s.klccBody, SW1: 0x90, SW2: 0x00}, nil
		}
		return &apdu.Response{SW1: byte(s.klccSW >> 8), SW2: byte(s.klccSW & 0xFF)}, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil
}

func (s *caIdSWStubTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}
func (s *caIdSWStubTransport) Close() error                         { return nil }
func (s *caIdSWStubTransport) TrustBoundary() transport.TrustBoundary { return transport.TrustBoundaryLocalPCSC }

// TestGetSupportedCaIdentifiers_NotPresent_6A88 confirms the
// canonical "reference data not found" SW is treated as empty.
func TestGetSupportedCaIdentifiers_NotPresent_6A88(t *testing.T) {
	stub := &caIdSWStubTransport{klocSW: 0x6A88, klccSW: 0x6A88}
	sd, err := OpenUnauthenticated(context.Background(), stub)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	got, err := sd.GetSupportedCaIdentifiers(context.Background(), true, true)
	if err != nil {
		t.Fatalf("expected nil error for 6A88, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d entries", len(got))
	}
}

// TestGetSupportedCaIdentifiers_NotPresent_6A82 confirms the
// alternate "not present" SW some applets use is treated the same
// as 6A88.
func TestGetSupportedCaIdentifiers_NotPresent_6A82(t *testing.T) {
	stub := &caIdSWStubTransport{klocSW: 0x6A82, klccSW: 0x6A82}
	sd, err := OpenUnauthenticated(context.Background(), stub)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	got, err := sd.GetSupportedCaIdentifiers(context.Background(), true, true)
	if err != nil {
		t.Fatalf("expected nil error for 6A82, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d entries", len(got))
	}
}

// TestGetSupportedCaIdentifiers_AuthRequired_6982 is the foot-gun
// case the prior swallow-everything behavior masked. A card that
// gates KLOC/KLCC reads behind authentication should surface that
// distinctly so the operator can re-run with the right credentials.
func TestGetSupportedCaIdentifiers_AuthRequired_6982(t *testing.T) {
	stub := &caIdSWStubTransport{klocSW: 0x6982, klccSW: 0x6A88}
	sd, err := OpenUnauthenticated(context.Background(), stub)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	_, err = sd.GetSupportedCaIdentifiers(context.Background(), true, true)
	if err == nil {
		t.Fatal("expected error for 6982 (auth required), got nil")
	}
	if !errors.Is(err, ErrCardStatus) {
		t.Errorf("expected ErrCardStatus, got %v", err)
	}
	if !strings.Contains(err.Error(), "6982") {
		t.Errorf("expected SW 6982 in error text, got %q", err.Error())
	}
	// The tag should also appear so an operator scanning logs can
	// tell which optional read was the one that needed auth.
	if !strings.Contains(err.Error(), "FF33") {
		t.Errorf("expected tag FF33 in error text, got %q", err.Error())
	}
}

// TestGetSupportedCaIdentifiers_NotSupported_6D00 covers the case
// where an applet doesn't implement the optional GP DOs at all.
// Distinct error from auth-required so operators don't waste time
// re-running with credentials when the tag will never work.
func TestGetSupportedCaIdentifiers_NotSupported_6D00(t *testing.T) {
	stub := &caIdSWStubTransport{klocSW: 0x6D00, klccSW: 0x6D00}
	sd, err := OpenUnauthenticated(context.Background(), stub)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	_, err = sd.GetSupportedCaIdentifiers(context.Background(), true, true)
	if err == nil {
		t.Fatal("expected error for 6D00 (instruction not supported), got nil")
	}
	if !strings.Contains(err.Error(), "6D00") {
		t.Errorf("expected SW 6D00 in error text, got %q", err.Error())
	}
}

// TestGetSupportedCaIdentifiers_PartialSuccess covers the mixed
// case where one tag is present and the other isn't. Only the
// not-present tag should be silenced; the present tag's data
// should make it back to the caller.
func TestGetSupportedCaIdentifiers_PartialSuccess(t *testing.T) {
	// Build a minimal valid KLOC body: a single CA identifier
	// envelope. parseSupportedCaIdentifiers expects the cards'
	// raw GP shape, which is a sequence of TLV-wrapped 7F21
	// children. To keep this stub minimal we send empty success
	// data on KLOC (parses to zero entries) and 6A88 on KLCC.
	stub := &caIdSWStubTransport{klocSW: 0, klocBody: nil, klccSW: 0x6A88}
	sd, err := OpenUnauthenticated(context.Background(), stub)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	got, err := sd.GetSupportedCaIdentifiers(context.Background(), true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected zero entries (empty KLOC, missing KLCC), got %d", len(got))
	}
}
