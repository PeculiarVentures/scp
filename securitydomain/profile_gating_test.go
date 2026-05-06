package securitydomain

// Tests for Session.GenerateECKey profile gating.
//
// The GenerateECKey method now consults the session's active
// profile before emitting INS=0xF1 (Yubico GENERATE EC KEY).
// When the profile reports Capabilities().GenerateECKey == false
// (e.g. profile.Standard()), the method returns
// ErrUnsupportedByProfile without sending any APDU.
//
// These tests verify:
//
//   1. No profile set → no gating (backward compat)
//   2. YubiKey profile → permits GENERATE EC KEY
//   3. Standard profile → refuses with ErrUnsupportedByProfile
//      AND no APDU is sent (verified via a recording transport)

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
	"github.com/PeculiarVentures/scp/transport"
)

// f1RecordingTransport records every APDU it sees so tests can
// verify whether INS=0xF1 was emitted. Always returns SW=9000
// with empty data — sufficient for this test because we're
// asserting on what was sent, not on a real GENERATE response.
type f1RecordingTransport struct {
	sent []byte // INS bytes actually emitted
}

func (r *f1RecordingTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	r.sent = append(r.sent, cmd.INS)
	if cmd.INS == 0xA4 && cmd.P1 == 0x04 {
		// SELECT — let it succeed so OpenUnauthenticated returns.
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	}
	if cmd.INS == 0xF1 {
		// Synthesize a minimal GENERATE EC KEY response so the
		// caller's parse doesn't error if the gate is bypassed.
		// In the gated tests this branch must never run; in the
		// ungated test we want a realistic response.
		return &apdu.Response{SW1: 0x90, SW2: 0x00, Data: []byte{0xB0, 0x00}}, nil
	}
	return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
}
func (r *f1RecordingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}
func (r *f1RecordingTransport) Close() error { return nil }
func (r *f1RecordingTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryLocalPCSC
}
func (r *f1RecordingTransport) sentINS(ins byte) bool {
	for _, i := range r.sent {
		if i == ins {
			return true
		}
	}
	return false
}

// TestGenerateECKey_StandardProfile_RefusedBeforeAPDU is the
// foot-gun guard: the standard GP profile reports
// GenerateECKey: false, so calling Session.GenerateECKey on a
// session configured with that profile must return
// ErrUnsupportedByProfile WITHOUT emitting INS=0xF1 to the card.
func TestGenerateECKey_StandardProfile_RefusedBeforeAPDU(t *testing.T) {
	rec := &f1RecordingTransport{}
	sd, err := OpenUnauthenticated(context.Background(), rec)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()
	sd.SetProfile(profile.Standard())

	// Force authentication state so requireOCEAuth doesn't
	// short-circuit before the profile gate. (This test isolates
	// the profile gate from the auth gate; both are required for
	// real callers, but here we want to prove the profile gate
	// fires when reached.)
	sd.authenticated = true
	sd.authenticated = true
	sd.oceAuthenticated = true

	_, err = sd.GenerateECKey(context.Background(), NewKeyReference(0x11, 0x01), 0x00)
	if err == nil {
		t.Fatal("expected ErrUnsupportedByProfile, got nil")
	}
	if !errors.Is(err, profile.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if rec.sentINS(0xF1) {
		t.Errorf("INS=0xF1 emitted despite profile refusal; sent: %v", rec.sent)
	}
}

// TestGenerateECKey_YubiKeyProfile_Permitted is the positive
// case: the YubiKey profile claims GenerateECKey: true, so the
// method proceeds past the profile gate to the APDU emission.
func TestGenerateECKey_YubiKeyProfile_Permitted(t *testing.T) {
	rec := &f1RecordingTransport{}
	sd, err := OpenUnauthenticated(context.Background(), rec)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()
	sd.SetProfile(profile.YubiKey())
	sd.authenticated = true
	sd.oceAuthenticated = true

	// We don't care about the parse result here — only whether
	// the gate let the call through to the transport. The
	// recording transport emits a minimal stub response that
	// the parser may or may not accept; we only assert on the
	// INS byte going out.
	_, _ = sd.GenerateECKey(context.Background(), NewKeyReference(0x11, 0x01), 0x00)
	if !rec.sentINS(0xF1) {
		t.Errorf("expected INS=0xF1 emission under YubiKey profile; sent: %v", rec.sent)
	}
}

// TestGenerateECKey_NoProfile_BackwardCompat confirms that
// callers who haven't adopted the profile package see the
// pre-package behavior: no host-side gating, the APDU goes out
// regardless. This protects existing callers from a behavior
// regression on this commit.
func TestGenerateECKey_NoProfile_BackwardCompat(t *testing.T) {
	rec := &f1RecordingTransport{}
	sd, err := OpenUnauthenticated(context.Background(), rec)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()
	// No SetProfile call.
	sd.authenticated = true
	sd.oceAuthenticated = true

	_, _ = sd.GenerateECKey(context.Background(), NewKeyReference(0x11, 0x01), 0x00)
	if !rec.sentINS(0xF1) {
		t.Errorf("expected INS=0xF1 emission with no profile (backward compat); sent: %v",
			rec.sent)
	}
}

// TestSetProfile_Nil_ClearsGate confirms passing nil to
// SetProfile clears any previously-set profile, restoring
// no-gating behavior.
func TestSetProfile_Nil_ClearsGate(t *testing.T) {
	rec := &f1RecordingTransport{}
	sd, _ := OpenUnauthenticated(context.Background(), rec)
	defer sd.Close()
	sd.SetProfile(profile.Standard())
	sd.SetProfile(nil)
	if sd.Profile() != nil {
		t.Errorf("Profile() should return nil after SetProfile(nil)")
	}
}
