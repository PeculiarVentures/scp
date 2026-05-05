package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
)

// TestBlockPIN_HappyPath_YubiKeyProfile pins the contract that
// BlockPIN exhausts the mock's 3-retry counter and returns 3.
// Also verifies it fails further VERIFY PIN attempts (the card
// is now in the "blocked" state).
func TestBlockPIN_HappyPath_YubiKeyProfile(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	attempts, err := sess.BlockPIN(context.Background(), 16)
	if err != nil {
		t.Fatalf("BlockPIN: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 wrong-PIN attempts (mock starts with 3 retries); got %d", attempts)
	}

	// Once PIN is blocked the correct PIN no longer works either.
	if err := sess.VerifyPIN(context.Background(), []byte("123456")); err == nil {
		t.Error("VerifyPIN with the right PIN should fail after BlockPIN — card is locked out")
	}
}

// TestBlockPIN_RefusedByStandardPIV ensures BlockPIN refuses
// under profiles that don't advertise Reset, since PIN-blocking
// without a follow-up reset path leaves the card unrecoverable.
// No APDU should hit the wire on profile refusal.
func TestBlockPIN_RefusedByStandardPIV(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	attempts, err := sess.BlockPIN(context.Background(), 16)
	if err == nil {
		t.Fatal("expected refusal under Standard PIV profile")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if attempts != 0 {
		t.Errorf("expected zero attempts on profile refusal; got %d", attempts)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs on profile refusal; got %d", got)
	}
}

// TestBlockPIN_ZeroMaxAttempts pins the input validation. A
// caller that passes maxAttempts=0 (often a bug — uninitialized
// integer) should get a clear error rather than silent success
// with zero attempts.
func TestBlockPIN_ZeroMaxAttempts(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	if _, err := sess.BlockPIN(context.Background(), 0); err == nil {
		t.Fatal("expected error for maxAttempts=0")
	}
}

// TestBlockPUK_HappyPath_YubiKeyProfile is the BlockPUK twin of
// TestBlockPIN_HappyPath_YubiKeyProfile.
func TestBlockPUK_HappyPath_YubiKeyProfile(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	attempts, err := sess.BlockPUK(context.Background(), 16)
	if err != nil {
		t.Fatalf("BlockPUK: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 wrong-PUK attempts (mock starts with 3 retries); got %d", attempts)
	}
}

// TestBlockPUK_RefusedByStandardPIV mirrors the BlockPIN refusal
// test for PUK.
func TestBlockPUK_RefusedByStandardPIV(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	attempts, err := sess.BlockPUK(context.Background(), 16)
	if err == nil {
		t.Fatal("expected refusal under Standard PIV profile")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if attempts != 0 {
		t.Errorf("expected zero attempts on profile refusal; got %d", attempts)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs on profile refusal; got %d", got)
	}
}

// TestBlockPIN_ThenBlockPUK_ThenReset is the full block-then-reset
// sequence that 'scpctl piv reset' performs against a real
// YubiKey. Pins the contract that BlockPIN + BlockPUK together
// satisfy the YubiKey precondition for INS=0xFB (PIV reset),
// which is the regression that motivated adding these methods.
//
// Without this contract, a future change that, say, makes
// BlockPIN succeed without actually exhausting the counter would
// leave Reset failing with SW=6985 in production while tests
// stay green.
func TestBlockPIN_ThenBlockPUK_ThenReset(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	if _, err := sess.BlockPIN(context.Background(), 16); err != nil {
		t.Fatalf("BlockPIN: %v", err)
	}
	if _, err := sess.BlockPUK(context.Background(), 16); err != nil {
		t.Fatalf("BlockPUK: %v", err)
	}
	if err := sess.Reset(context.Background(), ResetOptions{}); err != nil {
		t.Fatalf("Reset after block PIN/PUK should succeed; got %v", err)
	}

	// After Reset, the auth state should be cleared.
	if sess.PINVerified() {
		t.Error("PINVerified should be false after Reset")
	}
	if sess.MgmtKeyAuthenticated() {
		t.Error("MgmtKeyAuthenticated should be false after Reset")
	}
}

// TestReset_WithoutBlock_FailsLikeYubiKey is the negative case:
// without first blocking PIN and PUK, Reset against the mock
// produces an error mirroring the YubiKey SW=6985 behavior. This
// pins the documented precondition: callers are expected to use
// BlockPIN + BlockPUK before Reset, or already know the card is
// in the blocked state.
func TestReset_WithoutBlock_FailsLikeYubiKey(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	err := sess.Reset(context.Background(), ResetOptions{})
	if err == nil {
		t.Fatal("expected Reset to fail when PIN/PUK are not blocked (mock returns 6985)")
	}
	if !strings.Contains(err.Error(), "6985") && !strings.Contains(err.Error(), "RESET") {
		t.Errorf("error should reference 6985 or RESET path; got %v", err)
	}
}
