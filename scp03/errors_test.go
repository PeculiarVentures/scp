package scp03_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
)

// TestErrInvalidConfig_NilConfig confirms passing a nil Config to
// scp03.Open returns an error that errors.Is matches as
// ErrInvalidConfig. The descriptive message is preserved alongside
// the sentinel chain.
func TestErrInvalidConfig_NilConfig(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	_, err := scp03.Open(context.Background(), card.Transport(), nil)
	if err == nil {
		t.Fatal("expected error for nil Config; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
	// The descriptive substring should still appear so logs and
	// debug output remain useful.
	if !strings.Contains(err.Error(), "Config is required") {
		t.Errorf("error should retain descriptive context; got: %v", err)
	}
}

// TestErrInvalidConfig_NilTransport confirms a missing transport is
// reported as ErrInvalidConfig, matching the rest of the caller-error
// category.
func TestErrInvalidConfig_NilTransport(t *testing.T) {
	_, err := scp03.Open(context.Background(), nil, &scp03.Config{Keys: scp03.DefaultKeys})
	if err == nil {
		t.Fatal("expected error for nil transport; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestErrInvalidConfig_KeysizeMismatch confirms a Config with
// inconsistent key lengths is reported as ErrInvalidConfig.
func TestErrInvalidConfig_KeysizeMismatch(t *testing.T) {
	bad := scp03.StaticKeys{
		ENC: make([]byte, 16),
		MAC: make([]byte, 32), // mismatched
		DEK: make([]byte, 16),
	}
	card := scp03.NewMockCard(scp03.DefaultKeys)
	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{Keys: bad})
	if err == nil {
		t.Fatal("expected error for mismatched key lengths; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestErrAuthFailed_WrongKeys confirms a handshake against a card
// that holds a different key set is reported as ErrAuthFailed,
// distinct from ErrInvalidConfig and ErrInvalidResponse. Mirrors the
// pattern in TestSCP03_WrongKeys but adds the errors.Is assertion.
func TestErrAuthFailed_WrongKeys(t *testing.T) {
	// The mock card holds the well-known DefaultKeys (0x40..0x4F).
	card := scp03.NewMockCard(scp03.DefaultKeys)

	// The caller authenticates with a different key set, well-formed
	// but not matching the card.
	wrongKeys := scp03.StaticKeys{
		ENC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		MAC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		DEK: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	}
	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: wrongKeys,
	})
	if err == nil {
		t.Fatal("expected error for wrong keys; got nil")
	}
	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}
	if errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("ErrAuthFailed must not be confused with ErrInvalidConfig; err = %v", err)
	}
}

// TestSentinelsAreDistinct guards against accidentally aliasing two
// sentinels to the same value, which would defeat the whole point of
// having distinct categories.
func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{scp03.ErrAuthFailed, scp03.ErrInvalidConfig, scp03.ErrInvalidResponse}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels at index %d and %d compare equal: %v == %v", i, j, a, b)
			}
		}
	}
}

// TestCryptogramMismatchError_FieldsAndError pins the new rich
// auth-failure shape. Builds a CryptogramMismatchError directly,
// asserts that the bytes round-trip on the value, that errors.Is
// against ErrAuthFailed succeeds (so existing callers using
// errors.Is(err, ErrAuthFailed) continue to match), and that the
// rendered Error() string carries both bytes plus the brick-risk
// warning so log lines stay informative.
func TestCryptogramMismatchError_FieldsAndError(t *testing.T) {
	cm := &scp03.CryptogramMismatchError{
		Expected: []byte{0xB2, 0xF3, 0x92, 0xD2, 0xCF, 0xB9, 0xA4, 0x59},
		Received: []byte{0x76, 0x53, 0x2D, 0x72, 0xCF, 0x9D, 0xE0, 0x5F},
	}

	// errors.Is via ErrAuthFailed.
	if !errors.Is(cm, scp03.ErrAuthFailed) {
		t.Errorf("CryptogramMismatchError should errors.Is as ErrAuthFailed")
	}

	// errors.As against the concrete type for byte recovery.
	var got *scp03.CryptogramMismatchError
	if !errors.As(error(cm), &got) {
		t.Fatal("errors.As should recover the concrete type")
	}
	if string(got.Expected) != string(cm.Expected) {
		t.Errorf("Expected bytes mismatch: got %X want %X", got.Expected, cm.Expected)
	}
	if string(got.Received) != string(cm.Received) {
		t.Errorf("Received bytes mismatch: got %X want %X", got.Received, cm.Received)
	}

	// Rendered message must include both bytes (uppercase hex,
	// matching gppro) and the brick-risk warning.
	msg := cm.Error()
	for _, want := range []string{
		"B2F392D2CFB9A459", // expected
		"76532D72CF9DE05F", // received
		"Do not re-try",
		"counter",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() missing %q; got:\n%s", want, msg)
		}
	}
}

// TestCryptogramMismatchError_IsThroughWrap confirms the type
// continues to satisfy errors.Is(err, ErrAuthFailed) when wrapped
// behind another error in a fmt.Errorf %w chain. Pre-fix the
// callsite produced fmt.Errorf("%w: ...", ErrAuthFailed); post-fix
// it returns *CryptogramMismatchError directly. Both should
// behave the same for downstream callers using errors.Is.
func TestCryptogramMismatchError_IsThroughWrap(t *testing.T) {
	cm := &scp03.CryptogramMismatchError{
		Expected: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Received: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
	}
	wrapped := fmt.Errorf("opening session: %w", cm)

	if !errors.Is(wrapped, scp03.ErrAuthFailed) {
		t.Errorf("wrapped CryptogramMismatchError should errors.Is as ErrAuthFailed")
	}

	var got *scp03.CryptogramMismatchError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As should still recover the concrete type through wrap")
	}
	if got.Received[0] != 0x10 {
		t.Errorf("byte recovery failed through wrap: got %X", got.Received)
	}
}

// TestOpen_WrongKeys_SurfacesCryptogramBytes is the integration-
// level check. Drives a real handshake against the SCP03 mock with
// deliberately-wrong host keys. The mock's INITIALIZE UPDATE
// response includes a card cryptogram derived from the mock's
// configured (correct) keys; the host computes its own cryptogram
// from the wrong keys; the mismatch surfaces as a
// CryptogramMismatchError carrying both byte sequences.
func TestOpen_WrongKeys_SurfacesCryptogramBytes(t *testing.T) {
	// The mock card is configured with DefaultKeys.
	card := scp03.NewMockCard(scp03.DefaultKeys)

	// The host opens with a different key set. Both have to be
	// AES-128 (or all the same length) since scp03.Open enforces
	// uniform key length.
	wrongKeys := scp03.StaticKeys{
		ENC: bytes16(0xAA),
		MAC: bytes16(0xBB),
		DEK: bytes16(0xCC),
	}

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: wrongKeys,
	})
	if err == nil {
		t.Fatal("expected auth failure with mismatched keys; got nil")
	}

	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}

	var cm *scp03.CryptogramMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("errors.As should recover *CryptogramMismatchError; err = %v", err)
	}
	if len(cm.Expected) == 0 || len(cm.Received) == 0 {
		t.Errorf("CryptogramMismatchError should populate both byte slices; got expected=%X received=%X", cm.Expected, cm.Received)
	}
	if len(cm.Expected) != len(cm.Received) {
		t.Errorf("Expected and Received should have equal length (S8=8 or S16=16); got %d / %d", len(cm.Expected), len(cm.Received))
	}
	// They must differ — that's the whole point.
	if string(cm.Expected) == string(cm.Received) {
		t.Errorf("Expected and Received should differ on a key mismatch; both = %X", cm.Expected)
	}
}

// bytes16 returns a 16-byte slice filled with v. Test helper.
func bytes16(v byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = v
	}
	return out
}
