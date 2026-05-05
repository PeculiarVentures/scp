package scp03_test

import (
	"context"
	"errors"
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
