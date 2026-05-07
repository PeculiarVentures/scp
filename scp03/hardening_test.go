package scp03

import (
	"context"
	"strings"
	"testing"
)

// TestOpen_RejectsMixedKeyLengths confirms ENC/MAC/DEK must all be
// the same AES size. Earlier the channel layer derived S-MAC and
// S-RMAC at the ENC key length regardless of the MAC key length —
// silently non-standard cryptography that wouldn't interoperate
// with any compliant card.
func TestOpen_RejectsMixedKeyLengths(t *testing.T) {
	cases := []struct {
		name      string
		enc, mac  int
		dek       int
		wantInErr string
	}{
		{"mac shorter than enc", 32, 16, 32, "same length"},
		{"dek longer than enc", 16, 16, 24, "same length"},
		{"all different", 16, 24, 32, "same length"},
		{"enc invalid size", 17, 17, 17, "Keys.ENC length"},
		{"enc empty", 0, 16, 16, "must be set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{
				Keys: StaticKeys{
					ENC: make([]byte, c.enc),
					MAC: make([]byte, c.mac),
					DEK: make([]byte, c.dek),
				},
				KeyVersion: 0xFF,
			}
			_, err := Open(context.Background(), NewMockCard(DefaultKeys).Transport(), cfg)
			if err == nil {
				t.Fatal("Open should have rejected mixed key lengths")
			}
			if !strings.Contains(err.Error(), c.wantInErr) {
				t.Errorf("error %q should contain %q", err.Error(), c.wantInErr)
			}
		})
	}
}

// TestOpen_AcceptsAllSameLengths confirms the validator allows
// AES-128, -192, and -256 when all three keys match.
func TestOpen_AcceptsAllSameLengths(t *testing.T) {
	for _, sz := range []int{16, 24, 32} {
		cfg := &Config{
			Keys: StaticKeys{
				ENC: make([]byte, sz),
				MAC: make([]byte, sz),
				DEK: make([]byte, sz),
			},
			KeyVersion: 0xFF,
		}
		_, err := Open(context.Background(), erroringTransport{}, cfg)
		// We expect a transport-layer failure, NOT a key-length
		// validation failure. Confirm the error doesn't reference
		// the key-length checks.
		if err == nil {
			t.Errorf("size %d: erroring transport unexpectedly accepted", sz)
			continue
		}
		if strings.Contains(err.Error(), "must be set") ||
			strings.Contains(err.Error(), "same length") ||
			strings.Contains(err.Error(), "Keys.ENC length") {
			t.Errorf("size %d: key-length validator wrongly rejected: %v", sz, err)
		}
	}
}
