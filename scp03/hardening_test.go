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
			_, err := Open(context.Background(), nil, cfg)
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

// TestFactoryYubiKeyConfig_ReturnsKVN0xFF locks in the YubiKey
// factory KVN. Cards that ship at 0xFF (YubiKey 5.3+) reject 0x00
// with 6A88; the helper exists so callers don't get bitten by the
// default zero.
func TestFactoryYubiKeyConfig_ReturnsKVN0xFF(t *testing.T) {
	cfg := FactoryYubiKeyConfig()
	if cfg.KeyVersion != 0xFF {
		t.Errorf("FactoryYubiKeyConfig.KeyVersion = 0x%02X, want 0xFF", cfg.KeyVersion)
	}
	if cfg.KeyVersion != YubiKeyFactoryKeyVersion {
		t.Errorf("FactoryYubiKeyConfig.KeyVersion does not match YubiKeyFactoryKeyVersion constant")
	}
	// Verify the keys are the GP standard 0x40..0x4F, not zeros.
	if cfg.Keys.ENC[0] != 0x40 {
		t.Error("FactoryYubiKeyConfig should use scp03.DefaultKeys")
	}
}
