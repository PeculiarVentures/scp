package kdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestX963KDF_BasicDerivation(t *testing.T) {
	// Verify the X9.63 KDF produces the expected output structure:
	// key = SHA-256(Z || counter || sharedInfo)
	z := bytes.Repeat([]byte{0xAB}, 32)
	sharedInfo := []byte{KeyUsage, KeyTypeAES, SessionKeyLen}

	result, err := X963KDF(z, sharedInfo, 32)
	if err != nil {
		t.Fatalf("X963KDF failed: %v", err)
	}

	// Compute expected manually: SHA-256(Z || 0x00000001 || sharedInfo)
	h := sha256.New()
	h.Write(z)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	h.Write(counter[:])
	h.Write(sharedInfo)
	expected := h.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("X963KDF mismatch:\n  got:  %s\n  want: %s",
			hex.EncodeToString(result), hex.EncodeToString(expected))
	}
}

func TestX963KDF_MultiBlock(t *testing.T) {
	// 80 bytes requires 3 SHA-256 iterations (3 × 32 = 96, truncated to 80).
	z := bytes.Repeat([]byte{0xCD}, 32)
	sharedInfo := []byte{KeyUsage, KeyTypeAES, SessionKeyLen}

	result, err := X963KDF(z, sharedInfo, 80)
	if err != nil {
		t.Fatalf("X963KDF failed: %v", err)
	}

	if len(result) != 80 {
		t.Fatalf("expected 80 bytes, got %d", len(result))
	}

	// Verify the first 32 bytes match a single iteration.
	h := sha256.New()
	h.Write(z)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	h.Write(counter[:])
	h.Write(sharedInfo)
	firstBlock := h.Sum(nil)

	if !bytes.Equal(result[:32], firstBlock) {
		t.Error("first block of multi-block derivation doesn't match single-block")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	// Test that DeriveSessionKeysFromSharedSecrets produces 5 distinct
	// 16-byte keys from two 32-byte shared secrets.
	shSee := bytes.Repeat([]byte{0x01}, 32)
	shSes := bytes.Repeat([]byte{0x02}, 32)

	keys, err := DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, nil)
	if err != nil {
		t.Fatalf("derive failed: %v", err)
	}

	// All keys should be 16 bytes.
	for name, key := range map[string][]byte{
		"Receipt": keys.Receipt,
		"SENC":    keys.SENC,
		"SMAC":    keys.SMAC,
		"SRMAC":   keys.SRMAC,
		"DEK":     keys.DEK,
	} {
		if len(key) != 16 {
			t.Errorf("%s: expected 16 bytes, got %d", name, len(key))
		}
	}

	// All keys should be distinct from each other.
	allKeys := [][]byte{keys.Receipt, keys.SENC, keys.SMAC, keys.SRMAC, keys.DEK}
	for i := 0; i < len(allKeys); i++ {
		for j := i + 1; j < len(allKeys); j++ {
			if bytes.Equal(allKeys[i], allKeys[j]) {
				t.Errorf("keys %d and %d are identical", i, j)
			}
		}
	}

	// MAC chain should start at zero.
	if !bytes.Equal(keys.MACChain, make([]byte, 16)) {
		t.Error("MAC chain should be initialized to zeros")
	}
}

func TestDeriveSessionKeys_MismatchedLengths(t *testing.T) {
	shSee := make([]byte, 32)
	shSes := make([]byte, 24) // Wrong length

	_, err := DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, nil)
	if err == nil {
		t.Error("expected error for mismatched shared secret lengths")
	}
}

func TestPadUnpad(t *testing.T) {
	tests := []struct {
		input     []byte
		blockSize int
		padLen    int
	}{
		{[]byte{1, 2, 3}, 16, 16},
		{make([]byte, 15), 16, 16},
		{make([]byte, 16), 16, 32},
		{make([]byte, 0), 16, 16},
	}

	for _, tt := range tests {
		padded := Pad(tt.input, tt.blockSize)
		if len(padded) != tt.padLen {
			t.Errorf("Pad(%d bytes): expected %d, got %d", len(tt.input), tt.padLen, len(padded))
			continue
		}

		unpadded, err := Unpad(padded)
		if err != nil {
			t.Errorf("Unpad failed: %v", err)
			continue
		}

		if !bytes.Equal(unpadded, tt.input) {
			t.Errorf("round-trip failed: got %x, want %x", unpadded, tt.input)
		}
	}
}

func TestReceipt(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 16)
	data1 := bytes.Repeat([]byte{0x01}, 65)
	data2 := bytes.Repeat([]byte{0x02}, 65)
	agreementData := append(data1, data2...)

	receipt, err := ComputeReceipt(key, agreementData)
	if err != nil {
		t.Fatalf("ComputeReceipt failed: %v", err)
	}

	if len(receipt) != 16 {
		t.Fatalf("receipt should be 16 bytes, got %d", len(receipt))
	}

	// Verification should pass with matching data.
	if err := VerifyReceipt(key, agreementData, receipt); err != nil {
		t.Errorf("VerifyReceipt failed: %v", err)
	}

	// Verification should fail with wrong data.
	wrongData := bytes.Repeat([]byte{0x03}, 130)
	if err := VerifyReceipt(key, wrongData, receipt); err == nil {
		t.Error("VerifyReceipt should fail with wrong data")
	}
}

// TestDeriveSessionKeysFromSharedSecrets_RejectsOverlongIDs confirms
// the SharedInfo length-prefix check. Earlier the code did
// byte(len(...)) without bounds-checking, so a 256-byte hostID
// silently truncated to length 0 (still emitting all 256 bytes of
// value), which shifts the KDF input and produces different keys
// on host and card. Fail loud instead.
func TestDeriveSessionKeysFromSharedSecrets_RejectsOverlongIDs(t *testing.T) {
	shSee := bytes.Repeat([]byte{0x01}, 32)
	shSes := bytes.Repeat([]byte{0x02}, 32)

	// 256-byte hostID — one byte over the single-byte length encoding.
	long := bytes.Repeat([]byte{0xAA}, 256)

	if _, err := DeriveSessionKeysFromSharedSecrets(shSee, shSes, long, nil); err == nil {
		t.Error("256-byte hostID should be rejected (single-byte length prefix overflows)")
	}
	if _, err := DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, long); err == nil {
		t.Error("256-byte cardGroupID should be rejected (single-byte length prefix overflows)")
	}

	// 255-byte hostID is the longest valid case.
	max := bytes.Repeat([]byte{0xAA}, 255)
	if _, err := DeriveSessionKeysFromSharedSecrets(shSee, shSes, max, nil); err != nil {
		t.Errorf("255-byte hostID should be accepted (max valid length): %v", err)
	}
}
