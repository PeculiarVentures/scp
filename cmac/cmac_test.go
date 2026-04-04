package cmac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 4493 (AES-CMAC with AES-128).
func TestAESCMAC_RFC4493(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")

	tests := []struct {
		name    string
		message string
		expect  string
	}{
		{
			name:    "empty message",
			message: "",
			expect:  "bb1d6929e95937287fa37d129b756746",
		},
		{
			name:    "16-byte message",
			message: "6bc1bee22e409f96e93d7e117393172a",
			expect:  "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			name:    "40-byte message",
			message: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			expect:  "dfa66747de9ae63030ca32611497c827",
		},
		{
			name:    "64-byte message",
			message: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			expect:  "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tt.message)
			expected, _ := hex.DecodeString(tt.expect)

			result, err := AESCMAC(key, msg)
			if err != nil {
				t.Fatalf("AESCMAC failed: %v", err)
			}

			if !bytes.Equal(result, expected) {
				t.Errorf("mismatch:\n  got:  %s\n  want: %s",
					hex.EncodeToString(result), hex.EncodeToString(expected))
			}
		})
	}
}

func TestAESCMACChain(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv := make([]byte, 16)
	msg := []byte("test message 123") // 16 bytes, exact block

	// Chaining with zero IV should produce same result as regular CMAC.
	chained, err := AESCMACChain(key, iv, msg)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}

	regular, err := AESCMAC(key, msg)
	if err != nil {
		t.Fatalf("regular: %v", err)
	}

	if !bytes.Equal(chained, regular) {
		t.Error("chained CMAC with zero IV should match regular CMAC")
	}
}
