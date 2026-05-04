package pivapdu

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/tlv"
)

// TestMgmtKeyMutualAuthChallenge_Wire confirms the first APDU's
// header bytes and TLV body match NIST SP 800-73-4 Part 2 §3.2.4
// for "request witness." The card recognizes this exact byte
// sequence; a regression in the body (extra padding, wrong template
// tag, non-empty witness slot) would silently produce a different
// flow on the card.
func TestMgmtKeyMutualAuthChallenge_Wire(t *testing.T) {
	cases := []struct {
		name    string
		algo    byte
		wantP1  byte
		wantHex string // CLA INS P1 P2 Lc Data
	}{
		{"3DES", AlgoMgmt3DES, 0x03, "00 87 03 9B 04 7C 02 80 00"},
		{"AES-128", AlgoMgmtAES128, 0x08, "00 87 08 9B 04 7C 02 80 00"},
		{"AES-192", AlgoMgmtAES192, 0x0A, "00 87 0A 9B 04 7C 02 80 00"},
		{"AES-256", AlgoMgmtAES256, 0x0C, "00 87 0C 9B 04 7C 02 80 00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := MgmtKeyMutualAuthChallenge(tc.algo)
			if cmd.CLA != 0x00 || cmd.INS != 0x87 || cmd.P1 != tc.wantP1 || cmd.P2 != 0x9B {
				t.Errorf("header: got CLA=%02X INS=%02X P1=%02X P2=%02X want 00 87 %02X 9B",
					cmd.CLA, cmd.INS, cmd.P1, cmd.P2, tc.wantP1)
			}
			wantBody := []byte{0x7C, 0x02, 0x80, 0x00}
			if !bytes.Equal(cmd.Data, wantBody) {
				t.Errorf("body: got %X want %X", cmd.Data, wantBody)
			}
		})
	}
}

// TestMgmtKey_RoundTrip is the principal correctness test. It
// simulates the full mutual-auth exchange:
//
//  1. Host issues challenge APDU (request witness).
//  2. Test acts as card: generates random witness, encrypts under
//     the configured mgmt key, returns 7C { 80 <enc_witness> }.
//  3. Host parses witness, decrypts, generates fresh challenge,
//     wraps both into 7C { 80 <plain_witness>, 81 <challenge> }.
//  4. Test acts as card: verifies decrypted witness matches what
//     it generated, encrypts host challenge, returns 7C { 82 <enc> }.
//  5. Host calls VerifyMutualAuthResponse — must succeed.
//
// Run for all four algorithms with their correct key lengths.
func TestMgmtKey_RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		algo   byte
		keyLen int
	}{
		{"3DES", AlgoMgmt3DES, 24},
		{"AES-128", AlgoMgmtAES128, 16},
		{"AES-192", AlgoMgmtAES192, 24},
		{"AES-256", AlgoMgmtAES256, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("random key: %v", err)
			}

			// Step 1: host builds challenge.
			_ = MgmtKeyMutualAuthChallenge(tc.algo)

			// Step 2: card simulator generates witness, encrypts.
			cardWitness := generateBlock(t, tc.algo)
			cardEncWitness, err := mgmtEncrypt(key, cardWitness, tc.algo)
			if err != nil {
				t.Fatalf("card-side encrypt witness: %v", err)
			}
			cardResponse := buildAuthTemplate(t, tagWitness, cardEncWitness)

			// Step 3: host parses, decrypts, builds response.
			parsedEnc, err := ParseMutualAuthWitness(cardResponse, tc.algo)
			if err != nil {
				t.Fatalf("ParseMutualAuthWitness: %v", err)
			}
			if !bytes.Equal(parsedEnc, cardEncWitness) {
				t.Fatalf("parsed witness != card-sent witness")
			}
			respCmd, hostChallenge, err := MgmtKeyMutualAuthRespond(parsedEnc, key, tc.algo)
			if err != nil {
				t.Fatalf("MgmtKeyMutualAuthRespond: %v", err)
			}

			// Verify the host's response APDU has the right shape and
			// that the decrypted witness it carries equals what the
			// card originally generated (i.e., host correctly inverted
			// the encryption).
			template, err := findTLV(respCmd.Data, tagAuthTemplate)
			if err != nil {
				t.Fatalf("response template: %v", err)
			}
			plainWitness, err := findTLV(template, tagWitness)
			if err != nil {
				t.Fatalf("response witness tag: %v", err)
			}
			if !bytes.Equal(plainWitness, cardWitness) {
				t.Errorf("decrypted witness mismatch: got %X want %X", plainWitness, cardWitness)
			}
			parsedChallenge, err := findTLV(template, tagChallenge)
			if err != nil {
				t.Fatalf("response challenge tag: %v", err)
			}
			if !bytes.Equal(parsedChallenge, hostChallenge) {
				t.Errorf("returned challenge != generated challenge")
			}

			// Step 4: card simulator encrypts host's challenge.
			cardEncChallenge, err := mgmtEncrypt(key, hostChallenge, tc.algo)
			if err != nil {
				t.Fatalf("card-side encrypt challenge: %v", err)
			}
			cardFinal := buildAuthTemplate(t, tagResponse, cardEncChallenge)

			// Step 5: host verifies.
			if err := VerifyMutualAuthResponse(cardFinal, hostChallenge, key, tc.algo); err != nil {
				t.Errorf("VerifyMutualAuthResponse failed unexpectedly: %v", err)
			}
		})
	}
}

// TestMgmtKey_VerifyRejectsWrongKey confirms VerifyMutualAuthResponse
// fails closed when the card's response would decrypt to the host's
// challenge under a *different* key. This is the path that protects
// against a card that doesn't actually possess the key the host
// thinks it does.
func TestMgmtKey_VerifyRejectsWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 16)
	wrongKey := bytes.Repeat([]byte{0xBB}, 16)

	hostChallenge := generateBlock(t, AlgoMgmtAES128)
	encUnderWrongKey, err := mgmtEncrypt(wrongKey, hostChallenge, AlgoMgmtAES128)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cardFinal := buildAuthTemplate(t, tagResponse, encUnderWrongKey)
	err = VerifyMutualAuthResponse(cardFinal, hostChallenge, key, AlgoMgmtAES128)
	if err == nil {
		t.Fatal("expected verification to fail under wrong key")
	}
	if !strings.Contains(err.Error(), "did not verify") {
		t.Errorf("expected 'did not verify' error, got: %v", err)
	}
}

// TestMgmtKey_RejectsKeyLengthMismatch confirms the input-shape
// guards on the public functions. Wrong-length keys must fail at
// the API boundary, not at the cipher.
func TestMgmtKey_RejectsKeyLengthMismatch(t *testing.T) {
	cases := []struct {
		name string
		algo byte
		key  []byte
	}{
		{"3DES with 16 bytes", AlgoMgmt3DES, make([]byte, 16)},
		{"AES-128 with 24 bytes", AlgoMgmtAES128, make([]byte, 24)},
		{"AES-192 with 16 bytes", AlgoMgmtAES192, make([]byte, 16)},
		{"AES-256 with 24 bytes", AlgoMgmtAES256, make([]byte, 24)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			witness := make([]byte, 16)
			if tc.algo == AlgoMgmt3DES {
				witness = make([]byte, 8)
			}
			_, _, err := MgmtKeyMutualAuthRespond(witness, tc.key, tc.algo)
			if err == nil {
				t.Fatal("expected length-mismatch error")
			}
		})
	}
}

// TestMgmtKey_RejectsUnknownAlgorithm covers the algorithm-byte
// validation across all the entry points so a typo'd algorithm
// can't slip past one boundary check and explode at another.
func TestMgmtKey_RejectsUnknownAlgorithm(t *testing.T) {
	t.Run("ParseMutualAuthWitness", func(t *testing.T) {
		_, err := ParseMutualAuthWitness([]byte{0x7C, 0x0A, 0x80, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}, 0xFF)
		if err == nil {
			t.Fatal("expected unknown-algorithm error")
		}
	})
	t.Run("MgmtKeyMutualAuthRespond", func(t *testing.T) {
		_, _, err := MgmtKeyMutualAuthRespond(make([]byte, 8), make([]byte, 24), 0xFF)
		if err == nil {
			t.Fatal("expected unknown-algorithm error")
		}
	})
	t.Run("VerifyMutualAuthResponse", func(t *testing.T) {
		err := VerifyMutualAuthResponse([]byte{0x7C, 0x0A, 0x82, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}, make([]byte, 8), make([]byte, 24), 0xFF)
		if err == nil {
			t.Fatal("expected unknown-algorithm error")
		}
	})
}

// TestMgmtKey_RejectsMalformedTLV confirms the TLV walker flags
// truncation and missing tags rather than producing slice-bounds
// panics. Untrusted card responses must fail cleanly.
func TestMgmtKey_RejectsMalformedTLV(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"just template tag, no length", []byte{0x7C}},
		{"template length runs past buffer", []byte{0x7C, 0x10, 0x80, 0x02, 1, 2}},
		{"missing witness tag inside template", []byte{0x7C, 0x04, 0x99, 0x02, 1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseMutualAuthWitness(tc.data, AlgoMgmtAES128)
			if err == nil {
				t.Errorf("expected error parsing %X", tc.data)
			}
		})
	}
}

// TestMgmtKey_DefaultKeyMatchesYubicoConstant pins the well-known
// pre-5.7 default to the documented value. If anyone changes
// piv.DefaultMgmtKey by accident, this catches it. The value is
// public; there is nothing sensitive about it.
func TestMgmtKey_DefaultKeyMatchesYubicoConstant(t *testing.T) {
	want := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(piv.DefaultMgmtKey, want) {
		t.Errorf("piv.DefaultMgmtKey changed: got %X want %X", piv.DefaultMgmtKey, want)
	}
	// Smoke-check the cipher works with this key length.
	if _, err := des.NewTripleDESCipher(piv.DefaultMgmtKey); err != nil {
		t.Errorf("piv.DefaultMgmtKey not a valid 3DES key: %v", err)
	}
	// The deprecated DefaultMgmt3DESKey alias must still point at the
	// same bytes; this is the contract back-compat consumers rely on.
	// staticcheck flags the use of a deprecated symbol but the whole
	// purpose of this assertion is to verify the deprecated alias is
	// not silently broken.
	if !bytes.Equal(piv.DefaultMgmt3DESKey, piv.DefaultMgmtKey) { //nolint:staticcheck // intentional alias check
		t.Error("piv.DefaultMgmt3DESKey no longer equals piv.DefaultMgmtKey; the alias contract is broken")
	}
}

// TestMgmtKey_AESKeyLengthsAccepted is a sanity check that the four
// AES key lengths the package advertises are actually valid AES key
// lengths. (Caught a real bug once where an AES variant was
// declared but Go's aes.NewCipher rejected the length.)
func TestMgmtKey_AESKeyLengthsAccepted(t *testing.T) {
	for _, sz := range []int{16, 24, 32} {
		if _, err := aes.NewCipher(make([]byte, sz)); err != nil {
			t.Errorf("AES rejects %d-byte key: %v", sz, err)
		}
	}
}

// generateBlock returns a fresh random buffer the size of the named
// algorithm's block (8 for 3DES, 16 for AES).
func generateBlock(t *testing.T, algorithm byte) []byte {
	t.Helper()
	bs, err := blockSize(algorithm)
	if err != nil {
		t.Fatalf("blockSize: %v", err)
	}
	b := make([]byte, bs)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// buildAuthTemplate wraps a single inner TLV inside the 7C
// Authentication Template, simulating what the card would return
// at each step. innerTag is the inner tag byte (0x80 for witness
// in step 2, 0x82 for response in step 4).
func buildAuthTemplate(t *testing.T, innerTag byte, value []byte) []byte {
	t.Helper()
	inner := tlv.Build(tlv.Tag(innerTag), value).Encode()
	template := tlv.BuildConstructed(tlv.Tag(tagAuthTemplate))
	template.Value = inner
	return template.Encode()
}

// _ asserts errors.Is is in scope for future test growth without
// a noisy unused-import message if a sub-test gets removed.
var _ = errors.Is
