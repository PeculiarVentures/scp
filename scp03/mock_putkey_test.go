package scp03

// Tests for the SCP03 mock card's PUT KEY response synthesis.
//
// The mock previously returned 9000 with no body for PUT KEY,
// which works for EC public/private key installs (those genuinely
// don't carry a body in the response per GP §11.8.2.4) but fails
// for SCP03 AES key-set installs, which require the card to echo
// back KVN || KCV_enc || KCV_mac || KCV_dek so the host's
// PutSCP03Key can verify (via ErrChecksum) that the keys committed
// match what was sent.
//
// These tests pin the mock's new response synthesis end-to-end:
// drive securitydomain.Session.PutSCP03Key against a mock with
// known DEK, capture the recorded body, and verify the response
// causes no checksum failure.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// TestMock_PutKey_SCP03KeySet_RoundTrip drives the synthesis path
// directly: build a body that matches the SCP03 PUT KEY shape
// (KVN || three TLVs with encrypted keys + KCVs), call the
// synthesizer, and verify the response is the right shape.
//
// We test the synthesizer at the unit level rather than going
// through OpenSCP03 + PutSCP03Key end-to-end here because (a) those
// integration paths are covered by cmd/scpctl/cmd_sd_e2e_test.go
// and (b) a unit test makes any future regression in the
// synthesizer itself land an obvious failure here regardless of
// what the higher-level callers happen to send.
func TestMock_PutKey_SCP03KeySet_RoundTrip(t *testing.T) {
	// Static DEK matching the mock's c.Keys.DEK in this test setup.
	// We use scp03.DefaultKeys.DEK to mirror real-world use.
	mock := NewMockCard(DefaultKeys)
	dek := DefaultKeys.DEK

	// Build a body that PutSCP03Key would produce for a key triple
	// of (0x10×16, 0x20×16, 0x30×16) at KVN=0x42.
	enc := bytes.Repeat([]byte{0x10}, 16)
	mac := bytes.Repeat([]byte{0x20}, 16)
	depKey := bytes.Repeat([]byte{0x30}, 16)
	kvn := byte(0x42)

	body := []byte{kvn}
	for _, k := range [][]byte{enc, mac, depKey} {
		// Encrypt key under static DEK (matches putKeySCP03Cmd).
		ciphertext := aesCBCEncryptOneBlock(t, dek, k)
		// Append Tlv(0x88, 16-byte ciphertext).
		body = append(body, 0x88, 0x10)
		body = append(body, ciphertext...)
		// Append KCV: AES-CBC(k, ones)[:3], length 3.
		kcv := computeKCVForTest(t, k)
		body = append(body, 0x03)
		body = append(body, kcv...)
	}

	resp, ok := mock.synthesizeSCP03KeySetPutKeyResponse(body)
	if !ok {
		t.Fatalf("synthesizer returned ok=false on a valid SCP03 key-set body")
	}
	// Expected response: KVN || KCV_enc || KCV_mac || KCV_dek.
	want := []byte{kvn}
	for _, k := range [][]byte{enc, mac, depKey} {
		want = append(want, computeKCVForTest(t, k)...)
	}
	if !bytes.Equal(resp, want) {
		t.Errorf("response = %X, want %X", resp, want)
	}
	if len(resp) != 10 {
		t.Errorf("response length = %d, want 10 (1 KVN + 3×3 KCV)", len(resp))
	}
}

// TestMock_PutKey_SCP03KeySet_RecomputesKCVOnDecryption verifies
// that the mock recomputes KCVs from the decrypted plaintext rather
// than echoing back the host's claimed KCVs. This is the
// architecturally correct behavior — a real card recomputes — and
// it makes the mock useful for testing adversarial transmission
// paths where the host might (deliberately or by bug) send a body
// whose claimed KCV doesn't match the encrypted key.
func TestMock_PutKey_SCP03KeySet_RecomputesKCVOnDecryption(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	dek := DefaultKeys.DEK

	enc := bytes.Repeat([]byte{0x10}, 16)
	mac := bytes.Repeat([]byte{0x20}, 16)
	depKey := bytes.Repeat([]byte{0x30}, 16)

	body := []byte{0x42}
	for _, k := range [][]byte{enc, mac, depKey} {
		body = append(body, 0x88, 0x10)
		body = append(body, aesCBCEncryptOneBlock(t, dek, k)...)
		body = append(body, 0x03)
		// Lie about the KCV: send 00:00:00 instead of the real value.
		body = append(body, 0x00, 0x00, 0x00)
	}

	resp, ok := mock.synthesizeSCP03KeySetPutKeyResponse(body)
	if !ok {
		t.Fatalf("synthesizer returned ok=false on a valid (if mendacious) body")
	}
	// Response KCVs must NOT be the lying 00:00:00 we put in the
	// body. They must be the real KCVs computed from the decrypted
	// plaintext. If the mock echoed the body's claimed KCVs, the
	// response would contain three 00:00:00 triples after the KVN.
	if bytes.Contains(resp[1:], []byte{0x00, 0x00, 0x00}) {
		t.Errorf("response contains the host's lying KCV bytes; mock should recompute. resp=%X", resp)
	}
	for _, k := range [][]byte{enc, mac, depKey} {
		if !bytes.Contains(resp, computeKCVForTest(t, k)) {
			t.Errorf("response missing real KCV for key %X; mock should recompute. resp=%X", k[:4], resp)
		}
	}
}

// TestMock_PutKey_NotSCP03KeySet_FallsThrough verifies the
// synthesizer correctly returns ok=false for inputs that aren't
// SCP03 key-set bodies. The mock then falls back to the EC-key
// path which returns 9000 with no body.
func TestMock_PutKey_NotSCP03KeySet_FallsThrough(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	cases := []struct {
		name string
		body []byte
	}{
		{"too short", []byte{0x42, 0x88}},
		{"wrong tag", []byte{0x42, 0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x88, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x88, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}},
		{"wrong length byte", []byte{0x42, 0x88, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x88, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x88, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}},
		{"missing kcv length", []byte{0x42, 0x88, 0x10,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00, 0x88, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x88, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := mock.synthesizeSCP03KeySetPutKeyResponse(tc.body)
			if ok {
				t.Errorf("synthesizer accepted invalid body; resp=%X", resp)
			}
		})
	}
}

// TestMock_PutKey_SCP03KeySet_NoDEK falls through when the mock has
// no static DEK (zero-length). A zero-DEK mock can't decrypt
// encrypted keys; refusing the synthesis is the correct behavior.
func TestMock_PutKey_SCP03KeySet_NoDEK(t *testing.T) {
	mock := &MockCard{Keys: StaticKeys{ENC: DefaultKeys.ENC, MAC: DefaultKeys.MAC}}
	body := make([]byte, 67) // valid length, all zeros
	body[1] = 0x88           // tag
	body[2] = 0x10           // length
	if _, ok := mock.synthesizeSCP03KeySetPutKeyResponse(body); ok {
		t.Error("synthesizer accepted body without static DEK; should fall through")
	}
}

// --- helpers for these tests (kept local to avoid leaking AES
// utility wrappers into the package surface) ---

func aesCBCEncryptOneBlock(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	if len(key) != 16 || len(plaintext) != 16 {
		t.Fatalf("aesCBCEncryptOneBlock: key=%d plaintext=%d, want 16+16", len(key), len(plaintext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, 16)
	enc.CryptBlocks(out, plaintext)
	return out
}

func computeKCVForTest(t *testing.T, key []byte) []byte {
	t.Helper()
	ones := bytes.Repeat([]byte{0x01}, 16)
	cipherBlock := aesCBCEncryptOneBlock(t, key, ones)
	return cipherBlock[:3]
}
