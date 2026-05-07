package scp03

// PUT KEY / GENERATE KEY response synthesis for MockCard.
//
// This file holds the response builders for the two key-management
// commands the mock implements: GENERATE EC KEY (Yubico extension
// INS=0xF1) and PUT KEY (INS=0xD8) for SCP03 AES key-sets. Both
// produce wire-shape responses that the library's Session methods
// parse cleanly — the mock doesn't actually persist the key
// material in a way that survives a subsequent secure-channel
// re-auth, but the round-trip of a single command produces the
// same response a real card would.
//
// Split from mock.go because the body parsing and KCV recomputation
// are stateless (they don't touch any MockCard receiver state
// beyond reading c.Keys.DEK for SCP03), so they form a coherent
// computational layer separate from the dispatch and inventory
// surfaces.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"

	"github.com/PeculiarVentures/scp/tlv"
)

// synthesizeGenerateKeyResponse builds a wire-shape response that
// Session.GenerateECKey's parser accepts: Tlv(0xB0, <65-byte SEC1
// uncompressed P-256 point>). The matching private key is discarded
// because MockCard does not persist SD state — a subsequent
// authenticated read against the supposed new KID will not work, but
// the GENERATE KEY round-trip itself does.
//
// Tests that need to drive a specific keypair through GENERATE KEY
// can replace this stub by wrapping the transport returned by
// Transport(); for the common case (CLI hitting a synthetic card and
// asserting the public key parses) the random keypair is enough.
func synthesizeGenerateKeyResponse() ([]byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	point := priv.PublicKey().Bytes() // 65-byte uncompressed SEC1 (0x04 || X || Y)
	return tlv.Build(tlv.Tag(0xB0), point).Encode(), nil
}

// synthesizeSCP03KeySetPutKeyResponse parses an SCP03 AES key-set
// PUT KEY body and produces the response a real card would emit:
//
//	KVN || KCV_enc || KCV_mac || KCV_dek    (1 + 3 + 3 + 3 = 10 bytes)
//
// Returns (response, true) when the body matches the SCP03 key-set
// shape; (nil, false) when it doesn't (e.g. EC private or public key
// PUT KEY, which use different tag layouts and don't carry KCVs in
// the body).
//
// Body shape from securitydomain.putKeySCP03Cmd, which the GP spec
// (§11.8.2.3) anchors:
//
//	byte 0: KVN
//	repeated 3 times:
//	  byte: 0x88                    (key-type tag = AES)
//	  byte: 0x10                    (length = 16, AES-128)
//	  16 bytes: encrypted_key       (AES-CBC(static-DEK, key))
//	  byte: 0x03                    (KCV length)
//	  3 bytes: KCV                  (host-computed; the card
//	                                 recomputes after decryption)
//
// We faithfully recompute the KCVs after decryption rather than
// echoing back the host's. A real card would catch a mismatch
// between the encrypted-key payload and the host's KCV claim, and
// the mock should match that behavior so tests for adversarial
// transmission paths produce the same result against the mock as
// against a real card.
//
// Decryption: AES-CBC under c.Keys.DEK (the static DEK, the third
// component of the SCP03 StaticKeys triple) with a zero IV. The
// 16-byte ciphertext is exactly one AES block, so PKCS#7 padding
// from the encryption side adds a second block of all-0x10 bytes
// — but the library's encryption produces a 16-byte ciphertext
// (single block, no padding written) for AES-128 keys. We mirror
// that: decrypt 16 bytes, no unpad, the result is the new key.
//
// Returns (nil, false) on any structural problem: too-short body,
// wrong tag, bad length byte, missing KCV byte. The caller falls
// back to the EC-key path, which returns 9000-empty — that matches
// the strict semantics of "this isn't an SCP03 key-set body."
func (c *MockCard) synthesizeSCP03KeySetPutKeyResponse(body []byte) ([]byte, bool) {
	// Minimum size: 1 (KVN) + 3 × (1 tag + 1 len + 16 enc + 1 kcv-len + 3 kcv) = 1 + 66 = 67 bytes.
	const wantLen = 1 + 3*(1+1+16+1+3)
	if len(body) < wantLen {
		return nil, false
	}
	// The static DEK is what the host used to encrypt; we use the
	// same to decrypt. If the mock was constructed without a DEK
	// (zero-length), this is not an SCP03-key-set-capable mock and
	// we fall back to the EC path.
	if len(c.Keys.DEK) != 16 {
		return nil, false
	}

	kvn := body[0]
	resp := make([]byte, 0, 1+3*3)
	resp = append(resp, kvn)

	off := 1
	for k := 0; k < 3; k++ {
		// Tag must be 0x88 (keyTypeAES).
		if body[off] != 0x88 {
			return nil, false
		}
		// Length must be 0x10 (16 bytes, AES-128).
		if body[off+1] != 0x10 {
			return nil, false
		}
		encryptedKey := body[off+2 : off+2+16]
		off += 2 + 16
		// KCV length must be 0x03.
		if body[off] != 0x03 {
			return nil, false
		}
		// Skip the host's claimed KCV; we recompute.
		off += 1 + 3

		// Decrypt the 16-byte block under static DEK with a zero IV.
		// PutKeySCP03Cmd uses aesCBCEncrypt which PKCS#7-pads input,
		// but a 16-byte AES key fits in one block — pkcs7Pad would
		// in principle add a 16-byte all-0x10 padding block, BUT
		// the library code only emits the FIRST block of the
		// ciphertext for AES-128 (the encryptedKey is exactly the
		// 16-byte CBC encryption of the key). So we decrypt exactly
		// one block, no unpad.
		newKey := make([]byte, 16)
		decryptOneAESBlock(c.Keys.DEK, encryptedKey, newKey)
		// KCV = AES-CBC(new_key, IV=0, ones_block)[:3].
		kcvCipher := make([]byte, 16)
		ones := make([]byte, 16)
		for i := range ones {
			ones[i] = 0x01
		}
		decryptOneAESBlockWithEncrypt(newKey, ones, kcvCipher)
		resp = append(resp, kcvCipher[:3]...)
	}
	return resp, true
}

// decryptOneAESBlock decrypts a single 16-byte block under the
// AES-128 key with a zero IV (CBC mode degenerates to ECB for one
// block when IV is zero, but we use the CBC API for symmetry with
// the library encryption side that uses crypto/cipher.NewCBCDecrypter).
func decryptOneAESBlock(key, ciphertext, out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(out, ciphertext)
}

// decryptOneAESBlockWithEncrypt is intentionally named "with
// encrypt" because the KCV computation per GP Card Specification
// is the ENCRYPTION of an all-ones block under the candidate key;
// the result's first 3 bytes are the KCV. Using the CBC encrypter
// (zero IV) for one block matches the library's computeAESKCV.
func decryptOneAESBlockWithEncrypt(key, plaintext, out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(out, plaintext)
}
