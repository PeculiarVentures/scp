package pivapdu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/tlv"
)

// PIV management-key algorithm identifiers (NIST SP 800-73-4 Part 1
// Table 4 + YubiKey Technical Manual). The byte goes into P1 of
// GENERAL AUTHENTICATE during management-key mutual auth and must
// match what was configured on the card via SetManagementKey.
//
// AlgoMgmt3DES is the historic YubiKey factory default (firmware
// before 5.7). AlgoMgmtAES192 is the YubiKey 5.7+ factory default;
// AES-128 and AES-256 are also supported on 5.7+ via SetManagementKey
// with the matching algorithm.
const (
	AlgoMgmt3DES   byte = 0x03 // Triple-DES (TDES-EDE3, 24-byte key)
	AlgoMgmtAES128 byte = 0x08
	AlgoMgmtAES192 byte = 0x0A
	AlgoMgmtAES256 byte = 0x0C
)

// MgmtKeyRef and DefaultMgmtKey/DefaultMgmt3DESKey are defined in
// the parent piv package (piv/types.go) so the typed ManagementKey
// vocabulary lives in one place. They are referenced here as
// piv.MgmtKeyRef and piv.DefaultMgmtKey.

// PIV mutual-authentication TLV tags inside the 7C Authentication
// Template (NIST SP 800-73-4 Part 2 §3.2.4).
const (
	tagAuthTemplate byte = 0x7C
	tagWitness      byte = 0x80
	tagChallenge    byte = 0x81
	tagResponse     byte = 0x82
)

// MgmtKeyMutualAuthChallenge builds the first APDU in PIV management-
// key mutual authentication: GENERAL AUTHENTICATE with an empty
// witness slot (tag 7C { tag 80 length 0 }), requesting the card to
// generate a witness and return it encrypted under the management
// key. The host's job for step 2 is to decrypt that witness, prove
// possession of the key, and present a fresh challenge for the
// card to respond to.
//
// algorithm must match what's configured on the card (one of
// AlgoMgmt3DES / AlgoMgmtAES128 / AlgoMgmtAES192 / AlgoMgmtAES256).
// On YubiKey, the card's current management-key algorithm can be
// learned from the YubiKey-specific GET METADATA call; that's not
// in this package today, so callers either know it from
// configuration or try the factory default first.
func MgmtKeyMutualAuthChallenge(algorithm byte) *apdu.Command {
	// 7C 02 80 00 — empty Authentication Template requesting a witness.
	body := []byte{tagAuthTemplate, 0x02, tagWitness, 0x00}
	return &apdu.Command{
		CLA:  0x00,
		INS:  0x87,
		P1:   algorithm,
		P2:   piv.MgmtKeyRef,
		Data: body,
		Le:   -1,
	}
}

// ParseMutualAuthWitness extracts the encrypted witness the card
// returned in response to MgmtKeyMutualAuthChallenge. The card's
// response is `7C LL 80 LL <encrypted_witness>`; this returns just
// the encrypted-witness bytes.
//
// The witness length must equal the algorithm's block size (8 for
// 3DES, 16 for AES). A length mismatch usually means the card is
// using a different algorithm than the host configured — return
// an error rather than silently feeding the wrong-sized buffer to
// the cipher.
func ParseMutualAuthWitness(respData []byte, algorithm byte) ([]byte, error) {
	template, err := findTLV(respData, tagAuthTemplate)
	if err != nil {
		return nil, fmt.Errorf("mutual-auth response: %w", err)
	}
	witness, err := findTLV(template, tagWitness)
	if err != nil {
		return nil, fmt.Errorf("mutual-auth response: witness: %w", err)
	}
	expectedLen, err := blockSize(algorithm)
	if err != nil {
		return nil, err
	}
	if len(witness) != expectedLen {
		return nil, fmt.Errorf("witness length %d does not match algorithm 0x%02X block size %d (card algorithm mismatch?)",
			len(witness), algorithm, expectedLen)
	}
	return witness, nil
}

// MgmtKeyMutualAuthRespond builds the second APDU. Given the
// encrypted witness from the card, the management key, and the
// algorithm, it:
//
//  1. Decrypts the witness under the management key to prove
//     possession (this is what "authenticates" the host).
//  2. Generates a random challenge of the right block size.
//  3. Wraps both into 7C { 80 <decrypted_witness>, 81 <challenge> }.
//
// The card's response, on success, will contain
// 7C { 82 <encrypted_challenge> } which the host can verify with
// VerifyMutualAuthResponse to confirm the card also possesses the
// key (mutual auth, not just one-way).
//
// Errors fall into two categories: input shape (wrong key length
// for the named algorithm, malformed witness) and crypto. Both
// surface here rather than waiting for the card to reject.
func MgmtKeyMutualAuthRespond(witness, mgmtKey []byte, algorithm byte) (cmd *apdu.Command, challenge []byte, err error) {
	if err := checkKeyLen(mgmtKey, algorithm); err != nil {
		return nil, nil, err
	}
	bs, err := blockSize(algorithm)
	if err != nil {
		return nil, nil, err
	}
	if len(witness) != bs {
		return nil, nil, fmt.Errorf("witness length %d != block size %d for algorithm 0x%02X", len(witness), bs, algorithm)
	}

	decrypted, err := mgmtDecrypt(mgmtKey, witness, algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt witness: %w", err)
	}

	challenge = make([]byte, bs)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, fmt.Errorf("generate challenge: %w", err)
	}

	// Build 7C { 80 LL <decrypted>, 81 LL <challenge> }.
	witnessTLV := tlv.Build(tlv.Tag(tagWitness), decrypted).Encode()
	challengeTLV := tlv.Build(tlv.Tag(tagChallenge), challenge).Encode()
	inner := append(append([]byte{}, witnessTLV...), challengeTLV...)
	template := tlv.BuildConstructed(tlv.Tag(tagAuthTemplate))
	template.Value = inner
	body := template.Encode()

	cmd = &apdu.Command{
		CLA:  0x00,
		INS:  0x87,
		P1:   algorithm,
		P2:   piv.MgmtKeyRef,
		Data: body,
		Le:   -1,
	}
	return cmd, challenge, nil
}

// VerifyMutualAuthResponse checks the card's response to step 2 of
// mgmt-key mutual auth. The card must return 7C { 82 <enc> } where
// encrypting the host's challenge under the management key produces
// <enc>. A mismatch here means the card does not possess the key
// the host thought it did — fail closed.
//
// Constant-time comparison is intentional even though "wrong card"
// and "wrong key" are not particularly secret outcomes; it costs
// nothing and removes the foot-gun.
func VerifyMutualAuthResponse(respData []byte, hostChallenge, mgmtKey []byte, algorithm byte) error {
	template, err := findTLV(respData, tagAuthTemplate)
	if err != nil {
		return fmt.Errorf("mutual-auth response: %w", err)
	}
	encResponse, err := findTLV(template, tagResponse)
	if err != nil {
		return fmt.Errorf("mutual-auth response: response: %w", err)
	}
	expected, err := mgmtEncrypt(mgmtKey, hostChallenge, algorithm)
	if err != nil {
		return fmt.Errorf("encrypt expected response: %w", err)
	}
	if subtle.ConstantTimeCompare(encResponse, expected) != 1 {
		return errors.New("card mutual-auth response did not verify; card does not possess the configured management key")
	}
	return nil
}

// mgmtEncrypt / mgmtDecrypt are ECB-mode block-cipher primitives,
// per NIST SP 800-73-4 Part 2 §3.2.4 — PIV management-key auth uses
// raw ECB on a single block, not CBC. The inputs are exactly one
// block long.
//
// ECB on a single block is identical to a single application of
// the cipher's encrypt/decrypt routine, which is what GP and PIV
// reference implementations actually do. Using crypto/cipher's
// ECB-equivalent here keeps the surface obvious for review.
func mgmtEncrypt(key, block []byte, algorithm byte) ([]byte, error) {
	c, err := newMgmtCipher(key, algorithm)
	if err != nil {
		return nil, err
	}
	if len(block) != c.BlockSize() {
		return nil, fmt.Errorf("block length %d != cipher block size %d", len(block), c.BlockSize())
	}
	out := make([]byte, c.BlockSize())
	c.Encrypt(out, block)
	return out, nil
}

func mgmtDecrypt(key, block []byte, algorithm byte) ([]byte, error) {
	c, err := newMgmtCipher(key, algorithm)
	if err != nil {
		return nil, err
	}
	if len(block) != c.BlockSize() {
		return nil, fmt.Errorf("block length %d != cipher block size %d", len(block), c.BlockSize())
	}
	out := make([]byte, c.BlockSize())
	c.Decrypt(out, block)
	return out, nil
}

// newMgmtCipher constructs the right block cipher for a PIV mgmt
// algorithm. 3DES uses TDES-EDE3 (24-byte key); the AES variants
// use AES with the algorithm-implied key length.
func newMgmtCipher(key []byte, algorithm byte) (cipher.Block, error) {
	if err := checkKeyLen(key, algorithm); err != nil {
		return nil, err
	}
	switch algorithm {
	case AlgoMgmt3DES:
		return des.NewTripleDESCipher(key)
	case AlgoMgmtAES128, AlgoMgmtAES192, AlgoMgmtAES256:
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported PIV management-key algorithm 0x%02X", algorithm)
	}
}

func blockSize(algorithm byte) (int, error) {
	switch algorithm {
	case AlgoMgmt3DES:
		return 8, nil
	case AlgoMgmtAES128, AlgoMgmtAES192, AlgoMgmtAES256:
		return 16, nil
	default:
		return 0, fmt.Errorf("unsupported PIV management-key algorithm 0x%02X", algorithm)
	}
}

func checkKeyLen(key []byte, algorithm byte) error {
	want := 0
	switch algorithm {
	case AlgoMgmt3DES:
		want = 24
	case AlgoMgmtAES128:
		want = 16
	case AlgoMgmtAES192:
		want = 24
	case AlgoMgmtAES256:
		want = 32
	default:
		return fmt.Errorf("unsupported PIV management-key algorithm 0x%02X", algorithm)
	}
	if len(key) != want {
		return fmt.Errorf("management key length %d does not match algorithm 0x%02X (want %d bytes)", len(key), algorithm, want)
	}
	return nil
}

// findTLV scans a flat byte slice for a single top-level TLV with
// the given tag and returns its value. The PIV mutual-auth flow
// uses only a tiny set of tags (7C / 80 / 81 / 82) and short
// length fields, so a hand-rolled walker is clearer here than
// pulling the full BER-TLV parser. Length is encoded per
// ISO 7816-4 §5.2.2: 0x00..0x7F as a single byte, 0x81 LL for
// 0x80..0xFF, 0x82 LLLL for longer.
func findTLV(buf []byte, tag byte) ([]byte, error) {
	for i := 0; i < len(buf); {
		if buf[i] != tag && i+1 >= len(buf) {
			return nil, fmt.Errorf("tag 0x%02X not found", tag)
		}
		t := buf[i]
		i++
		if i >= len(buf) {
			return nil, errors.New("truncated TLV: no length byte")
		}
		var L int
		switch {
		case buf[i] < 0x80:
			L = int(buf[i])
			i++
		case buf[i] == 0x81:
			if i+1 >= len(buf) {
				return nil, errors.New("truncated TLV: 0x81 length")
			}
			L = int(buf[i+1])
			i += 2
		case buf[i] == 0x82:
			if i+2 >= len(buf) {
				return nil, errors.New("truncated TLV: 0x82 length")
			}
			L = int(buf[i+1])<<8 | int(buf[i+2])
			i += 3
		default:
			return nil, fmt.Errorf("unsupported TLV length encoding 0x%02X", buf[i])
		}
		if i+L > len(buf) {
			return nil, fmt.Errorf("truncated TLV value (need %d bytes, have %d)", L, len(buf)-i)
		}
		if t == tag {
			return buf[i : i+L], nil
		}
		i += L
	}
	return nil, fmt.Errorf("tag 0x%02X not found", tag)
}
