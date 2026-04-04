// Package kdf implements the key derivation functions used by SCP11.
//
// SCP11 uses two KDF stages:
//
//  1. X9.63 KDF (BSI TR-03111 variant) to derive a master key from the
//     concatenated ECDH shared secrets (ShSee and ShSes for SCP11a,
//     just ShSee for SCP11b).
//
//  2. NIST SP 800-108 KDF in counter mode with AES-CMAC as the PRF to
//     derive individual session keys (S-ENC, S-MAC, S-RMAC, DEK) from
//     the master key.
//
// This implementation follows the combined approach where both
// hash-based derivation for SCP11b (since there's only one shared secret
// plus the SD static key). This implementation follows that model while
// stages are merged for the common AES-128 case.
package kdf

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"github.com/PeculiarVentures/scp/cmac"
)

// SCP11 constants per GP Amendment F §7.6-7.7 and Amendment D §6.2.
const (
	KeyUsage      = 0x3C // C-MAC, R-MAC, encryption
	KeyTypeAES    = 0x88
	SessionKeyLen = 16 // AES-128

	// Derivation constants for NIST 800-108 KDF (GP SCP03 §6.2.2)
	DerivConstSENC  = 0x04
	DerivConstSMAC  = 0x06
	DerivConstSRMAC = 0x07
	DerivConstDEK   = 0x08
)

// SessionKeys holds the derived session keys for SCP11 secure messaging.
type SessionKeys struct {
	SENC     []byte // Session encryption key (AES-128)
	SMAC     []byte // Session C-MAC key
	SRMAC    []byte // Session R-MAC key
	DEK      []byte // Data encryption key
	Receipt  []byte // Key confirmation receipt (for SCP11a/c)
	MACChain []byte // Initial MAC chaining value (all zeros)
}

// X963KDF implements the X9.63 Key Derivation Function as specified in
// BSI TR-03111 and used by GP SCP11 for deriving key material from ECDH
// shared secrets.
//
// The derivation is: key = SHA-256(Z || counter || sharedInfo)
// repeated with incrementing counter until enough bytes are produced.
//
// The derivation follows GP SCP11 §3.1.2 where:
//   - Z = ShSee || ShSes (or just ShSee for SCP11b)
//   - sharedInfo = key_usage || key_type || key_len
func X963KDF(sharedSecret []byte, sharedInfo []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 || keyLen > 256 {
		return nil, fmt.Errorf("invalid key length: %d", keyLen)
	}

	hashLen := sha256.Size
	iterations := (keyLen + hashLen - 1) / hashLen
	var derived []byte

	for counter := 1; counter <= iterations; counter++ {
		h := sha256.New()
		h.Write(sharedSecret)

		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], uint32(counter))
		h.Write(counterBytes[:])

		h.Write(sharedInfo)
		derived = append(derived, h.Sum(nil)...)
	}

	return derived[:keyLen], nil
}

// DeriveSessionKeysFromSharedSecrets performs the full SCP11 key derivation.
//
// For SCP11b (single ECDH):
//   - shSee: ECDH(ePK.OCE, eSK.SD) — ephemeral-ephemeral shared secret
//   - shSes: ECDH(ePK.OCE, SK.SD)  — ephemeral-static shared secret
//   - Both are derived using the OCE ephemeral private key
//
// The combined hash input is: ShSee || ShSes || counter(4B) || sharedInfo
// The hash input is: Z || counter(4B) || sharedInfo
//
// GP SCP11 §3.1.2: SharedInfo = keyUsage || keyType || keyLength
// Optionally followed by: len(hostID) || hostID || len(cardGroupID) || cardGroupID
//
// Returns 5 keys × 16 bytes = 80 bytes total:
//   - Receipt key (16B), S-ENC (16B), S-MAC (16B), S-RMAC (16B), DEK (16B)
func DeriveSessionKeysFromSharedSecrets(shSee, shSes []byte, hostID, cardGroupID []byte) (*SessionKeys, error) {
	if len(shSee) == 0 {
		return nil, errors.New("ShSee cannot be empty")
	}

	ecdhLen := len(shSee)

	// Build SharedInfo: keyUsage || keyType || keyLength [|| hostIDLen || hostID] [|| cardGroupIDLen || cardGroupID]
	sharedInfo := []byte{KeyUsage, KeyTypeAES, SessionKeyLen}
	if len(hostID) > 0 {
		sharedInfo = append(sharedInfo, byte(len(hostID)))
		sharedInfo = append(sharedInfo, hostID...)
	}
	if len(cardGroupID) > 0 {
		sharedInfo = append(sharedInfo, byte(len(cardGroupID)))
		sharedInfo = append(sharedInfo, cardGroupID...)
	}

	// Total keys needed: 5 × 16 = 80 bytes.
	// SHA-256 produces 32 bytes per iteration, so 3 iterations give 96 bytes.
	totalKeyMaterial := 5 * SessionKeyLen

	// Build the concatenated shared secret: ShSee || ShSes
	z := make([]byte, 0, ecdhLen*2)
	z = append(z, shSee...)
	if len(shSes) > 0 {
		if len(shSes) != ecdhLen {
			return nil, fmt.Errorf("ShSes length mismatch: got %d, expected %d", len(shSes), ecdhLen)
		}
		z = append(z, shSes...)
	}

	keyMaterial, err := X963KDF(z, sharedInfo, totalKeyMaterial)

	zeroBytes(z)

	if err != nil {
		return nil, fmt.Errorf("X9.63 KDF failed: %w", err)
	}

	// Copy keys out of keyMaterial into separate slices, then zero keyMaterial.
	// This limits the window where all 5 keys exist in a single contiguous buffer.
	keys := &SessionKeys{
		Receipt:  make([]byte, 16),
		SENC:     make([]byte, 16),
		SMAC:     make([]byte, 16),
		SRMAC:    make([]byte, 16),
		DEK:      make([]byte, 16),
		MACChain: make([]byte, 16),
	}
	copy(keys.Receipt, keyMaterial[0:16])
	copy(keys.SENC, keyMaterial[16:32])
	copy(keys.SMAC, keyMaterial[32:48])
	copy(keys.SRMAC, keyMaterial[48:64])
	copy(keys.DEK, keyMaterial[64:80])
	zeroBytes(keyMaterial)

	return keys, nil
}

// zeroBytes overwrites a byte slice with zeros.
//
//go:noinline
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// DeriveSCP03SessionKey derives a single session key using the NIST SP
// 800-108 KDF in counter mode, as specified in GP SCP03 §6.2.2. This is
// used for session key diversification in SCP03 and can also be used as
// an alternative derivation path in SCP11.
//
// The input to AES-CMAC is:
//
//	label(12B) || 0x00 || L(2B) || counter(1B) || context
//
// Where label = 11 zero bytes || derivation_constant.
func DeriveSCP03SessionKey(baseKey []byte, derivConst byte, context []byte, keyLenBits int) ([]byte, error) {
	keyLenBytes := keyLenBits / 8
	if keyLenBytes != 16 && keyLenBytes != 24 && keyLenBytes != 32 {
		return nil, fmt.Errorf("unsupported key length: %d bits", keyLenBits)
	}

	iterations := (keyLenBytes + 15) / 16 // AES-CMAC output is 16 bytes
	var derived []byte

	for counter := byte(1); counter <= byte(iterations); counter++ {
		// Build the CMAC input per SP 800-108 / GP SCP03:
		// label: 11 bytes of 0x00 + derivation constant
		var input []byte
		input = append(input, make([]byte, 11)...)
		input = append(input, derivConst)
		input = append(input, 0x00) // separation indicator

		// L: key length in bits, big-endian 2 bytes
		input = append(input, byte(keyLenBits>>8), byte(keyLenBits))
		input = append(input, counter)
		input = append(input, context...)

		mac, err := cmac.AESCMAC(baseKey, input)
		if err != nil {
			return nil, fmt.Errorf("AES-CMAC failed: %w", err)
		}
		derived = append(derived, mac...)
	}

	return derived[:keyLenBytes], nil
}

// ComputeReceipt calculates the key confirmation receipt using AES-CMAC
// over the key agreement data, as specified in GP SCP11 §3.1.2.
//
// The receipt input is: MUTUAL_AUTH_command_data || ePK.SD.ECKA_TLV
// where command_data is the TLV-encoded data field sent in the MUTUAL/
// INTERNAL AUTHENTICATE command, and ePK.SD.ECKA_TLV is the card's
// ephemeral public key response TLV (tag 5F49 + value).
func ComputeReceipt(receiptKey []byte, keyAgreementData []byte) ([]byte, error) {
	if len(receiptKey) != 16 {
		return nil, errors.New("receipt key must be 16 bytes")
	}

	mac, err := cmac.AESCMAC(receiptKey, keyAgreementData)
	if err != nil {
		return nil, err
	}

	return mac, nil
}

// VerifyReceipt checks a receipt from the card against the expected value.
func VerifyReceipt(receiptKey []byte, keyAgreementData, receipt []byte) error {
	expected, err := ComputeReceipt(receiptKey, keyAgreementData)
	if err != nil {
		return err
	}

	if !constantTimeEqual(expected, receipt) {
		return errors.New("receipt verification failed: possible MITM or key mismatch")
	}
	return nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Pad applies ISO 9797-1 Method 2 padding (0x80 followed by zeros)
// to reach a multiple of blockSize.
func Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - ((len(data) + 1) % blockSize)
	if padLen == blockSize {
		padLen = 0
	}
	padded := make([]byte, len(data)+1+padLen)
	copy(padded, data)
	padded[len(data)] = 0x80
	return padded
}

// Unpad removes ISO 9797-1 Method 2 padding.
func Unpad(data []byte) ([]byte, error) {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		if data[i] != 0x00 {
			return nil, errors.New("invalid padding")
		}
	}
	return nil, errors.New("padding marker not found")
}

// Verify that AES block size matches expectations at init time.
func init() {
	if aes.BlockSize != 16 {
		panic("expected AES block size of 16")
	}
}
