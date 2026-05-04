// Package piv implements PIV (NIST SP 800-73-4) command builders for
// the provisioning operations that run over an established SCP11
// secure channel. These are the commands a remote provisioning server
// sends after the handshake completes.
//
// # Scope
//
// The command builders here are tuned for YubiKey 5.x, not the full
// NIST PIV instruction set. Several functions use YubiKey-proprietary
// instructions (IMPORT_KEY = 0xFE, ATTEST = 0xF9, RESET = 0xFB,
// SET_MGMKEY = 0xFF) and YubiKey-specific data layouts. Behavior
// against non-YubiKey PIV applets is unverified.
//
// PIV management-key authentication is intentionally not provided:
// it is a multi-step GENERAL AUTHENTICATE challenge-response that
// the caller must drive directly. A "simplified" single-call helper
// would be wrong both protocol-wise and as a security primitive.
//
// Each function returns a plain *apdu.Command; the session's Transmit
// method wraps it with secure messaging before sending.
package pivapdu

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/tlv"
)

// PIV slot identifiers (NIST SP 800-73-4).
const (
	SlotAuthentication byte = 0x9A // PIV Authentication
	SlotSignature      byte = 0x9C // Digital Signature
	SlotKeyManagement  byte = 0x9D // Key Management
	SlotCardAuth       byte = 0x9E // Card Authentication
	SlotRetired1       byte = 0x82 // Retired Key Management 1 (start of retired range)
	SlotRetired20      byte = 0x95 // Retired Key Management 20 (end of retired range)
	SlotAttestation    byte = 0xF9 // Attestation (YubiKey specific)
)

// Algorithm identifiers for PIV key generation.
const (
	AlgoRSA2048 byte = 0x07
	AlgoECCP256 byte = 0x11
	AlgoECCP384 byte = 0x14
	AlgoEd25519 byte = 0xE0 // YubiKey 5.7+ specific
	AlgoX25519  byte = 0xE1 // YubiKey 5.7+ specific
)

// PIN policy values (YubiKey specific).
const (
	PINPolicyDefault byte = 0x00
	PINPolicyNever   byte = 0x01
	PINPolicyOnce    byte = 0x02
	PINPolicyAlways  byte = 0x03
	PINPolicyMatch   byte = 0x04 // YubiKey 5.7+
)

// Touch policy values (YubiKey specific).
const (
	TouchPolicyDefault byte = 0x00
	TouchPolicyNever   byte = 0x01
	TouchPolicyAlways  byte = 0x02
	TouchPolicyCached  byte = 0x03
)

// GenerateKey builds a GENERATE ASYMMETRIC KEY PAIR command per
// NIST SP 800-73-4 Part 2 §3.3.2.
//
// The response contains the generated public key which should be
// used to build the certificate for injection into the same slot.
func GenerateKey(slot, algorithm byte) *apdu.Command {
	// Data field: tag 0xAC (cryptographic mechanism template)
	// containing tag 0x80 (algorithm reference).
	inner := tlv.Build(tlv.Tag(0x80), []byte{algorithm})
	outer := tlv.BuildConstructed(tlv.Tag(0xAC), inner)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0x47, // GENERATE ASYMMETRIC KEY PAIR
		P1:   0x00,
		P2:   slot,
		Data: outer.Encode(),
		Le:   0,
	}
}

// GenerateKeyWithPolicy builds a key generation command with YubiKey-specific
// PIN and touch policy extensions.
func GenerateKeyWithPolicy(slot, algorithm, pinPolicy, touchPolicy byte) *apdu.Command {
	var children []*tlv.Node
	children = append(children, tlv.Build(tlv.Tag(0x80), []byte{algorithm}))

	if pinPolicy != PINPolicyDefault {
		children = append(children, tlv.Build(tlv.Tag(0xAA), []byte{pinPolicy}))
	}
	if touchPolicy != TouchPolicyDefault {
		children = append(children, tlv.Build(tlv.Tag(0xAB), []byte{touchPolicy}))
	}

	outer := tlv.BuildConstructed(tlv.Tag(0xAC), children...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0x47,
		P1:   0x00,
		P2:   slot,
		Data: outer.Encode(),
		Le:   0,
	}
}

// PutCertificate builds a PUT DATA command to store a certificate in a
// PIV slot. The data object ID for each slot is defined in SP 800-73-4.
func PutCertificate(slot byte, cert *x509.Certificate) (*apdu.Command, error) {
	if cert == nil {
		return nil, errors.New("certificate cannot be nil")
	}

	objID, err := slotToObjectID(slot)
	if err != nil {
		return nil, err
	}

	// Certificate data object structure (SP 800-73-4 Part 1):
	// Tag 0x70: Certificate
	// Tag 0x71: CertInfo (0x00 = uncompressed)
	// Tag 0xFE: Error detection code (empty = no EDC)
	certTLV := tlv.Build(tlv.Tag(0x70), cert.Raw)
	certInfo := tlv.Build(tlv.Tag(0x71), []byte{0x00})
	edc := tlv.Build(tlv.Tag(0xFE), nil)

	// Wrap in the data object tag (0x5C for object ID, 0x53 for data).
	objIDTLV := tlv.Build(tlv.Tag(0x5C), objID)
	dataTLV := tlv.BuildConstructed(tlv.Tag(0x53), certTLV, certInfo, edc)

	var data []byte
	data = append(data, objIDTLV.Encode()...)
	data = append(data, dataTLV.Encode()...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0xDB, // PUT DATA
		P1:   0x3F,
		P2:   0xFF,
		Data: data,
		Le:   -1,
	}, nil
}

// ImportKey builds the YubiKey-specific IMPORT ASYMMETRIC KEY command.
//
// Only NIST P-256 and P-384 EC private keys are supported — the
// algorithm constants for RSA, Ed25519, and X25519 are defined for
// completeness but not implemented here. Pass the raw EC private
// key bytes (32 bytes for P-256, 48 for P-384).
func ImportKey(slot, algorithm byte, keyData []byte) (*apdu.Command, error) {
	if len(keyData) == 0 {
		return nil, errors.New("key data cannot be empty")
	}

	// YubiKey uses algorithm-specific tags for key components.
	var data []byte
	switch algorithm {
	case AlgoECCP256:
		// Tag 0x06: EC private key (32 bytes for P-256)
		if len(keyData) != 32 {
			return nil, fmt.Errorf("P-256 key must be 32 bytes, got %d", len(keyData))
		}
		data = tlv.Build(tlv.Tag(0x06), keyData).Encode()

	case AlgoECCP384:
		// Tag 0x06: EC private key (48 bytes for P-384)
		if len(keyData) != 48 {
			return nil, fmt.Errorf("P-384 key must be 48 bytes, got %d", len(keyData))
		}
		data = tlv.Build(tlv.Tag(0x06), keyData).Encode()

	default:
		return nil, fmt.Errorf("unsupported algorithm for import: 0x%02X", algorithm)
	}

	return &apdu.Command{
		CLA:  0x00,
		INS:  0xFE, // IMPORT ASYMMETRIC KEY (YubiKey specific)
		P1:   algorithm,
		P2:   slot,
		Data: data,
		Le:   -1,
	}, nil
}

// SetManagementKey builds a SET MANAGEMENT KEY command.
// This changes the card's management key, used for administrative operations.
func SetManagementKey(algorithm byte, newKey []byte) (*apdu.Command, error) {
	if len(newKey) == 0 {
		return nil, errors.New("management key cannot be empty")
	}

	// Tag 0x9B: management key
	data := tlv.Build(tlv.Tag(0x9B), newKey)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0xFF,
		P1:   0xFF,
		P2:   0xFF,
		Data: append([]byte{algorithm}, data.Encode()...),
		Le:   -1,
	}, nil
}

// piv.MaxPINLength is defined in the parent piv package
// (piv/types.go) and referenced here as piv.piv.MaxPINLength.

// VerifyPIN builds a VERIFY command for PIN authentication. The PIN
// is padded to 8 bytes with 0xFF.
//
// PINs longer than 8 bytes are rejected — silently truncating would
// have the card see a different value than the caller passed in,
// which is exactly the kind of bug that hides until production.
func VerifyPIN(pin []byte) (*apdu.Command, error) {
	if len(pin) == 0 {
		return nil, errors.New("PIN cannot be empty")
	}
	if len(pin) > piv.MaxPINLength {
		return nil, fmt.Errorf("PIN exceeds %d bytes (got %d)", piv.MaxPINLength, len(pin))
	}
	padded := make([]byte, piv.MaxPINLength)
	for i := range padded {
		padded[i] = 0xFF
	}
	copy(padded, pin)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0x20, // VERIFY
		P1:   0x00,
		P2:   0x80, // PIV Card Application PIN
		Data: padded,
		Le:   -1,
	}, nil
}

// Attest builds an ATTEST command for the given slot (YubiKey specific).
// Returns a certificate signed by the card's attestation key proving
// that the key was generated on-device.
func Attest(slot byte) *apdu.Command {
	return &apdu.Command{
		CLA:  0x00,
		INS:  0xF9,
		P1:   slot,
		P2:   0x00,
		Data: nil,
		Le:   0,
	}
}

// Reset performs a PIV application reset (YubiKey specific).
// Requires both PIN and PUK to be blocked.
func Reset() *apdu.Command {
	return &apdu.Command{
		CLA:  0x00,
		INS:  0xFB,
		P1:   0x00,
		P2:   0x00,
		Data: nil,
		Le:   -1,
	}
}

// slotToObjectID maps PIV slot bytes to their data object IDs
// as defined in SP 800-73-4 Part 1 Table 10.
func slotToObjectID(slot byte) ([]byte, error) {
	switch slot {
	case SlotAuthentication:
		return []byte{0x5F, 0xC1, 0x05}, nil
	case SlotSignature:
		return []byte{0x5F, 0xC1, 0x0A}, nil
	case SlotKeyManagement:
		return []byte{0x5F, 0xC1, 0x0B}, nil
	case SlotCardAuth:
		return []byte{0x5F, 0xC1, 0x01}, nil
	default:
		if slot >= 0x82 && slot <= 0x95 {
			// Retired key management slots 1-20
			idx := slot - 0x82
			return []byte{0x5F, 0xC1, 0x0D + idx}, nil
		}
		return nil, fmt.Errorf("unknown slot: 0x%02X", slot)
	}
}
