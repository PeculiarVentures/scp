// Package piv: shared types, constants, and parsers.
//
// This file holds the named-type surface that callers (CLI, session,
// profile, server-side provisioning code) use when they want type
// safety beyond the bare byte constants in piv.go. The byte constants
// in piv.go are retained for compatibility within this module and are
// the authoritative wire values; the named-type constants here are
// thin typed aliases that compare equal at the wire level.
//
// Parsers in this file are the canonical place for command-line and
// configuration-file callers to turn user-facing strings ("9a",
// "eccp256", "aes192", "default") into the values the protocol
// actually emits. They were originally inlined into the smoke CLI;
// lifting them here lets non-CLI callers use the same vocabulary.
package piv

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Slot is a PIV slot identifier (NIST SP 800-73-4 Part 1, Table 4b).
type Slot byte

// Slot constants. These match the byte-typed Slot* constants in
// piv.go at the wire level; the named-type form is preferred in new
// code.
const (
	SlotPIVAuthentication Slot = 0x9A
	SlotDigitalSignature  Slot = 0x9C
	SlotKeyMgmt           Slot = 0x9D
	SlotCardAuthentication Slot = 0x9E

	// Retired key management slots 1..20 (0x82..0x95).
	SlotRetiredKeyMgmt1  Slot = 0x82
	SlotRetiredKeyMgmt20 Slot = 0x95

	// YubiKey-specific.
	SlotYubiKeyAttestation Slot = 0xF9
)

// Byte returns the wire byte for the slot.
func (s Slot) Byte() byte { return byte(s) }

// String returns a short descriptive name. Unknown slots render as
// hex.
func (s Slot) String() string {
	switch s {
	case SlotPIVAuthentication:
		return "9a (PIV Authentication)"
	case SlotDigitalSignature:
		return "9c (Digital Signature)"
	case SlotKeyMgmt:
		return "9d (Key Management)"
	case SlotCardAuthentication:
		return "9e (Card Authentication)"
	case SlotYubiKeyAttestation:
		return "f9 (YubiKey Attestation)"
	}
	if s >= SlotRetiredKeyMgmt1 && s <= SlotRetiredKeyMgmt20 {
		return fmt.Sprintf("%02x (Retired Key Mgmt %d)", byte(s), int(s)-int(SlotRetiredKeyMgmt1)+1)
	}
	return fmt.Sprintf("%02x", byte(s))
}

// IsRetired reports whether s is one of the 20 retired key management
// slots.
func (s Slot) IsRetired() bool {
	return s >= SlotRetiredKeyMgmt1 && s <= SlotRetiredKeyMgmt20
}

// IsYubiKeyOnly reports whether s exists only on YubiKey profiles.
// SP 800-73-4 does not define an attestation slot.
func (s Slot) IsYubiKeyOnly() bool {
	return s == SlotYubiKeyAttestation
}

// ParseSlot parses a hex byte (case-insensitive, optional 0x prefix)
// into a recognized Slot. The friendly aliases used by the smoke CLI
// (no aliases beyond the hex form today) can be added here without
// breaking callers.
func ParseSlot(s string) (Slot, error) {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	v, err := strconv.ParseUint(raw, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("piv: slot %q is not a valid hex byte", s)
	}
	slot := Slot(v)
	switch slot {
	case SlotPIVAuthentication, SlotDigitalSignature, SlotKeyMgmt,
		SlotCardAuthentication, SlotYubiKeyAttestation:
		return slot, nil
	}
	if slot.IsRetired() {
		return slot, nil
	}
	return 0, fmt.Errorf(
		"piv: slot 0x%02X is not recognized "+
			"(9a/9c/9d/9e for primary slots, 82-95 for retired key management 1-20, "+
			"or f9 for YubiKey attestation)", byte(slot))
}

// Algorithm is a PIV key algorithm identifier (NIST SP 800-78-4 plus
// YubiKey extensions for Ed25519 and X25519).
type Algorithm byte

const (
	AlgorithmRSA2048 Algorithm = 0x07
	AlgorithmECCP256 Algorithm = 0x11
	AlgorithmECCP384 Algorithm = 0x14

	// YubiKey 5.7+ extensions; not in SP 800-78-4.
	AlgorithmEd25519 Algorithm = 0xE0
	AlgorithmX25519  Algorithm = 0xE1
)

// Byte returns the wire byte for the algorithm.
func (a Algorithm) Byte() byte { return byte(a) }

// String returns a short descriptive name.
func (a Algorithm) String() string {
	switch a {
	case AlgorithmRSA2048:
		return "RSA-2048"
	case AlgorithmECCP256:
		return "ECC P-256"
	case AlgorithmECCP384:
		return "ECC P-384"
	case AlgorithmEd25519:
		return "Ed25519"
	case AlgorithmX25519:
		return "X25519"
	}
	return fmt.Sprintf("0x%02X", byte(a))
}

// IsStandardPIV reports whether a is defined by SP 800-78-4. Ed25519
// and X25519 are YubiKey 5.7+ extensions and return false.
func (a Algorithm) IsStandardPIV() bool {
	switch a {
	case AlgorithmRSA2048, AlgorithmECCP256, AlgorithmECCP384:
		return true
	}
	return false
}

// ParseAlgorithm accepts the friendly forms used by the existing
// smoke CLI: rsa2048, eccp256/ecc-p256/p256, eccp384/ecc-p384/p384,
// ed25519, x25519. Case insensitive.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "rsa2048", "rsa-2048":
		return AlgorithmRSA2048, nil
	case "eccp256", "ecc-p256", "p256":
		return AlgorithmECCP256, nil
	case "eccp384", "ecc-p384", "p384":
		return AlgorithmECCP384, nil
	case "ed25519":
		return AlgorithmEd25519, nil
	case "x25519":
		return AlgorithmX25519, nil
	}
	return 0, fmt.Errorf(
		"piv: algorithm %q not recognized (rsa2048, eccp256, eccp384, ed25519, x25519)", s)
}

// PINPolicy controls how often the PIN must be presented before a
// PIN-gated operation. Values 0x00..0x03 are the YubiKey baseline;
// 0x04 (Match) is YubiKey 5.7+.
type PINPolicy byte

const (
	PINPolicyDefaultPIV PINPolicy = 0x00
	PINPolicyNeverPIV   PINPolicy = 0x01
	PINPolicyOncePIV    PINPolicy = 0x02
	PINPolicyAlwaysPIV  PINPolicy = 0x03
	PINPolicyMatchPIV   PINPolicy = 0x04 // YubiKey 5.7+
)

// Byte returns the wire byte.
func (p PINPolicy) Byte() byte { return byte(p) }

// String returns a short descriptive name.
func (p PINPolicy) String() string {
	switch p {
	case PINPolicyDefaultPIV:
		return "default"
	case PINPolicyNeverPIV:
		return "never"
	case PINPolicyOncePIV:
		return "once"
	case PINPolicyAlwaysPIV:
		return "always"
	case PINPolicyMatchPIV:
		return "match"
	}
	return fmt.Sprintf("0x%02X", byte(p))
}

// IsStandardPIV reports whether p is part of SP 800-73-4. PIN policy
// is a YubiKey extension; SP 800-73-4 has no PIN policy field. All
// values therefore return false. The method is provided so the
// profile layer can refuse non-default values cleanly when running
// under the Standard PIV profile.
func (p PINPolicy) IsStandardPIV() bool { return false }

// ParsePINPolicy accepts default/never/once/always/match (case
// insensitive).
func ParsePINPolicy(s string) (PINPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return PINPolicyDefaultPIV, nil
	case "never":
		return PINPolicyNeverPIV, nil
	case "once":
		return PINPolicyOncePIV, nil
	case "always":
		return PINPolicyAlwaysPIV, nil
	case "match":
		return PINPolicyMatchPIV, nil
	}
	return 0, fmt.Errorf(
		"piv: pin-policy %q not recognized (default, never, once, always, match)", s)
}

// TouchPolicy controls whether the user must physically touch the
// card to authorize a private-key operation. YubiKey extension; SP
// 800-73-4 has no equivalent.
type TouchPolicy byte

const (
	TouchPolicyDefaultPIV TouchPolicy = 0x00
	TouchPolicyNeverPIV   TouchPolicy = 0x01
	TouchPolicyAlwaysPIV  TouchPolicy = 0x02
	TouchPolicyCachedPIV  TouchPolicy = 0x03
)

// Byte returns the wire byte.
func (t TouchPolicy) Byte() byte { return byte(t) }

// String returns a short descriptive name.
func (t TouchPolicy) String() string {
	switch t {
	case TouchPolicyDefaultPIV:
		return "default"
	case TouchPolicyNeverPIV:
		return "never"
	case TouchPolicyAlwaysPIV:
		return "always"
	case TouchPolicyCachedPIV:
		return "cached"
	}
	return fmt.Sprintf("0x%02X", byte(t))
}

// IsStandardPIV reports whether t is part of SP 800-73-4. Touch
// policy is a YubiKey extension; always returns false.
func (t TouchPolicy) IsStandardPIV() bool { return false }

// ParseTouchPolicy accepts default/never/always/cached (case
// insensitive).
func ParseTouchPolicy(s string) (TouchPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return TouchPolicyDefaultPIV, nil
	case "never":
		return TouchPolicyNeverPIV, nil
	case "always":
		return TouchPolicyAlwaysPIV, nil
	case "cached":
		return TouchPolicyCachedPIV, nil
	}
	return 0, fmt.Errorf(
		"piv: touch-policy %q not recognized (default, never, always, cached)", s)
}

// ManagementKeyAlgorithm identifies the cipher used for the PIV
// management key (NIST SP 800-78-4 §3.1). 3DES is the historical
// SP 800-78 default; AES-128/192/256 are the current options.
type ManagementKeyAlgorithm byte

const (
	ManagementKeyAlg3DES   ManagementKeyAlgorithm = 0x03
	ManagementKeyAlgAES128 ManagementKeyAlgorithm = 0x08
	ManagementKeyAlgAES192 ManagementKeyAlgorithm = 0x0A
	ManagementKeyAlgAES256 ManagementKeyAlgorithm = 0x0C
)

// Byte returns the wire byte.
func (m ManagementKeyAlgorithm) Byte() byte { return byte(m) }

// String returns a short descriptive name.
func (m ManagementKeyAlgorithm) String() string {
	switch m {
	case ManagementKeyAlg3DES:
		return "3DES"
	case ManagementKeyAlgAES128:
		return "AES-128"
	case ManagementKeyAlgAES192:
		return "AES-192"
	case ManagementKeyAlgAES256:
		return "AES-256"
	}
	return fmt.Sprintf("0x%02X", byte(m))
}

// KeyLen returns the expected key length in bytes for m.
func (m ManagementKeyAlgorithm) KeyLen() int {
	switch m {
	case ManagementKeyAlg3DES:
		return 24
	case ManagementKeyAlgAES128:
		return 16
	case ManagementKeyAlgAES192:
		return 24
	case ManagementKeyAlgAES256:
		return 32
	}
	return 0
}

// ParseManagementKeyAlgorithm accepts 3des/tdes, aes128/aes-128,
// aes192/aes-192, aes256/aes-256 (case insensitive).
func ParseManagementKeyAlgorithm(s string) (ManagementKeyAlgorithm, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "3des", "tdes":
		return ManagementKeyAlg3DES, nil
	case "aes128", "aes-128":
		return ManagementKeyAlgAES128, nil
	case "aes192", "aes-192":
		return ManagementKeyAlgAES192, nil
	case "aes256", "aes-256":
		return ManagementKeyAlgAES256, nil
	}
	return 0, fmt.Errorf(
		"piv: management-key algorithm %q not recognized (3des, aes128, aes192, aes256)", s)
}

// ManagementKey is a PIV management key plus its algorithm. The Label
// field is a free-form display label used in reports; it is not sent
// to the card.
type ManagementKey struct {
	Algorithm ManagementKeyAlgorithm
	Key       []byte
	Label     string
}

// Validate reports whether mk is internally consistent: the Key
// length must match the Algorithm's expected length.
func (mk ManagementKey) Validate() error {
	want := mk.Algorithm.KeyLen()
	if want == 0 {
		return fmt.Errorf("piv: management-key algorithm 0x%02X is not recognized", byte(mk.Algorithm))
	}
	if len(mk.Key) != want {
		return fmt.Errorf("piv: management-key length %d does not match algorithm %s (want %d bytes)",
			len(mk.Key), mk.Algorithm, want)
	}
	return nil
}

// ParseManagementKey decodes a hex-encoded key string and binds it
// to the named algorithm. The literal string "default" is accepted
// for 3DES and AES-192 only, where it resolves to the well-known
// pre-rotation YubiKey factory value (24 bytes,
// 010203040506070801020304050607080102030405060708). For AES-128 and
// AES-256 the well-known value does not apply (different key
// lengths) and "default" is rejected.
//
// Whitespace, colons, and hyphens are stripped from the hex for
// paste-from-docs convenience.
func ParseManagementKey(hexStr, algoStr string) (ManagementKey, error) {
	algo, err := ParseManagementKeyAlgorithm(algoStr)
	if err != nil {
		return ManagementKey{}, err
	}
	var key []byte
	if strings.EqualFold(strings.TrimSpace(hexStr), "default") {
		if algo != ManagementKeyAlg3DES && algo != ManagementKeyAlgAES192 {
			return ManagementKey{}, fmt.Errorf(
				"piv: management-key=default is only valid with algorithm=3des or aes192 " +
					"(the well-known default value is 24 bytes; AES-128 and AES-256 use different key lengths)")
		}
		key = append([]byte{}, DefaultMgmtKey...)
	} else {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(hexStr)
		key, err = hex.DecodeString(clean)
		if err != nil {
			return ManagementKey{}, fmt.Errorf("piv: management-key not valid hex: %w", err)
		}
	}
	mk := ManagementKey{Algorithm: algo, Key: key, Label: algo.String()}
	if err := mk.Validate(); err != nil {
		return ManagementKey{}, err
	}
	return mk, nil
}

// ObjectID is a BER-TLV tag identifying a PIV data object (NIST
// SP 800-73-4 Part 1 Table 3). Standard objects use 3-byte tags
// starting with 0x5F 0xC1 (e.g. 5FC105 = X.509 Cert for PIV
// Authentication). YubiKey extensions reuse the same encoding for
// vendor objects.
type ObjectID []byte

// String renders the object ID as lowercase hex.
func (o ObjectID) String() string {
	return hex.EncodeToString(o)
}

// Equal reports whether o and other are the same object ID.
func (o ObjectID) Equal(other ObjectID) bool {
	if len(o) != len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

// ParseObjectID parses a hex-encoded PIV object ID. Whitespace and
// 0x prefixes are stripped. Length is not constrained beyond
// non-empty; callers that require the canonical 3-byte standard form
// can inspect the returned slice.
func ParseObjectID(s string) (ObjectID, error) {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if raw == "" {
		return nil, fmt.Errorf("piv: object-id is empty")
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("piv: object-id %q is not valid hex: %w", s, err)
	}
	return ObjectID(b), nil
}
