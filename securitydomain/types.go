// Package securitydomain implements the GlobalPlatform Security Domain
// management layer for YubiKey devices. It provides typed APIs for
// provisioning, rotating, inspecting, and retiring SCP03 and SCP11
// key material, certificate chains, allowlists, and CA issuer references.
//
// This package sits above the secure channel layer:
//
//	application code
//	  -> securitydomain.Session
//	     -> scp.Session (secure messaging)
//	        -> transport.Transport (PC/SC, NFC, relay, etc.)
//
// A Session wraps an authenticated SCP03 or SCP11 channel to the
// Security Domain and exposes management operations. Some read-only
// operations are available without authentication via OpenUnauthenticated.
//
// # Quick start
//
//	sd, err := securitydomain.Open(ctx, t, scp03.DefaultConfig())
//	if err != nil { ... }
//	defer sd.Close()
//
//	info, err := sd.GetKeyInformation(ctx)
//	err = sd.PutSCP03Key(ctx, ref, keys, 0)
//	certs, err := sd.GetCertificates(ctx, ref)
package securitydomain

import (
	"errors"
	"fmt"
)

// KeyReference identifies a key on the Security Domain by Key ID (KID)
// and Key Version Number (KVN). This matches the GlobalPlatform key
// reference model and Yubico's KeyReference type.
type KeyReference struct {
	ID      byte // Key ID (KID): ScpKeyIds constant
	Version byte // Key Version Number (KVN): 0x01-0x7F, or 0xFF for default
}

// String returns a human-readable key reference like "KID=0x01,KVN=0x03".
func (r KeyReference) String() string {
	return fmt.Sprintf("KID=0x%02X,KVN=0x%02X", r.ID, r.Version)
}

// NewKeyReference creates a KeyReference from a key ID and version number.
func NewKeyReference(id, version byte) KeyReference {
	return KeyReference{ID: id, Version: version}
}

// Well-known Key IDs from the Yubico Security Domain implementation.
// These correspond to ScpKeyIds in the Yubico .NET SDK.
const (
	// KeyIDSCP03 is the Key ID for SCP03 symmetric key sets.
	// SCP03 key sets always use KID=0x01.
	KeyIDSCP03 byte = 0x01

	// KeyIDSCP11a is the Key ID for SCP11a key pairs.
	KeyIDSCP11a byte = 0x13

	// KeyIDSCP11b is the Key ID for SCP11b key pairs.
	KeyIDSCP11b byte = 0x13

	// KeyIDSCP11c is the Key ID for SCP11c key pairs.
	KeyIDSCP11c byte = 0x13

	// KeyIDOCE is the Key ID for Off-Card Entity (OCE) public keys.
	// Used in SCP11a/c for mutual authentication configuration.
	KeyIDOCE byte = 0x10
)

// DefaultSCP03KeyVersion is the KVN of the factory-default SCP03 key set.
// The default keys are publicly known and provide no security.
const DefaultSCP03KeyVersion byte = 0xFF

// KeyInfo holds information about a single key component installed
// on the Security Domain, as returned by GET DATA [Key Information].
// The Yubico SDK returns this as Dictionary<byte, byte> mapping
// component ID to component type/length.
type KeyInfo struct {
	Reference  KeyReference
	Components map[byte]byte // Component ID -> component type
}

// CaIdentifier holds a CA identifier (Subject Key Identifier) associated
// with a key reference, as returned by GetSupportedCaIdentifiers.
type CaIdentifier struct {
	Reference KeyReference
	SKI       []byte
}

// --- Errors ---

var (
	// ErrNotAuthenticated is returned when a management operation is
	// attempted on an unauthenticated session.
	ErrNotAuthenticated = errors.New("securitydomain: session is not authenticated")

	// ErrUnsupported is returned when the connected device does not
	// support the requested operation or protocol.
	ErrUnsupported = errors.New("securitydomain: unsupported capability")

	// ErrInvalidKey is returned when key material fails validation
	// (wrong length, wrong curve, etc.).
	ErrInvalidKey = errors.New("securitydomain: invalid key material")

	// ErrChecksum is returned when the card's PUT KEY response
	// contains a checksum that does not match the expected value.
	ErrChecksum = errors.New("securitydomain: key checksum verification failed")

	// ErrCardStatus is returned when the card returns a non-success
	// status word. The underlying apdu.Response error is wrapped.
	ErrCardStatus = errors.New("securitydomain: card returned error status")

	// ErrInvalidResponse is returned when a card response cannot be
	// parsed as expected TLV structure.
	ErrInvalidResponse = errors.New("securitydomain: invalid response data")

	// ErrInvalidSerial is returned when a certificate serial number
	// string cannot be decoded as hexadecimal.
	ErrInvalidSerial = errors.New("securitydomain: invalid certificate serial number")
)
