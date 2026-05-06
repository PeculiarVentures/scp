// Package gp provides GlobalPlatform card-content management primitives
// for use with the existing securitydomain.Session secure-channel API.
//
// Scope of this package:
//
//   - AID parsing, validation, and length-value encoding.
//   - CAP file inspection (ZIP-based parser for Header.cap and Applet.cap).
//   - Trace event model for APDU debugging.
//
// What is NOT in this package:
//
//   - Registry data types. Use securitydomain.RegistryEntry,
//     securitydomain.Privileges, securitydomain.LifecycleState, and
//     securitydomain.StatusScope.
//   - GET STATUS construction. Use securitydomain.Session.GetStatus,
//     which already handles continuation (SW=6310), the legacy/tagged
//     P2 fallback (SW=6A86), and empty-scope (SW=6A88) cases.
//   - SCP03 key configuration. Use scp03.StaticKeys plus the existing
//     registerSCP03KeyFlags helper in cmd/scpctl.
//   - Session abstraction. Card-content management methods extend
//     securitydomain.Session directly when added (Install, Delete);
//     this package provides only the pure command builders they call.
//
// Dependency direction. The gp package is a leaf utility: it depends
// only on the standard library. It does NOT import securitydomain.
// When destructive applet management lands in future work,
// securitydomain will import gp for CAPFile and command-builder
// types. cmd/scpctl composes both layers for operator-facing
// commands.
//
// # License posture
//
// Implementation is derived only from the GlobalPlatform Card
// Specification v2.3.1, ISO/IEC 7816-4 and 7816-5, Java Card VM
// specifications, and APDU traces independently captured against
// our own test cards. Contributors do not consult the source code,
// comments, log formats, or test fixtures of any GPL-, AGPL-, or
// LGPL-licensed GlobalPlatform implementation. This includes but
// is not limited to GlobalPlatformPro (LGPL-3.0), jCardSim
// (AGPL-3.0), and OpenSC GP modules (LGPL-2.1).
package gp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// AID is a GlobalPlatform Application Identifier per ISO/IEC 7816-5.
// Length is constrained to 5..16 bytes by the same standard.
//
// Storing as a byte slice rather than a fixed array keeps the type
// printable, copyable, and hex-roundtrippable without ceremony, at
// the cost of allowing the zero value (a nil slice) to exist. Use
// ValidateAID before treating an AID as authoritative; constructors
// in this package call it for the caller.
type AID []byte

// MinAIDLength is the ISO/IEC 7816-5 minimum AID length.
const MinAIDLength = 5

// MaxAIDLength is the ISO/IEC 7816-5 maximum AID length. The same
// length is the upper bound on a single-byte length-value encoding,
// which is why ParseAIDHex and LV do not need to handle multi-byte
// length encoding for AIDs.
const MaxAIDLength = 16

// ValidateAID returns an error when the byte slice is outside the
// 5..16 byte range fixed by ISO/IEC 7816-5. A zero-length slice
// returns the same shape of error as a too-long slice; callers that
// need to distinguish "no AID supplied" from "supplied AID too short"
// should check len(a) == 0 themselves first.
func ValidateAID(a []byte) error {
	if len(a) < MinAIDLength || len(a) > MaxAIDLength {
		return fmt.Errorf("aid length %d invalid (must be %d..%d per ISO/IEC 7816-5)",
			len(a), MinAIDLength, MaxAIDLength)
	}
	return nil
}

// ParseAIDHex decodes an AID from its hex string representation.
// Common separators (space, colon, hyphen, underscore) are stripped
// before decoding so the same function accepts the formats real
// operators paste in: "A0000001510000", "a0:00:00:01:51:00:00:00",
// "A0 00 00 01 51 00 00 00".
//
// Decoded AIDs are validated before return; an out-of-range length
// produces a clear error rather than a nil slice.
func ParseAIDHex(s string) (AID, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '-', '_':
			return -1
		default:
			return r
		}
	}, s)

	if len(cleaned) == 0 {
		return nil, fmt.Errorf("aid hex is empty")
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("aid hex %q has odd length %d", s, len(cleaned))
	}

	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode aid hex %q: %w", s, err)
	}
	if err := ValidateAID(b); err != nil {
		return nil, err
	}
	return AID(b), nil
}

// Bytes returns a copy of the AID's bytes. Callers that need to
// mutate the returned slice can do so without affecting the AID.
func (a AID) Bytes() []byte {
	if len(a) == 0 {
		return nil
	}
	out := make([]byte, len(a))
	copy(out, a)
	return out
}

// String returns the uppercase hex encoding of the AID with no
// separators. Stable across Go versions; suitable for log and trace
// output and for direct use as a map key.
func (a AID) String() string {
	return strings.ToUpper(hex.EncodeToString(a))
}

// LV returns the length-value encoding of the AID: a single length
// byte followed by the AID bytes. Used as a payload component in
// every GP command that requires an AID — INSTALL [for load],
// INSTALL [for install], DELETE. Single-byte length is sufficient
// because AIDs are bounded at 16 bytes by ISO/IEC 7816-5; no BER
// long-form length encoding is needed.
//
// LV is fail-closed on an invalid AID. An empty AID (or an AID
// outside the 5..16 byte range) returns an error rather than a
// silently-malformed encoding. Callers that need the GP "no AID
// match criterion" form (one-byte 0x00, used by GET STATUS as
// "match all AIDs") must use EmptyAIDLV explicitly so the choice
// is visible at the call site.
func (a AID) LV() ([]byte, error) {
	if err := ValidateAID(a); err != nil {
		return nil, fmt.Errorf("aid LV: %w", err)
	}
	out := make([]byte, 1+len(a))
	out[0] = byte(len(a))
	copy(out[1:], a)
	return out, nil
}

// EmptyAIDLV returns the GP "no AID criterion" length-value
// encoding: a single 0x00 byte representing AID_length=0 with no
// AID bytes following. Used in GET STATUS as "match all entries
// in this scope." Distinct from a nil slice or from AID.LV()
// returning an error: the empty-LV form is a meaningful wire
// value, not the absence of an AID.
func EmptyAIDLV() []byte {
	return []byte{0x00}
}

// Equal reports whether two AIDs have the same bytes. Provided for
// readability over bytes.Equal in call sites that work with AID
// values throughout.
func (a AID) Equal(other AID) bool {
	if len(a) != len(other) {
		return false
	}
	for i := range a {
		if a[i] != other[i] {
			return false
		}
	}
	return true
}
