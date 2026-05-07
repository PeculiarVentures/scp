// Package cardcaps parses Card Capability Information per
// GlobalPlatform Card Spec v2.3.1 §H.4 (tag 0x67).
//
// Card Capability Information is the unauthenticated GET DATA object
// at tag 0x67 that enumerates the SCP versions a card supports, the
// AES key sizes available for SCP03, the GP privileges the card
// implements, the hash algorithms the card supports for Load File
// Data Block hash verification, and the cipher suites the card
// supports for Token Verification, Receipt Generation, and DAP
// Verification. The information is informational, not security-
// relevant in itself: a card that lies about its capabilities is
// the card's bug, not a host-side trust failure. Reading Card
// Capabilities lets an operator see at a glance what a card claims
// to support without authenticating to it.
//
// # Hardware coverage
//
// The parser is validated against bytes captured from a SafeNet
// Token JC (Athena IDProtect platform, GP 2.3, SCP03 i=0x10) on
// 2026-05-08. gppro v25.10.20 produces the same SCP-version and
// hash-algorithm decode against the same bytes, which gives the
// implementation a cross-tool ground truth. YubiKey 5.x and the
// SafeNet eToken Fusion both return SW=6A88 for tag 0x67, so this
// parser does not exercise their behavior.
//
// # The doubled-67 wrapper
//
// A behaviorally important quirk: at least the SafeNet Token JC's
// Card Capability Information response begins with two nested
// "tag 0x67" TLV headers — `67 LL_outer 67 LL_inner ...`. gppro
// silently strips the outer wrapper and warns "Bogus data detected,
// fixing double tag." Whether this is firmware non-conformance or a
// spec ambiguity isn't fully clear; either way, callers that pass
// raw GET DATA bytes to Parse get the doubled wrapper unwrapped
// transparently. Parse accepts both shapes (with or without the
// outer wrapper) without surfacing the difference.
//
// # Scope of this parser (tier 1)
//
// This parser decodes the structural parts of the response that
// are unambiguous against the captured bytes and gppro's decoded
// output:
//
//   - SCP entries: version byte, supported i-parameter values,
//     optional AES key-size bitmap.
//   - Hash algorithms: GP-defined IDs decoded into named values.
//
// The privilege bitmaps (DOM and APP) and the Token / Receipt / DAP
// cipher suite bitmaps are returned as raw bytes without semantic
// naming. gppro labels each bit, but this parser's authors have
// not cross-validated those labels against GP §H.4 directly, and
// gppro has been observed to produce wrong decodes elsewhere in
// this session (CPLC date-resolution bug). Callers that need
// named privileges supply their own bit-to-name table; the raw
// bytes from this package are sufficient input.
package cardcaps

import (
	"errors"
	"fmt"
)

// Tag is the GP Card Spec tag value for Card Capability Information.
const Tag = 0x67

// HashAlgorithm names a hash algorithm advertised under sub-tag 0x83
// (Supported LFDB Hash Algorithms). The integer values match GP
// Card Spec v2.3.1 §H.4 and what gppro decodes for the same bytes.
type HashAlgorithm byte

// Hash algorithm constants. The IDs match GP Card Spec v2.3.1 §H.4
// and gppro's interpretation of the same bytes against a SafeNet
// Token JC.
const (
	HashSHA1   HashAlgorithm = 0x01
	HashSHA256 HashAlgorithm = 0x02
	HashSHA384 HashAlgorithm = 0x03
	HashSHA512 HashAlgorithm = 0x04
)

// String renders a HashAlgorithm as the spec name (SHA-1, SHA-256,
// SHA-384, SHA-512) for known values, or "unknown(0xNN)" for
// unrecognized IDs. Unrecognized IDs are not promoted to errors —
// the parser surfaces them so an operator sees what the card
// actually advertised.
func (h HashAlgorithm) String() string {
	switch h {
	case HashSHA1:
		return "SHA-1"
	case HashSHA256:
		return "SHA-256"
	case HashSHA384:
		return "SHA-384"
	case HashSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("unknown(0x%02X)", byte(h))
	}
}

// SCPEntry describes one Secure Channel Protocol the card supports.
// gppro renders an SCPEntry as e.g. "Supports SCP03 i=00 i=10 with
// AES-128 AES-196 AES-256." The Version field carries the SCP
// number (1, 2, or 3); IValues carries the supported i-parameter
// bytes; KeySizes carries the AES key sizes encoded as a bitmap
// per GP §H.4 — bit 0 = AES-128, bit 1 = AES-192, bit 2 = AES-256.
// KeySizes is nil for SCP entries that don't include a key-size
// sub-element (typical of SCP01 / SCP02 entries; only SCP03 entries
// usually carry it).
type SCPEntry struct {
	// Version is the SCP version number (1, 2, or 3).
	Version byte

	// IValues is the list of supported i-parameter bytes for this
	// SCP version. For SCP03 against the SafeNet Token JC fixture,
	// IValues = [0x00, 0x10]. The mapping of i-parameter bits to
	// modes is SCP-version-specific (e.g. SCP03 bit 0 = S16,
	// bit 4 = pseudorandom card challenge).
	IValues []byte

	// KeySizes is the raw key-size bitmap byte from sub-tag 0x82
	// when present. Bit 0 set means AES-128, bit 1 AES-192, bit 2
	// AES-256. Nil when the SCP entry does not include the sub-
	// element (typical of SCP01 / SCP02 entries on Thales firmware).
	KeySizes []byte
}

// HasAES128 reports whether the SCP entry advertises AES-128
// support. Returns false when KeySizes is nil (no key-size sub-
// element in the entry).
func (e SCPEntry) HasAES128() bool { return e.hasKeySize(0x01) }

// HasAES192 reports whether the SCP entry advertises AES-192
// support. Returns false when KeySizes is nil.
func (e SCPEntry) HasAES192() bool { return e.hasKeySize(0x02) }

// HasAES256 reports whether the SCP entry advertises AES-256
// support. Returns false when KeySizes is nil.
func (e SCPEntry) HasAES256() bool { return e.hasKeySize(0x04) }

func (e SCPEntry) hasKeySize(mask byte) bool {
	if len(e.KeySizes) == 0 {
		return false
	}
	return e.KeySizes[0]&mask != 0
}

// Data is the parsed Card Capability Information.
//
// Privilege and cipher bitmaps are returned as raw bytes because
// the bit-to-name mapping requires GP §H.4 cross-reference that
// hasn't been done in this package. Callers that need names supply
// their own table; the raw bytes are stable input for that mapping.
type Data struct {
	// SCPEntries lists the SCP versions the card advertises, in
	// the order they appeared in the response.
	SCPEntries []SCPEntry

	// DOMPrivileges is the raw bitmap from sub-tag 0x81 listing
	// the GP privileges the card supports for Security Domains.
	// Decoded with caller-supplied name tables.
	DOMPrivileges []byte

	// APPPrivileges is the raw bitmap from sub-tag 0x82 listing
	// the GP privileges the card supports for Applications.
	APPPrivileges []byte

	// HashAlgorithms is the list of hash algorithm IDs from sub-
	// tag 0x83 (Supported LFDB Hash Algorithms). Decoded into
	// named HashAlgorithm values; unknown IDs are preserved as
	// HashAlgorithm(rawByte).
	HashAlgorithms []HashAlgorithm

	// TokenVerificationCiphers is the raw bitmap from sub-tag
	// 0x85 listing the cipher suites the card supports for Token
	// Verification.
	TokenVerificationCiphers []byte

	// ReceiptGenerationCiphers is the raw bitmap from sub-tag
	// 0x86 listing the cipher suites the card supports for
	// Receipt Generation.
	ReceiptGenerationCiphers []byte

	// DAPVerificationCiphers is the raw bitmap from sub-tag 0x87
	// listing the cipher suites the card supports for DAP
	// Verification.
	DAPVerificationCiphers []byte

	// Unknown carries the raw TLV bytes of any sub-tag the parser
	// didn't recognize. Empty in normal cases; populated when a
	// card emits a sub-tag outside the GP §H.4 set this parser
	// implements. Operators see the raw bytes via this field
	// rather than having them silently dropped.
	Unknown []UnknownTLV
}

// UnknownTLV carries an unrecognized sub-element so the operator
// can see what the card emitted without the parser silently
// dropping it.
type UnknownTLV struct {
	// Tag is the TLV tag byte as it appeared in the response.
	Tag byte
	// Value is the value field of the TLV (header stripped).
	Value []byte
}

// Errors returned by Parse.
var (
	// ErrTruncated signals the input ran out of bytes mid-TLV.
	ErrTruncated = errors.New("cardcaps: truncated TLV")

	// ErrInvalidWrapper signals the outer tag/length didn't decode
	// as a Card Capability Information template.
	ErrInvalidWrapper = errors.New("cardcaps: invalid outer wrapper")
)

// Parse decodes Card Capability Information bytes returned by GET
// DATA tag 0x67. Accepts:
//
//   - A bare inner template: 67 LL <60-byte payload>.
//   - The doubled-wrapper form some firmwares emit: 67 LL_outer 67
//     LL_inner <payload>. The outer wrapper is stripped silently;
//     gppro reports this as "Bogus data detected, fixing double tag"
//     and proceeds the same way.
//   - The raw payload without any wrapper. Detected by inspecting
//     the first byte: if it's not 0x67, the input is treated as raw
//     payload and parsed directly.
//
// Returns a populated Data on success, or ErrTruncated /
// ErrInvalidWrapper on malformed input.
func Parse(b []byte) (*Data, error) {
	payload, err := stripOuterWrappers(b)
	if err != nil {
		return nil, err
	}

	d := &Data{}
	for off := 0; off < len(payload); {
		tag := payload[off]
		off++
		if off >= len(payload) {
			return nil, fmt.Errorf("%w: missing length for tag 0x%02X", ErrTruncated, tag)
		}
		length := int(payload[off])
		off++
		if off+length > len(payload) {
			return nil, fmt.Errorf("%w: tag 0x%02X length %d exceeds remaining %d bytes",
				ErrTruncated, tag, length, len(payload)-off)
		}
		value := payload[off : off+length]
		off += length

		switch tag {
		case 0xA0:
			entry, err := parseSCPEntry(value)
			if err != nil {
				return nil, fmt.Errorf("parse SCP entry: %w", err)
			}
			d.SCPEntries = append(d.SCPEntries, entry)
		case 0x81:
			d.DOMPrivileges = append([]byte(nil), value...)
		case 0x82:
			d.APPPrivileges = append([]byte(nil), value...)
		case 0x83:
			d.HashAlgorithms = make([]HashAlgorithm, len(value))
			for i, v := range value {
				d.HashAlgorithms[i] = HashAlgorithm(v)
			}
		case 0x85:
			d.TokenVerificationCiphers = append([]byte(nil), value...)
		case 0x86:
			d.ReceiptGenerationCiphers = append([]byte(nil), value...)
		case 0x87:
			d.DAPVerificationCiphers = append([]byte(nil), value...)
		default:
			d.Unknown = append(d.Unknown, UnknownTLV{
				Tag:   tag,
				Value: append([]byte(nil), value...),
			})
		}
	}
	return d, nil
}

// stripOuterWrappers handles the three accepted input shapes
// described on Parse. Returns the inner payload bytes for the
// caller to iterate.
func stripOuterWrappers(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrTruncated)
	}
	if b[0] != Tag {
		// Treat as raw payload.
		return b, nil
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: outer tag 0x67 without length", ErrTruncated)
	}
	length := int(b[1])
	if 2+length > len(b) {
		return nil, fmt.Errorf("%w: outer length %d exceeds available %d",
			ErrInvalidWrapper, length, len(b)-2)
	}
	inner := b[2 : 2+length]
	// Doubled-67 case: the value begins with another 67 LL header.
	// Strip it transparently.
	if len(inner) >= 2 && inner[0] == Tag {
		innerLen := int(inner[1])
		if 2+innerLen > len(inner) {
			return nil, fmt.Errorf("%w: inner length %d exceeds available %d",
				ErrInvalidWrapper, innerLen, len(inner)-2)
		}
		return inner[2 : 2+innerLen], nil
	}
	return inner, nil
}

// parseSCPEntry decodes one A0-tagged SCP entry. The expected layout
// is 80 LL_v <version> 81 LL_i <i-values> [82 LL_k <key-size-bitmap>]
// per GP §H.4 and the SafeNet Token JC fixture. Sub-tags appearing in
// other orders are tolerated by tag dispatch rather than positional
// reads. Anything beyond the recognized set is silently dropped at
// this level (a future revision may add an Unknown field on
// SCPEntry; today's coverage is sufficient for the 0xA0 entries
// gppro emits and the captured fixtures show).
func parseSCPEntry(value []byte) (SCPEntry, error) {
	var e SCPEntry
	for off := 0; off < len(value); {
		tag := value[off]
		off++
		if off >= len(value) {
			return e, fmt.Errorf("%w: missing length for SCP sub-tag 0x%02X", ErrTruncated, tag)
		}
		length := int(value[off])
		off++
		if off+length > len(value) {
			return e, fmt.Errorf("%w: SCP sub-tag 0x%02X length %d exceeds remaining %d",
				ErrTruncated, tag, length, len(value)-off)
		}
		sub := value[off : off+length]
		off += length

		switch tag {
		case 0x80:
			if length != 1 {
				return e, fmt.Errorf("SCP version sub-tag should be 1 byte, got %d", length)
			}
			e.Version = sub[0]
		case 0x81:
			e.IValues = append([]byte(nil), sub...)
		case 0x82:
			e.KeySizes = append([]byte(nil), sub...)
		}
	}
	return e, nil
}
