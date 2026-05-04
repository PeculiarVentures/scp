// Package cardrecognition parses GlobalPlatform Card Recognition
// Data (CRD) — the tag 0x66 BER-TLV structure a card returns from
// `GET DATA 80CA0066`. CRD is the spec-defined way for a card to
// advertise its GP version, supported SCP version and `i` parameter,
// card identification scheme, and optional configuration / chip /
// trust-point details.
//
// This package is for diagnostics and trace metadata. It does NOT
// drive protocol behavior — the SCP open path still requires an
// explicit Config. Auto-detecting SCP version from CRD has subtle
// security implications (a hostile or buggy card could lie about
// CRD to coerce a downgrade), so callers configure protocol
// explicitly and use CRD only as a check.
//
// References:
//   - GP Card Specification v2.3.1 §H.2 "Structure of Card Recognition Data"
//   - GP OID prefix 1.2.840.114283 (DER: 2A 86 48 86 FC 6B)
package cardrecognition

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// CardInfo is the parsed view of a Card Recognition Data structure.
// All non-pointer fields are zero-valued when absent; presence of
// optional sections is signaled by non-nil byte slices or by
// the boolean Has* flags where appropriate.
//
// The struct is JSON-friendly so it can be embedded in trace headers
// and emitted by diagnostic tooling.
type CardInfo struct {
	// Raw is the full tag 0x66 wire bytes the parser was given.
	// Kept so traces can preserve evidence of what came off the card.
	Raw []byte `json:"raw_hex"`

	// GPVersion is the human-readable GlobalPlatform version
	// (e.g. "2.3.1") parsed from the App-Tag-0 OID. Empty if
	// the OID was absent or malformed.
	GPVersion string `json:"gp_version,omitempty"`

	// GPVersionOID is the full OID for the GP version, dotted form
	// (e.g. "1.2.840.114283.2.2.3.1"). Useful for debugging.
	GPVersionOID string `json:"gp_version_oid,omitempty"`

	// SCP is the Secure Channel Protocol identifier (0x02, 0x03,
	// 0x11, ...). Zero if absent. Note that a card MAY advertise
	// multiple SCP versions; this field reflects the OID actually
	// present in tag 0x64. Cards that support more than one
	// typically expose this through GET DATA tag 0x66 by listing
	// only one preferred protocol.
	SCP byte `json:"scp,omitempty"`

	// SCPParameter is the `i` parameter from the SCP OID. For
	// SCP03 this typically distinguishes implementation options;
	// for SCP02 it encodes the option set. Zero if absent.
	SCPParameter byte `json:"scp_parameter,omitempty"`

	// SCPVersionOID is the full SCP version OID
	// (e.g. "1.2.840.114283.4.3.112" for SCP03, i=0x70).
	SCPVersionOID string `json:"scp_version_oid,omitempty"`

	// CardIDSchemeOID is the OID from App-Tag-3 (Card ID Scheme),
	// dotted form. Cards that follow the GP card-ID scheme set this
	// to "1.2.840.114283.3".
	CardIDSchemeOID string `json:"card_id_scheme_oid,omitempty"`

	// CardConfigurationDetails holds the raw bytes of the optional
	// tag 0x65 (Card Configuration Details) sub-TLV, if present.
	// Format is profile-specific; we expose bytes for downstream
	// inspection rather than guess at structure.
	CardConfigurationDetails []byte `json:"card_configuration_details_hex,omitempty"`

	// ChipDetails holds the raw bytes of the optional inner
	// tag 0x66 (Card / Chip Details). Note: the OUTER tag 0x66 is
	// the Card Data envelope; this is the inner App-Tag-6 whose
	// numeric tag value happens to coincide.
	ChipDetails []byte `json:"chip_details_hex,omitempty"`

	// IssuerTrustPointInfo is tag 0x67, optional. ISD trust point
	// certificate information. Bytes only — format is GP-specific.
	IssuerTrustPointInfo []byte `json:"issuer_trust_point_info_hex,omitempty"`

	// IssuerCertInfo is tag 0x68, optional. ISD certificate
	// information. Bytes only.
	IssuerCertInfo []byte `json:"issuer_cert_info_hex,omitempty"`

	// UnknownTags collects any constructed sub-TLVs inside the
	// Card Recognition Data envelope that this parser doesn't
	// recognize. Map key is the TLV tag, value is the raw bytes.
	// Helpful for diagnosing forward-compat issues without forcing
	// callers to re-parse from Raw.
	UnknownTags map[tlv.Tag][]byte `json:"unknown_tags,omitempty"`
}

// Tag values used inside Card Recognition Data per GP §H.2.
const (
	tagCardData                tlv.Tag = 0x66 // outer envelope returned by GET DATA
	tagCardRecognitionData     tlv.Tag = 0x73 // inner CRD envelope
	tagOID                     tlv.Tag = 0x06 // universal OID tag
	tagAppGPVersion            tlv.Tag = 0x60 // App-Tag-0
	tagAppCardIDScheme         tlv.Tag = 0x63 // App-Tag-3
	tagAppSCPVersion           tlv.Tag = 0x64 // App-Tag-4
	tagAppCardConfigDetails    tlv.Tag = 0x65 // App-Tag-5
	tagAppChipDetails          tlv.Tag = 0x66 // App-Tag-6 (NB: same value as outer)
	tagAppIssuerTrustPointInfo tlv.Tag = 0x67 // App-Tag-7
	tagAppIssuerCertInfo       tlv.Tag = 0x68 // App-Tag-8
)

// gpOIDPrefix is the DER encoding of the GlobalPlatform OID arc
// 1.2.840.114283. All Card Recognition Data OIDs hang off this
// prefix. We compare bytewise rather than re-decode each OID into
// arcs for speed and to keep the parser tiny.
var gpOIDPrefix = []byte{0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B}

// ErrNotPresent is returned when the card responds to GET DATA
// 80CA0066 with a status word indicating the data object is not
// present (typical: 6A 88, 6A 82). It is wrapped with the actual
// status word for callers that want to distinguish.
var ErrNotPresent = errors.New("cardrecognition: tag 0x66 not present on card")

// ErrMalformed is returned when CRD bytes are present but cannot
// be parsed into the expected envelope structure.
var ErrMalformed = errors.New("cardrecognition: malformed Card Recognition Data")

// Parse decodes tag 0x66 wire bytes (as returned by `GET DATA
// 80CA0066`, sans status word) into a *CardInfo.
//
// The parser is permissive about unknown sub-TLVs (collected into
// CardInfo.UnknownTags) and lenient about absent optional fields,
// but strict about the outer envelope: a missing tag 0x66 or a
// missing inner tag 0x73 returns ErrMalformed.
func Parse(data []byte) (*CardInfo, error) {
	if len(data) == 0 {
		return nil, ErrMalformed
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	outer := tlv.Find(nodes, tagCardData)
	if outer == nil {
		return nil, fmt.Errorf("%w: outer tag 0x66 not found", ErrMalformed)
	}

	crd := tlv.Find(outer.Children, tagCardRecognitionData)
	if crd == nil {
		return nil, fmt.Errorf("%w: inner tag 0x73 not found", ErrMalformed)
	}

	info := &CardInfo{
		Raw:         append([]byte(nil), data...),
		UnknownTags: nil,
	}

	for _, child := range crd.Children {
		switch child.Tag {
		case tagOID:
			// The bare OID at top level of CRD is the
			// "Card Recognition Data" identifier itself
			// (1.2.840.114283.1). We accept it without storing —
			// its sole purpose is to identify the structure.
		case tagAppGPVersion:
			if oid := findOID(child); oid != nil {
				info.GPVersionOID = formatOID(oid)
				info.GPVersion = decodeGPVersion(oid)
			}
		case tagAppCardIDScheme:
			if oid := findOID(child); oid != nil {
				info.CardIDSchemeOID = formatOID(oid)
			}
		case tagAppSCPVersion:
			if oid := findOID(child); oid != nil {
				info.SCPVersionOID = formatOID(oid)
				info.SCP, info.SCPParameter = decodeSCPOID(oid)
			}
		case tagAppCardConfigDetails:
			info.CardConfigurationDetails = encodeChildren(child)
		case tagAppChipDetails:
			info.ChipDetails = encodeChildren(child)
		case tagAppIssuerTrustPointInfo:
			info.IssuerTrustPointInfo = encodeChildren(child)
		case tagAppIssuerCertInfo:
			info.IssuerCertInfo = encodeChildren(child)
		default:
			if info.UnknownTags == nil {
				info.UnknownTags = map[tlv.Tag][]byte{}
			}
			info.UnknownTags[child.Tag] = encodeChildren(child)
		}
	}

	return info, nil
}

// Read issues `GET DATA 80CA0066` against t and parses the response.
// The transport must be talking to a target that has been SELECTed
// (typically the ISD); CRD is returned by whatever applet/SD is
// currently selected.
//
// On a card that doesn't expose CRD, Read returns ErrNotPresent
// wrapped around the card's status word. On a malformed response,
// it returns ErrMalformed.
func Read(ctx context.Context, t transport.Transport) (*CardInfo, error) {
	cmd := &apdu.Command{
		CLA: 0x80,
		INS: 0xCA, // GET DATA
		P1:  0x00,
		P2:  0x66, // tag 0x66 — Card Data
		Le:  0,    // request maximum response
	}
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("cardrecognition: GET DATA: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("%w (SW=%04X)", ErrNotPresent, resp.StatusWord())
	}
	return Parse(resp.Data)
}

// findOID returns the value bytes of the first tag-0x06 child of n,
// or nil if none.
func findOID(n *tlv.Node) []byte {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Tag == tagOID {
			return c.Value
		}
	}
	return nil
}

// encodeChildren returns the wire bytes of n's children concatenated
// (each as TLV). When n has no children, it returns n.Value. This
// gives callers something usable from CardInfo's optional byte
// fields without re-parsing.
func encodeChildren(n *tlv.Node) []byte {
	if n == nil {
		return nil
	}
	if len(n.Children) == 0 {
		if len(n.Value) == 0 {
			return nil
		}
		return append([]byte(nil), n.Value...)
	}
	var out []byte
	for _, c := range n.Children {
		out = append(out, c.Encode()...)
	}
	return out
}

// decodeGPVersion extracts a "major.minor.patch" string from a GP
// version OID. The OID has the GP prefix followed by arc 2 (GP
// version path) and then the version arcs. Returns "" if the OID
// doesn't match the expected shape.
//
// Example: 1.2.840.114283.2.2.3.1 → "2.3.1"
func decodeGPVersion(oid []byte) string {
	arcs := decodeRemainingArcs(oid)
	if len(arcs) < 2 || arcs[0] != 2 {
		return ""
	}
	verArcs := arcs[1:]
	switch len(verArcs) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("%d", verArcs[0])
	case 2:
		return fmt.Sprintf("%d.%d", verArcs[0], verArcs[1])
	default:
		return fmt.Sprintf("%d.%d.%d", verArcs[0], verArcs[1], verArcs[2])
	}
}

// decodeSCPOID extracts (scp, i) from an SCP version OID. The OID
// has the GP prefix followed by arc 4 (SCP path), then arcs scp
// and i.
//
// Example: 1.2.840.114283.4.3.112 → (0x03, 0x70).
//
// Returns (0, 0) if the OID doesn't match the expected shape.
func decodeSCPOID(oid []byte) (scp, i byte) {
	arcs := decodeRemainingArcs(oid)
	if len(arcs) < 3 || arcs[0] != 4 {
		return 0, 0
	}
	if arcs[1] > 0xFF || arcs[2] > 0xFF {
		return 0, 0
	}
	return byte(arcs[1]), byte(arcs[2])
}

// decodeRemainingArcs takes raw OID DER bytes and returns the arcs
// that come AFTER the GP prefix (1.2.840.114283). Returns nil if
// the OID doesn't start with that prefix.
func decodeRemainingArcs(oid []byte) []uint64 {
	if len(oid) < len(gpOIDPrefix) {
		return nil
	}
	for i, b := range gpOIDPrefix {
		if oid[i] != b {
			return nil
		}
	}
	return decodeArcs(oid[len(gpOIDPrefix):])
}

// decodeArcs decodes BER-OID base-128 variable-length arcs from raw
// bytes. Each arc continues while the high bit of the byte is set.
// Returns nil on malformed input.
func decodeArcs(b []byte) []uint64 {
	var out []uint64
	var cur uint64
	for _, byt := range b {
		// Guard against arcs that would overflow uint64 (would
		// require an absurdly long encoding; treat as malformed).
		if cur > (1 << 57) {
			return nil
		}
		cur = (cur << 7) | uint64(byt&0x7F)
		if byt&0x80 == 0 {
			out = append(out, cur)
			cur = 0
		}
	}
	if cur != 0 {
		// Final byte had continuation bit set — malformed.
		return nil
	}
	return out
}

// formatOID renders raw OID DER bytes as a dotted string. The GP
// OIDs we care about all start with the prefix 1.2.840.114283; we
// hard-code that and decode only the trailing arcs from the bytes.
// For non-GP OIDs (which shouldn't appear in CRD but we tolerate
// for robustness) we fall back to a raw hex form.
func formatOID(oid []byte) string {
	rest := decodeRemainingArcs(oid)
	if rest == nil {
		// Not a GP OID — render as hex so callers can at least see it.
		return fmt.Sprintf("non-gp-oid:%x", oid)
	}
	out := "1.2.840.114283"
	for _, a := range rest {
		out += fmt.Sprintf(".%d", a)
	}
	return out
}
