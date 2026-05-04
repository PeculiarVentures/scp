// Package cardrecognition parses GlobalPlatform Card Recognition Data
// (CRD), the spec-defined TLV blob a GP card publishes at GET DATA tag
// 0x66 to advertise what it is.
//
// CRD is the standard answer to "what GP version, which SCP, which
// `i` parameter does this card actually implement." Reading it is
// strictly more honest than encoding card capabilities in static
// per-vendor profiles: the data lives on the card and nowhere else,
// and a card that lies about its CRD is the card's bug, not ours.
//
// # Scope
//
// This package is for diagnostics and trace metadata. It is not used
// to drive protocol behavior — scp03 and scp11 still take an explicit
// Config. Auto-selecting an SCP version from CRD has different
// security implications (a hostile card could lie about CRD to
// downgrade a session), so the library does not do that. If you want
// to use CRD to choose a Config, do it explicitly at the call site.
//
// # Wire format (GP Card Spec v2.3.1 §H.2)
//
// The card returns CRD as the value of tag 0x66 from a GET DATA
// command. The structure is BER-TLV:
//
//	66 LL                            -- Card Recognition Data
//	  73 LL                          -- OID list (constructed)
//	    06 LL <oid>                  -- GlobalPlatform RID OID (1.2.840.114283.1)
//	    60 LL                        -- GP version (application tag 0x60)
//	      06 LL <oid>                -- 1.2.840.114283.2.<major>.<minor>[.<patch>]
//	    63 LL                        -- Card Identification Scheme (application tag 0x63)
//	      06 LL <oid>
//	    64 LL                        -- Secure Channel Protocol (application tag 0x64)
//	      06 LL <oid>                -- 1.2.840.114283.4.<scp>.<i>
//	    65 LL                        -- Card Configuration Details (application tag 0x65)
//	      06 LL <oid>
//	    66 LL                        -- Card / Chip Details (application tag 0x66, inside CRD)
//	      06 LL <oid>
//	    67 LL                        -- ISD trust point OID (optional)
//	    68 LL                        -- ISD certificate OID (optional)
//
// The outer 0x66 tag and the inner 0x66 tag (Card / Chip Details)
// share a number; they are unambiguous because of nesting.
package cardrecognition

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// CardInfo is a parsed Card Recognition Data record.
//
// Fields are populated from the corresponding TLV elements when
// present. An absent element leaves the field at its zero value;
// callers can detect "GP version absent" with len(GPVersion) == 0,
// "SCP absent" with SCPVersion == 0, and so on.
//
// Raw preserves the unparsed CRD bytes (the value of tag 0x66) so
// callers can introspect fields not surfaced here or re-emit the
// CRD verbatim. CardInfo round-trips through JSON with no special
// handling because asn1.ObjectIdentifier has stdlib JSON support.
type CardInfo struct {
	// GPVersion is the GlobalPlatform Card Spec version the card
	// claims, decoded from the OID 1.2.840.114283.2.<arcs>. Common
	// values: {2,1,1}, {2,2}, {2,3}, {2,3,1}.
	GPVersion []int `json:"gpVersion,omitempty"`

	// SCPVersion identifies the secure channel protocol the card
	// supports. 0x02 = SCP02, 0x03 = SCP03, 0x11 = SCP11. The value
	// is decoded from the second-to-last arc of the OID
	// 1.2.840.114283.4.<SCP>.<i>. Zero means the SCP element was
	// absent from the CRD.
	SCPVersion byte `json:"scpVersion,omitempty"`

	// SCPParameter is the SCP "i" parameter from the OID, decoded
	// from the last arc. Interpretation is SCP-version-specific:
	//
	//   SCP02: encodes initiation method, key derivation, base key
	//          count (see GP Amendment A).
	//   SCP03: bit 0 = pseudo-random card challenge, bit 4 = R-MAC
	//          support, bit 5 = R-ENC support (see GP Amendment D).
	//   SCP11: variant flags (see GP Amendment F).
	//
	// Zero is meaningful (it's a valid `i` value), not "absent" —
	// check SCPVersion to detect presence.
	SCPParameter byte `json:"scpParameter,omitempty"`

	// CardIdentificationOID is the value of tag 0x63 (Card
	// Identification Scheme). Empty if absent. Vendor-specific.
	CardIdentificationOID asn1.ObjectIdentifier `json:"cardIdentificationOID,omitempty"`

	// CardConfigDetailsOID is the value of tag 0x65 (Card
	// Configuration Details). Empty if absent. Vendor-specific.
	CardConfigDetailsOID asn1.ObjectIdentifier `json:"cardConfigDetailsOID,omitempty"`

	// CardChipDetailsOID is the value of the inner tag 0x66 (Card
	// or Chip Details). Empty if absent. Vendor-specific.
	CardChipDetailsOID asn1.ObjectIdentifier `json:"cardChipDetailsOID,omitempty"`

	// Raw is the value of the outer tag 0x66 — the bytes returned
	// by GET DATA, with the outer tag and length stripped.
	Raw []byte `json:"-"`
}

// gpRIDPrefix is the OID prefix 1.2.840.114283 (GlobalPlatform's
// registered IANA enterprise number). Every well-formed GP OID
// starts with these arcs.
var gpRIDPrefix = asn1.ObjectIdentifier{1, 2, 840, 114283}

// Errors returned by Parse.
var (
	// ErrEmpty signals that the input contains no CRD content.
	ErrEmpty = errors.New("cardrecognition: empty input")

	// ErrMalformed signals that the CRD bytes could not be parsed
	// as BER-TLV per GP §H.2.
	ErrMalformed = errors.New("cardrecognition: malformed CRD")
)

// Parse decodes a Card Recognition Data blob.
//
// Input may be either the value of tag 0x66 (inner contents) or the
// full TLV including the outer 0x66 tag and length. Parse detects
// which form was provided by inspecting the first byte.
//
// Parse is permissive about missing optional fields — a card that
// publishes only GP version and SCP information returns a CardInfo
// with the other fields empty, not an error.
func Parse(data []byte) (*CardInfo, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}

	// Accept both the full TLV and the inner value. The outer tag
	// 0x66 is application-class constructed; if the input starts
	// with 0x66, parse it as the full TLV and descend into the
	// children. Otherwise treat the input as the value bytes.
	var children []*tlv.Node
	if data[0] == 0x66 {
		nodes, err := tlv.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if len(nodes) != 1 || nodes[0].Tag != 0x66 {
			return nil, fmt.Errorf("%w: expected single tag 0x66, got %d nodes", ErrMalformed, len(nodes))
		}
		children = nodes[0].Children
	} else {
		// Treat as the value bytes — wrap and decode. The CRD
		// payload always contains a tag-0x73 OID list as its
		// outermost structure.
		nodes, err := tlv.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		children = nodes
	}

	// The CRD value is itself a constructed tag 0x73 (OID list)
	// containing the various application-tagged fields.
	listNode := tlv.Find(children, 0x73)
	if listNode == nil {
		return nil, fmt.Errorf("%w: missing OID list (tag 0x73)", ErrMalformed)
	}

	info := &CardInfo{Raw: append([]byte(nil), data...)}

	for _, child := range listNode.Children {
		switch child.Tag {
		case 0x06:
			// The bare GP RID marker. We don't need to record it —
			// its presence is implicit in the CRD existing — but
			// validate that it matches the GP RID so we know we're
			// looking at GP CRD and not someone else's tag-0x66 data.
			oid, err := parseInnerOID(child.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: GP marker OID: %v", ErrMalformed, err)
			}
			if !startsWith(oid, gpRIDPrefix) {
				return nil, fmt.Errorf("%w: marker OID %v does not start with GP RID %v",
					ErrMalformed, oid, gpRIDPrefix)
			}

		case 0x60:
			oid, err := extractInnerOID(child)
			if err != nil {
				return nil, fmt.Errorf("%w: GP version (tag 0x60): %v", ErrMalformed, err)
			}
			// 1.2.840.114283.2.<major>.<minor>[.<patch>]
			if len(oid) < 6 || !startsWith(oid, append(gpRIDPrefix, 2)) {
				return nil, fmt.Errorf("%w: GP version OID has unexpected shape: %v",
					ErrMalformed, oid)
			}
			info.GPVersion = append([]int(nil), oid[5:]...)

		case 0x63:
			oid, err := extractInnerOID(child)
			if err != nil {
				return nil, fmt.Errorf("%w: card ID (tag 0x63): %v", ErrMalformed, err)
			}
			info.CardIdentificationOID = oid

		case 0x64:
			oid, err := extractInnerOID(child)
			if err != nil {
				return nil, fmt.Errorf("%w: SCP (tag 0x64): %v", ErrMalformed, err)
			}
			// 1.2.840.114283.4.<SCP>.<i>
			if len(oid) < 6 || !startsWith(oid, append(gpRIDPrefix, 4)) {
				return nil, fmt.Errorf("%w: SCP OID has unexpected shape: %v",
					ErrMalformed, oid)
			}
			scp := oid[len(oid)-2]
			i := oid[len(oid)-1]
			if scp < 0 || scp > 0xFF || i < 0 || i > 0xFF {
				return nil, fmt.Errorf("%w: SCP OID arcs out of byte range: %v",
					ErrMalformed, oid)
			}
			info.SCPVersion = byte(scp)
			info.SCPParameter = byte(i)

		case 0x65:
			oid, err := extractInnerOID(child)
			if err != nil {
				return nil, fmt.Errorf("%w: card config (tag 0x65): %v", ErrMalformed, err)
			}
			info.CardConfigDetailsOID = oid

		case 0x66:
			oid, err := extractInnerOID(child)
			if err != nil {
				return nil, fmt.Errorf("%w: card chip (tag 0x66): %v", ErrMalformed, err)
			}
			info.CardChipDetailsOID = oid

		default:
			// Unknown application-tag child. GP §H.2 reserves space
			// for additions (0x67 = ISD trust point, 0x68 = ISD
			// cert, future extensions). Ignore them — Raw preserves
			// the bytes for callers that want to look.
		}
	}

	return info, nil
}

// Probe issues GET DATA 80CA0066 against the transport and parses
// the response. The card must be SELECTed first; CRD is a property
// of the currently selected SD or applet, not the card globally.
//
// Probe does not interpret the SCP information — it just returns
// what the card said. Callers deciding which Config to build should
// do that explicitly.
func Probe(ctx context.Context, t transport.Transport) (*CardInfo, error) {
	cmd := &apdu.Command{
		CLA: 0x80,
		INS: 0xCA, // GET DATA
		P1:  0x00,
		P2:  0x66,
		Le:  0,
	}
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("cardrecognition: GET DATA tag 0x66: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("cardrecognition: GET DATA tag 0x66 returned SW=%04X", resp.StatusWord())
	}
	return Parse(resp.Data)
}

// extractInnerOID expects a constructed application-tagged node
// whose single child is a primitive OID (tag 0x06).
func extractInnerOID(n *tlv.Node) (asn1.ObjectIdentifier, error) {
	if len(n.Children) == 0 {
		// Some cards/encoders emit the OID directly as the value
		// of the application tag rather than wrapping it in 0x06.
		// Try parsing the raw value as OID contents.
		return parseInnerOID(n.Value)
	}
	for _, c := range n.Children {
		if c.Tag == 0x06 {
			return parseInnerOID(c.Value)
		}
	}
	return nil, errors.New("no OID (tag 0x06) child")
}

// parseInnerOID decodes the value bytes of an OID (tag-0x06 contents,
// with the tag and length already stripped) into an ObjectIdentifier.
//
// We reconstruct a complete tag-0x06 TLV and feed it to asn1.Unmarshal
// so we can rely on the standard library's OID arc decoder, including
// the variable-length encoding used for arcs >= 128.
func parseInnerOID(value []byte) (asn1.ObjectIdentifier, error) {
	if len(value) == 0 {
		return nil, errors.New("empty OID value")
	}
	if len(value) > 127 {
		// Spec allows longer OIDs but no GP CRD OID approaches this.
		// Refuse rather than implement multi-byte length encoding here.
		return nil, fmt.Errorf("OID value too long (%d bytes)", len(value))
	}
	der := make([]byte, 0, len(value)+2)
	der = append(der, 0x06, byte(len(value)))
	der = append(der, value...)
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oid)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after OID: %d", len(rest))
	}
	return oid, nil
}

// startsWith returns true if oid begins with prefix.
func startsWith(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if oid[i] != p {
			return false
		}
	}
	return true
}
