// Package tlv implements the BER-TLV subset used by GlobalPlatform
// and ISO 7816 smart cards. GP relies on BER-TLV for structuring APDU
// data fields, certificate stores, key agreement payloads, and secure
// messaging wrappers.
//
// Scope of this package:
//
//   - Tag decoding supports up to 3-byte tags (covers all GP-defined
//     tags including 0x5F49, 0x7F21, 0xBF21).
//   - Length decoding supports up to 3 length bytes (covers values
//     up to 65535 bytes, which is the GP and short/extended APDU
//     ceiling).
//   - Resource caps on depth, node count, and length are enforced
//     during decode to bound memory use against hostile-card responses.
//
// What this package is NOT:
//
//   - A full BER-TLV decoder. Tags requiring more than 3 bytes and
//     length encodings beyond 3 bytes (BER's "indefinite length" form
//     and 4+ byte definite-length forms) are rejected. If you need
//     general BER/DER processing, use crypto/asn1 or a dedicated
//     library — this package is purpose-built for GP wire formats.
//   - A DER validator. Decoding is permissive about non-minimal
//     length encodings; encode() always emits minimal length form.
package tlv

import (
	"errors"
	"fmt"
)

// Tag represents a BER-TLV tag value. GP uses single-byte tags (0x80,
// 0x86), two-byte tags (0x5F49, 0x7F21), and constructed tags (0xBF21).
type Tag uint32

// Common tags from GP Amendment F (SCP11) and ISO 7816.
const (
	TagCertStore     Tag = 0xBF21 // Certificate chain container
	TagCertificate   Tag = 0x7F21 // Single certificate wrapper
	TagEphPubKey     Tag = 0x5F49 // ePK.SD.ECKA / ePK.OCE.ECKA
	TagReceipt       Tag = 0x86   // Cryptographic receipt
	TagKeyInfo       Tag = 0x90   // Key information
	TagKeyUsage      Tag = 0x95   // Key usage qualifier
	TagKeyType       Tag = 0x80   // Key type
	TagKeyLength     Tag = 0x81   // Key length
	TagControlRef    Tag = 0xA6   // Control reference template
	TagKeyID         Tag = 0x83   // Key identifier
	TagCryptogram    Tag = 0x9E   // Digital signature / cryptogram
	TagMACChaining   Tag = 0x87   // MAC chaining value
	TagEncryptedData Tag = 0x85   // Encrypted payload
)

// Node is a single BER-TLV element. It can contain raw value bytes
// for primitive tags or child nodes for constructed tags.
type Node struct {
	Tag      Tag
	Value    []byte
	Children []*Node
}

const (
	maxDecodeDepth  = 32
	maxDecodeNodes  = 4096
	maxDecodeLength = 1 << 20
)

// errResourceLimit signals that a hard decoder resource limit was hit.
// Unlike ordinary parse errors (which are swallowed at constructed-node
// boundaries because GP cards routinely return constructed tags with
// opaque payloads), resource-limit errors must propagate so the host
// cannot be coerced into unbounded work by a hostile or buggy card.
var errResourceLimit = errors.New("tlv: decoder resource limit exceeded")

// Encode serializes a Node into BER-TLV bytes. Constructed nodes
// (those with children) encode recursively. Primitive nodes write
// their raw value.
func (n *Node) Encode() []byte {
	var payload []byte
	if len(n.Children) > 0 {
		for _, child := range n.Children {
			payload = append(payload, child.Encode()...)
		}
	} else {
		payload = n.Value
	}

	var buf []byte
	buf = append(buf, encodeTag(n.Tag)...)
	buf = append(buf, encodeLength(len(payload))...)
	buf = append(buf, payload...)
	return buf
}

// Decode parses a byte slice into a sequence of TLV Nodes.
func Decode(data []byte) ([]*Node, error) {
	count := 0
	return decode(data, 0, &count)
}

func decode(data []byte, depth int, count *int) ([]*Node, error) {
	if depth > maxDecodeDepth {
		return nil, fmt.Errorf("%w: nesting too deep (>%d)", errResourceLimit, maxDecodeDepth)
	}
	if len(data) > maxDecodeLength {
		return nil, fmt.Errorf("%w: input too large (%d bytes)", errResourceLimit, len(data))
	}
	var nodes []*Node
	offset := 0
	for offset < len(data) {
		*count += 1
		if *count > maxDecodeNodes {
			return nil, fmt.Errorf("%w: too many nodes (>%d)", errResourceLimit, maxDecodeNodes)
		}
		tag, tagLen, err := decodeTag(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("decode tag at offset %d: %w", offset, err)
		}
		offset += tagLen

		if offset >= len(data) {
			return nil, errors.New("truncated TLV: no length after tag")
		}

		length, lenBytes, err := decodeLength(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("decode length at offset %d: %w", offset, err)
		}
		offset += lenBytes

		if offset+length > len(data) {
			return nil, fmt.Errorf("truncated TLV: need %d bytes, have %d", length, len(data)-offset)
		}

		value := data[offset : offset+length]
		offset += length

		node := &Node{Tag: tag, Value: make([]byte, len(value))}
		copy(node.Value, value)

		// Constructed tags have bit 6 of the first byte set.
		if isConstructed(tag) && length > 0 {
			children, err := decode(value, depth+1, count)
			if err == nil {
				node.Children = children
			} else if errors.Is(err, errResourceLimit) {
				// Resource limits are non-negotiable: propagate.
				return nil, err
			}
			// Otherwise: parse error inside an opaque payload. Some GP
			// responses use constructed tags whose value is not itself
			// well-formed BER-TLV; tolerate that and keep the raw value.
		}

		nodes = append(nodes, node)
	}
	return nodes, nil
}

// Find locates the first node with a matching tag, searching recursively.
func Find(nodes []*Node, tag Tag) *Node {
	for _, n := range nodes {
		if n.Tag == tag {
			return n
		}
		if found := Find(n.Children, tag); found != nil {
			return found
		}
	}
	return nil
}

// FindAll returns every node matching the tag.
func FindAll(nodes []*Node, tag Tag) []*Node {
	var result []*Node
	for _, n := range nodes {
		if n.Tag == tag {
			result = append(result, n)
		}
		result = append(result, FindAll(n.Children, tag)...)
	}
	return result
}

// Build is a convenience for constructing a single TLV node.
func Build(tag Tag, value []byte) *Node {
	v := make([]byte, len(value))
	copy(v, value)
	return &Node{Tag: tag, Value: v}
}

// BuildConstructed creates a node wrapping child nodes.
func BuildConstructed(tag Tag, children ...*Node) *Node {
	return &Node{Tag: tag, Children: children}
}

// --- internal encoding helpers ---

func encodeTag(t Tag) []byte {
	switch {
	case t <= 0xFF:
		return []byte{byte(t)}
	case t <= 0xFFFF:
		return []byte{byte(t >> 8), byte(t)}
	default:
		return []byte{byte(t >> 16), byte(t >> 8), byte(t)}
	}
}

func encodeLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func decodeTag(data []byte) (Tag, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data for tag")
	}
	b0 := data[0]
	// Two-byte tag prefix: first byte has low 5 bits set
	if b0&0x1F == 0x1F {
		if len(data) < 2 {
			return 0, 0, errors.New("truncated multi-byte tag")
		}
		// Check for 3-byte tag (continuation bit set on byte 1)
		if data[1]&0x80 != 0 {
			if len(data) < 3 {
				return 0, 0, errors.New("truncated 3-byte tag")
			}
			t := Tag(b0)<<16 | Tag(data[1])<<8 | Tag(data[2])
			return t, 3, nil
		}
		t := Tag(b0)<<8 | Tag(data[1])
		return t, 2, nil
	}
	return Tag(b0), 1, nil
}

func decodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data for length")
	}
	b0 := data[0]
	if b0 < 0x80 {
		return int(b0), 1, nil
	}
	numBytes := int(b0 & 0x7F)
	if numBytes == 0 || numBytes > 3 || len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("invalid length encoding: indicator=%02X, available=%d", b0, len(data)-1)
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

func isConstructed(t Tag) bool {
	// Bit 6 of the first tag byte indicates constructed encoding.
	switch {
	case t <= 0xFF:
		return t&0x20 != 0
	case t <= 0xFFFF:
		return (t>>8)&0x20 != 0
	default:
		return (t>>16)&0x20 != 0
	}
}
