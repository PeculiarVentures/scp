package tlv

import (
	"bytes"
	"testing"
)

func TestEncodeDecodePrimitive(t *testing.T) {
	node := Build(Tag(0x80), []byte{0x88})
	encoded := node.Encode()

	expected := []byte{0x80, 0x01, 0x88}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("encode: got %X, want %X", encoded, expected)
	}

	nodes, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Tag != 0x80 {
		t.Errorf("tag: got %X, want 80", nodes[0].Tag)
	}
	if !bytes.Equal(nodes[0].Value, []byte{0x88}) {
		t.Errorf("value: got %X, want 88", nodes[0].Value)
	}
}

func TestEncodeTwoByteTag(t *testing.T) {
	node := Build(TagEphPubKey, []byte{0x04, 0x01, 0x02})
	encoded := node.Encode()

	// Tag 0x5F49: two bytes
	if encoded[0] != 0x5F || encoded[1] != 0x49 {
		t.Errorf("tag bytes: got %X %X, want 5F 49", encoded[0], encoded[1])
	}
	// Length: 3
	if encoded[2] != 0x03 {
		t.Errorf("length: got %X, want 03", encoded[2])
	}
}

func TestConstructedNode(t *testing.T) {
	child1 := Build(Tag(0x80), []byte{0x88})
	child2 := Build(Tag(0x81), []byte{0x10})
	parent := BuildConstructed(Tag(0xA6), child1, child2)

	encoded := parent.Encode()

	// Should be: A6 06 80 01 88 81 01 10
	nodes, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 top-level node, got %d", len(nodes))
	}
	if len(nodes[0].Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(nodes[0].Children))
	}
}

func TestFind(t *testing.T) {
	child := Build(TagEphPubKey, []byte{0x04})
	parent := BuildConstructed(TagControlRef, child)

	nodes := []*Node{parent}

	found := Find(nodes, TagEphPubKey)
	if found == nil {
		t.Fatal("Find should locate nested tag")
	}
	if !bytes.Equal(found.Value, []byte{0x04}) {
		t.Errorf("found wrong value: %X", found.Value)
	}

	notFound := Find(nodes, Tag(0xFF))
	if notFound != nil {
		t.Error("Find should return nil for missing tag")
	}
}

func TestLongLength(t *testing.T) {
	// 200-byte value should use 0x81 length encoding.
	value := make([]byte, 200)
	node := Build(Tag(0x70), value)
	encoded := node.Encode()

	// Tag: 0x70, Length: 0x81 0xC8, Value: 200 bytes
	if encoded[1] != 0x81 || encoded[2] != 0xC8 {
		t.Errorf("length encoding: got %X %X, want 81 C8", encoded[1], encoded[2])
	}

	nodes, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(nodes[0].Value) != 200 {
		t.Errorf("decoded value length: got %d, want 200", len(nodes[0].Value))
	}
}

func TestMultipleNodes(t *testing.T) {
	n1 := Build(Tag(0x80), []byte{0x88})
	n2 := Build(Tag(0x81), []byte{0x10})

	var encoded []byte
	encoded = append(encoded, n1.Encode()...)
	encoded = append(encoded, n2.Encode()...)

	nodes, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
}

// --- DoS-resistance tests (resource limits) ---

// TestDecode_RejectsExcessiveDepth confirms that deeply nested constructed
// TLV input from the card is rejected before exhausting the host's stack.
func TestDecode_RejectsExcessiveDepth(t *testing.T) {
	// Build a deeply nested constructed TLV: A0 LL (A0 LL (...)) repeating.
	// Each level: tag 0xA0 (constructed), BER-TLV length, inner payload.
	// Innermost is a primitive 0x80 0x00 (empty primitive).
	build := func(depth int) []byte {
		payload := []byte{0x80, 0x00}
		for i := 0; i < depth; i++ {
			lenBytes := encodeLength(len(payload))
			wrapped := make([]byte, 0, 1+len(lenBytes)+len(payload))
			wrapped = append(wrapped, 0xA0)
			wrapped = append(wrapped, lenBytes...)
			wrapped = append(wrapped, payload...)
			payload = wrapped
		}
		return payload
	}

	// Just under the limit: should decode.
	if _, err := Decode(build(30)); err != nil {
		t.Errorf("depth 30 should decode: %v", err)
	}

	// Well over the limit: should be rejected.
	if _, err := Decode(build(100)); err == nil {
		t.Error("excessively nested TLV should be rejected")
	}
}

// TestDecode_RejectsTooManyNodes confirms that a TLV stream with too many
// elements is rejected to prevent O(N) memory blowup from a single GET DATA.
func TestDecode_RejectsTooManyNodes(t *testing.T) {
	// Build N empty primitives back-to-back: each one is 2 bytes (80 00).
	// With maxDecodeNodes = 4096, we want to exceed that comfortably.
	const target = 5000
	encoded := make([]byte, 0, target*2)
	for i := 0; i < target; i++ {
		encoded = append(encoded, 0x80, 0x00)
	}
	if _, err := Decode(encoded); err == nil {
		t.Errorf("decoding %d nodes should be rejected", target)
	}
}

// TestDecode_RejectsHugeInput confirms that an input larger than the
// per-call byte limit is rejected. This prevents a hostile card from
// inducing the host to decode a multi-megabyte response stream.
func TestDecode_RejectsHugeInput(t *testing.T) {
	// 2 MB of a primitive — exceeds the 1 MB limit.
	const size = 2 * 1024 * 1024
	huge := make([]byte, size)
	if _, err := Decode(huge); err == nil {
		t.Error("huge input should be rejected")
	}
}
