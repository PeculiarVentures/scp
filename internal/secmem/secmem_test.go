package secmem

import (
	"bytes"
	"testing"
)

func TestZero_Basic(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0xFF}
	Zero(b)
	want := []byte{0, 0, 0, 0}
	if !bytes.Equal(b, want) {
		t.Errorf("Zero left non-zero bytes: %x", b)
	}
}

func TestZero_Empty(t *testing.T) {
	// Must not panic on nil or zero-length slices.
	Zero(nil)
	Zero([]byte{})
}

func TestZero_Long(t *testing.T) {
	// Length far exceeding any session key, just to stress the loop.
	b := bytes.Repeat([]byte{0xAA}, 4096)
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d not zeroed: %02x", i, v)
			break
		}
	}
}
