package kdf

import (
	"bytes"
	"testing"
)

// TestSessionKeys_CloneIsDefensive confirms Clone() returns slices
// that are independent from the original — mutating the clone must
// not affect the source, and vice versa.
func TestSessionKeys_CloneIsDefensive(t *testing.T) {
	orig := &SessionKeys{
		SENC:     []byte{0x01, 0x02, 0x03},
		SMAC:     []byte{0x10, 0x11, 0x12},
		SRMAC:    []byte{0x20, 0x21},
		DEK:      []byte{0x30, 0x31, 0x32, 0x33},
		Receipt:  []byte{0x40},
		MACChain: []byte{0x50, 0x51},
	}

	clone := orig.Clone()

	// Mutate the clone — original must be untouched.
	clone.SENC[0] = 0xFF
	clone.SMAC[0] = 0xFF
	clone.SRMAC[0] = 0xFF
	clone.DEK[0] = 0xFF
	clone.Receipt[0] = 0xFF
	clone.MACChain[0] = 0xFF

	if !bytes.Equal(orig.SENC, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("orig.SENC mutated by clone: %X", orig.SENC)
	}
	if !bytes.Equal(orig.SMAC, []byte{0x10, 0x11, 0x12}) {
		t.Errorf("orig.SMAC mutated by clone: %X", orig.SMAC)
	}
	if !bytes.Equal(orig.SRMAC, []byte{0x20, 0x21}) {
		t.Errorf("orig.SRMAC mutated by clone: %X", orig.SRMAC)
	}
	if !bytes.Equal(orig.DEK, []byte{0x30, 0x31, 0x32, 0x33}) {
		t.Errorf("orig.DEK mutated by clone: %X", orig.DEK)
	}
	if !bytes.Equal(orig.Receipt, []byte{0x40}) {
		t.Errorf("orig.Receipt mutated by clone: %X", orig.Receipt)
	}
	if !bytes.Equal(orig.MACChain, []byte{0x50, 0x51}) {
		t.Errorf("orig.MACChain mutated by clone: %X", orig.MACChain)
	}
}

func TestSessionKeys_CloneNil(t *testing.T) {
	var k *SessionKeys
	if c := k.Clone(); c != nil {
		t.Errorf("Clone of nil should be nil, got %+v", c)
	}
}
