package apdu

import (
	"bytes"
	"testing"
)

func TestEncodeShort(t *testing.T) {
	cmd := &Command{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00, 0x00, 0x03, 0x08}, Le: 0}
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00}
	if !bytes.Equal(raw, expected) {
		t.Errorf("short encode:\n  got:  %X\n  want: %X", raw, expected)
	}
}

func TestEncodeShort_RejectsLargeData(t *testing.T) {
	cmd := &Command{CLA: 0x00, INS: 0xDB, P1: 0x3F, P2: 0xFF,
		Data: make([]byte, 300), Le: -1}
	_, err := cmd.Encode()
	if err == nil {
		t.Fatal("expected error for 300-byte data with short encoding")
	}
}

func TestEncodeExtended_SmallData(t *testing.T) {
	// Extended encoding with small data — should still use 3-byte Lc.
	cmd := &Command{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00}, Le: -1, ExtendedLength: true}
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// CLA INS P1 P2 | 0x00 0x00 0x02 | A0 00
	expected := []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x02, 0xA0, 0x00}
	if !bytes.Equal(raw, expected) {
		t.Errorf("extended small:\n  got:  %X\n  want: %X", raw, expected)
	}
}

func TestEncodeExtended_LargeData(t *testing.T) {
	// 5000-byte payload — typical post-quantum certificate size.
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	cmd := &Command{CLA: 0x00, INS: 0xDB, P1: 0x3F, P2: 0xFF,
		Data: data, Le: -1, ExtendedLength: true}
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Header: 4 bytes
	// Extended Lc: 0x00 0x13 0x88 (5000 = 0x1388)
	// Data: 5000 bytes
	// Total: 4 + 3 + 5000 = 5007
	if len(raw) != 5007 {
		t.Fatalf("extended large: got %d bytes, want 5007", len(raw))
	}
	if raw[4] != 0x00 || raw[5] != 0x13 || raw[6] != 0x88 {
		t.Errorf("extended Lc: got %02X %02X %02X, want 00 13 88", raw[4], raw[5], raw[6])
	}
	if !bytes.Equal(raw[7:], data) {
		t.Error("extended data mismatch")
	}
}

func TestEncodeExtended_WithLe(t *testing.T) {
	// Case 4E: data + Le
	cmd := &Command{CLA: 0x80, INS: 0xCA, P1: 0xBF, P2: 0x21,
		Data: []byte{0xA6, 0x04}, Le: 0, ExtendedLength: true}
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// CLA INS P1 P2 | 0x00 0x00 0x02 | A6 04 | 0x00 0x00 (Le=max)
	expected := []byte{0x80, 0xCA, 0xBF, 0x21, 0x00, 0x00, 0x02, 0xA6, 0x04, 0x00, 0x00}
	if !bytes.Equal(raw, expected) {
		t.Errorf("extended with Le:\n  got:  %X\n  want: %X", raw, expected)
	}
}

func TestEncodeExtended_LeOnly(t *testing.T) {
	// Case 2E: no data, just Le
	cmd := &Command{CLA: 0x00, INS: 0xC0, P1: 0x00, P2: 0x00,
		Le: 1000, ExtendedLength: true}
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// CLA INS P1 P2 | 0x00 | 0x03 0xE8 (Le=1000)
	expected := []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x03, 0xE8}
	if !bytes.Equal(raw, expected) {
		t.Errorf("extended Le only:\n  got:  %X\n  want: %X", raw, expected)
	}
}

func TestChainCommands_ShortFallback(t *testing.T) {
	// Verify chaining still works for transports without extended length support.
	data := make([]byte, 600)
	cmd := &Command{CLA: 0x00, INS: 0xDB, P1: 0x3F, P2: 0xFF, Data: data, Le: 0}
	chains, err := ChainCommands(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 3 { // 255 + 255 + 90
		t.Errorf("expected 3 chained commands, got %d", len(chains))
	}
	// First two should have chaining bit set
	if chains[0].CLA&0x10 == 0 {
		t.Error("first chain command missing chaining bit")
	}
	// Last should not
	if chains[2].CLA&0x10 != 0 {
		t.Error("last chain command should not have chaining bit")
	}
}
