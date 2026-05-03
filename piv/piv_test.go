package piv

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

// --- VerifyPIN ---

// TestVerifyPIN_CommandEncoding confirms the wire shape of a VERIFY
// APDU: CLA=0x00, INS=0x20, P1=0x00, P2=0x80, Data is the PIN padded
// to 8 bytes with 0xFF.
func TestVerifyPIN_CommandEncoding(t *testing.T) {
	cmd, err := VerifyPIN([]byte("123456"))
	if err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if cmd.CLA != 0x00 || cmd.INS != 0x20 || cmd.P1 != 0x00 || cmd.P2 != 0x80 {
		t.Errorf("header = %02X %02X %02X %02X, want 00 20 00 80",
			cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	}
	want := []byte{'1', '2', '3', '4', '5', '6', 0xFF, 0xFF}
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data = %X, want %X", cmd.Data, want)
	}
}

func TestVerifyPIN_Padding(t *testing.T) {
	// A short PIN must be padded with 0xFF up to 8 bytes.
	cmd, _ := VerifyPIN([]byte{0x01})
	want := []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data = %X, want %X", cmd.Data, want)
	}
}

func TestVerifyPIN_RejectsOverlongPIN(t *testing.T) {
	// 9-byte PIN must be rejected, not silently truncated. Silent
	// truncation would mean the card sees a different value than the
	// caller intended — exactly the class of bug a length check
	// prevents.
	if _, err := VerifyPIN([]byte("123456789")); err == nil {
		t.Error("expected error for 9-byte PIN")
	}
}

func TestVerifyPIN_RejectsEmptyPIN(t *testing.T) {
	if _, err := VerifyPIN(nil); err == nil {
		t.Error("expected error for nil PIN")
	}
	if _, err := VerifyPIN([]byte{}); err == nil {
		t.Error("expected error for empty PIN")
	}
}

// --- GenerateKey ---

// TestGenerateKey_CommandEncoding pins down the GENERATE ASYMMETRIC
// KEY PAIR shape: INS=0x47, P1=0, P2=slot, data = AC{80 01 algo}.
func TestGenerateKey_CommandEncoding_ECCP256(t *testing.T) {
	cmd := GenerateKey(SlotAuthentication, AlgoECCP256)
	if cmd.INS != 0x47 {
		t.Errorf("INS = %02X, want 47", cmd.INS)
	}
	if cmd.P2 != SlotAuthentication {
		t.Errorf("P2 = %02X, want %02X (slot)", cmd.P2, SlotAuthentication)
	}
	// AC 03 80 01 11
	want := []byte{0xAC, 0x03, 0x80, 0x01, AlgoECCP256}
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data = %X, want %X", cmd.Data, want)
	}
}

// TestGenerateKeyWithPolicy_PINTouch confirms that PIN and Touch
// policy bytes are added under tags 0xAA and 0xAB inside the AC
// template, which is YubiKey's documented extension.
func TestGenerateKeyWithPolicy_PinTouchPolicyEncoding(t *testing.T) {
	cmd := GenerateKeyWithPolicy(SlotSignature, AlgoECCP256, PINPolicyAlways, TouchPolicyAlways)
	if cmd.INS != 0x47 || cmd.P2 != SlotSignature {
		t.Errorf("header wrong: INS=%02X P2=%02X", cmd.INS, cmd.P2)
	}
	// AC <len> 80 01 11 AA 01 03 AB 01 02
	want := []byte{0xAC, 0x09, 0x80, 0x01, AlgoECCP256, 0xAA, 0x01, PINPolicyAlways, 0xAB, 0x01, TouchPolicyAlways}
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data = %X, want %X", cmd.Data, want)
	}
}

func TestGenerateKeyWithPolicy_DefaultPoliciesOmitted(t *testing.T) {
	// PINPolicyDefault and TouchPolicyDefault should NOT add tags;
	// the wire form should reduce to the same as plain GenerateKey.
	cmd := GenerateKeyWithPolicy(SlotAuthentication, AlgoECCP256, PINPolicyDefault, TouchPolicyDefault)
	want := []byte{0xAC, 0x03, 0x80, 0x01, AlgoECCP256}
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data = %X, want %X (default policies should be elided)", cmd.Data, want)
	}
}

// --- PutCertificate ---

func TestPutCertificate_CommandEncoding(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		Raw:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	cmd, err := PutCertificate(SlotAuthentication, cert)
	if err != nil {
		t.Fatalf("PutCertificate: %v", err)
	}
	if cmd.CLA != 0x00 || cmd.INS != 0xDB || cmd.P1 != 0x3F || cmd.P2 != 0xFF {
		t.Errorf("header = %02X %02X %02X %02X, want 00 DB 3F FF",
			cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	}
	// Expect: 5C 03 5FC105 53 <len> 70 04 DEADBEEF 71 01 00 FE 00
	if !bytes.Contains(cmd.Data, []byte{0x5C, 0x03, 0x5F, 0xC1, 0x05}) {
		t.Errorf("missing object ID 0x5C 0x03 5FC105 (PIV Authentication slot)")
	}
	if !bytes.Contains(cmd.Data, []byte{0x70, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("missing certificate tag 0x70 with raw cert bytes")
	}
	if !bytes.Contains(cmd.Data, []byte{0x71, 0x01, 0x00}) {
		t.Errorf("missing CertInfo tag 0x71 0x01 0x00 (uncompressed)")
	}
	if !bytes.Contains(cmd.Data, []byte{0xFE, 0x00}) {
		t.Errorf("missing EDC tag 0xFE 0x00 (no error detection code)")
	}
}

func TestPutCertificate_RejectsNilCert(t *testing.T) {
	if _, err := PutCertificate(SlotAuthentication, nil); err == nil {
		t.Error("expected error for nil certificate")
	}
}

// --- slotToObjectID ---

func TestSlotToObjectID_StandardSlots(t *testing.T) {
	cases := []struct {
		slot    byte
		wantHex string
	}{
		{SlotAuthentication, "5FC105"},
		{SlotSignature, "5FC10A"},
		{SlotKeyManagement, "5FC10B"},
		{SlotCardAuth, "5FC101"},
	}
	for _, tc := range cases {
		got, err := slotToObjectID(tc.slot)
		if err != nil {
			t.Errorf("slot %02X: %v", tc.slot, err)
			continue
		}
		// Format expected
		want := []byte{0x5F, 0xC1, 0}
		switch tc.slot {
		case SlotAuthentication:
			want[2] = 0x05
		case SlotSignature:
			want[2] = 0x0A
		case SlotKeyManagement:
			want[2] = 0x0B
		case SlotCardAuth:
			want[2] = 0x01
		}
		if !bytes.Equal(got, want) {
			t.Errorf("slot %02X: got %X, want %X", tc.slot, got, want)
		}
	}
}

func TestSlotToObjectID_RetiredSlots(t *testing.T) {
	// Retired slots run from 0x82 to 0x95, mapped to 0x5FC10D + (slot - 0x82).
	for slot := byte(0x82); slot <= 0x95; slot++ {
		got, err := slotToObjectID(slot)
		if err != nil {
			t.Errorf("retired slot %02X: %v", slot, err)
			continue
		}
		wantLast := 0x0D + (slot - 0x82)
		if len(got) != 3 || got[0] != 0x5F || got[1] != 0xC1 || got[2] != wantLast {
			t.Errorf("retired slot %02X: got %X, want 5FC1%02X", slot, got, wantLast)
		}
	}
}

func TestSlotToObjectID_RejectsUnknownSlot(t *testing.T) {
	if _, err := slotToObjectID(0x00); err == nil {
		t.Error("slot 0x00 should be rejected")
	}
	if _, err := slotToObjectID(0xAA); err == nil {
		t.Error("slot 0xAA should be rejected")
	}
}

// --- ImportKey ---

func TestImportKey_ECCP256_CommandEncoding(t *testing.T) {
	keyData := make([]byte, 32)
	for i := range keyData {
		keyData[i] = byte(i)
	}
	cmd, err := ImportKey(SlotAuthentication, AlgoECCP256, keyData)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if cmd.INS != 0xFE {
		t.Errorf("INS = %02X, want FE (IMPORT_KEY YubiKey extension)", cmd.INS)
	}
	if cmd.P1 != AlgoECCP256 {
		t.Errorf("P1 = %02X, want algorithm %02X", cmd.P1, AlgoECCP256)
	}
	if cmd.P2 != SlotAuthentication {
		t.Errorf("P2 = %02X, want slot %02X", cmd.P2, SlotAuthentication)
	}
	// Tag 0x06 with 32 bytes of key.
	want := append([]byte{0x06, 0x20}, keyData...)
	if !bytes.Equal(cmd.Data, want) {
		t.Errorf("Data: got %X\nwant %X", cmd.Data, want)
	}
}

func TestImportKey_ECCP384_CommandEncoding(t *testing.T) {
	keyData := make([]byte, 48)
	cmd, err := ImportKey(SlotSignature, AlgoECCP384, keyData)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if cmd.P1 != AlgoECCP384 || cmd.P2 != SlotSignature {
		t.Errorf("header wrong: P1=%02X P2=%02X", cmd.P1, cmd.P2)
	}
	if len(cmd.Data) < 50 || cmd.Data[0] != 0x06 || cmd.Data[1] != 0x30 {
		t.Errorf("expected tag 0x06 length 0x30, got %X", cmd.Data[:2])
	}
}

func TestImportKey_RejectsWrongLength(t *testing.T) {
	// P-256 key with wrong length must be rejected.
	if _, err := ImportKey(SlotAuthentication, AlgoECCP256, make([]byte, 31)); err == nil {
		t.Error("31-byte P-256 key should be rejected")
	}
	if _, err := ImportKey(SlotAuthentication, AlgoECCP384, make([]byte, 32)); err == nil {
		t.Error("32-byte P-384 key should be rejected")
	}
}

func TestImportKey_UnsupportedAlgorithms(t *testing.T) {
	// RSA, Ed25519, X25519 constants exist, but ImportKey only
	// implements EC P-256/P-384. Anything else must surface as an
	// explicit "unsupported algorithm" error rather than silently
	// producing a wrong-shape APDU.
	cases := []byte{AlgoRSA2048, AlgoEd25519, AlgoX25519, 0x99}
	for _, alg := range cases {
		if _, err := ImportKey(SlotAuthentication, alg, make([]byte, 32)); err == nil {
			t.Errorf("algorithm 0x%02X: expected unsupported error, got nil", alg)
		}
	}
}

func TestImportKey_RejectsEmptyKey(t *testing.T) {
	if _, err := ImportKey(SlotAuthentication, AlgoECCP256, nil); err == nil {
		t.Error("expected error for empty key data")
	}
}

// --- Other command builders ---

func TestAttest_CommandEncoding(t *testing.T) {
	cmd := Attest(SlotAuthentication)
	if cmd.CLA != 0x00 || cmd.INS != 0xF9 || cmd.P1 != SlotAuthentication || cmd.P2 != 0x00 {
		t.Errorf("header = %02X %02X %02X %02X, want 00 F9 %02X 00",
			cmd.CLA, cmd.INS, cmd.P1, cmd.P2, SlotAuthentication)
	}
}

func TestReset_CommandEncoding(t *testing.T) {
	cmd := Reset()
	if cmd.CLA != 0x00 || cmd.INS != 0xFB || cmd.P1 != 0x00 || cmd.P2 != 0x00 {
		t.Errorf("header = %02X %02X %02X %02X, want 00 FB 00 00",
			cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	}
}
