package securitydomain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

// --- KCV tests ---

func TestComputeAESKCV(t *testing.T) {
	// Default SCP03 key: 0x40414243...4F
	key := []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

	kcv := computeAESKCV(key)
	if kcv == nil {
		t.Fatal("KCV should not be nil")
	}
	if len(kcv) != 3 {
		t.Fatalf("KCV should be 3 bytes, got %d", len(kcv))
	}

	// KCV must be deterministic.
	kcv2 := computeAESKCV(key)
	if !bytes.Equal(kcv, kcv2) {
		t.Errorf("KCV not deterministic: %X vs %X", kcv, kcv2)
	}
}

func TestComputeAESKCV_WrongLength(t *testing.T) {
	kcv := computeAESKCV([]byte{0x01, 0x02, 0x03}) // too short
	if kcv != nil {
		t.Error("KCV should be nil for invalid key length")
	}
}

// --- KeyReference tests ---

func TestKeyReference_String(t *testing.T) {
	ref := NewKeyReference(0x01, 0xFF)
	s := ref.String()
	if s != "KID=0x01,KVN=0xFF" {
		t.Errorf("unexpected string: %s", s)
	}
}

// --- Serial conversion tests ---

func TestSerialToHex(t *testing.T) {
	serial := big.NewInt(0x2A)
	got := SerialToHex(serial)
	if got != "2a" {
		t.Errorf("expected 2a, got %s", got)
	}
}

func TestSerialFromHex(t *testing.T) {
	serial, err := SerialFromHex("2a")
	if err != nil {
		t.Fatal(err)
	}
	if serial.Int64() != 42 {
		t.Errorf("expected 42, got %d", serial.Int64())
	}
}

func TestSerialFromHex_Invalid(t *testing.T) {
	_, err := SerialFromHex("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

// --- APDU construction tests ---

func TestPutKeySCP03Cmd_ValidKeys(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP03, 0x01)
	enc := bytes.Repeat([]byte{0xAA}, 16)
	mac := bytes.Repeat([]byte{0xBB}, 16)
	dek := bytes.Repeat([]byte{0xCC}, 16)

	cmd, expectedKCV, err := putKeySCP03Cmd(ref, enc, mac, dek, 0xFF)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X, got 0x%02X", insPutKey, cmd.INS)
	}
	if cmd.P1 != 0xFF {
		t.Errorf("expected P1=0xFF (replaceKvn), got 0x%02X", cmd.P1)
	}
	if cmd.P2 != (KeyIDSCP03 | 0x80) {
		t.Errorf("expected P2=0x%02X, got 0x%02X", KeyIDSCP03|0x80, cmd.P2)
	}
	if expectedKCV == nil || len(expectedKCV) != 3 {
		t.Error("expected 3-byte KCV")
	}

	// Data: 1 (version) + 3*(2 + 16 + 1 + 3) = 1 + 66 = 67
	if len(cmd.Data) != 67 {
		t.Errorf("expected 67 bytes data, got %d", len(cmd.Data))
	}
	if cmd.Data[0] != 0x01 {
		t.Errorf("first byte should be key version 0x01, got 0x%02X", cmd.Data[0])
	}
}

func TestPutKeySCP03Cmd_WrongKeyLength(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP03, 0x01)
	_, _, err := putKeySCP03Cmd(ref, make([]byte, 8), make([]byte, 16), make([]byte, 16), 0)
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestPutKeyECPrivateCmd_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ref := NewKeyReference(KeyIDSCP11b, 0x03)

	cmd, err := putKeyECPrivateCmd(ref, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X", insPutKey)
	}
	if cmd.P1 != 0x00 {
		t.Errorf("expected P1=0x00 (new key), got 0x%02X", cmd.P1)
	}
}

func TestPutKeyECPublicCmd_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ref := NewKeyReference(KeyIDOCE, 0x03)

	cmd, err := putKeyECPublicCmd(ref, &key.PublicKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X", insPutKey)
	}
	// Data: 1 (version) + 1 (type) + 1 (len) + 65 (point) + 1 (no kcv) = 69
	if len(cmd.Data) != 69 {
		t.Errorf("expected 69 bytes data, got %d", len(cmd.Data))
	}
}

func TestGenerateECKeyCmd(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP11b, 0x01)
	cmd := generateECKeyCmd(ref, 0)
	if cmd.INS != insGenAsymKey {
		t.Errorf("expected INS 0x%02X", insGenAsymKey)
	}
	if cmd.P1 != 0x00 {
		t.Errorf("expected P1=0x00 for new key")
	}
	if cmd.P2 != KeyIDSCP11b {
		t.Errorf("expected P2=0x%02X", KeyIDSCP11b)
	}
}

func TestDeleteKeyCmd(t *testing.T) {
	ref := NewKeyReference(0, 0x01) // delete by KVN only
	cmd, err := deleteKeyCmd(ref, false)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insDeleteKey {
		t.Errorf("expected INS 0x%02X", insDeleteKey)
	}
	// Should contain D2 01 01 (KVN=1)
	if !bytes.Contains(cmd.Data, []byte{0xD2, 0x01, 0x01}) {
		t.Errorf("expected KVN TLV in data: %X", cmd.Data)
	}
}

func TestDeleteKeyCmd_BothZero(t *testing.T) {
	_, err := deleteKeyCmd(NewKeyReference(0, 0), false)
	if err == nil {
		t.Error("expected error when both KID and KVN are zero")
	}
}

// --- Response parsing tests ---

func TestParseKeyInformation(t *testing.T) {
	// Construct a minimal E0 { C0 { KID=0x01, KVN=0x03, type=0x88, len=0x10 } }
	inner := []byte{0x01, 0x03, 0x88, 0x10}
	data := []byte{0xE0, byte(2 + len(inner)), 0xC0, byte(len(inner))}
	data = append(data, inner...)

	infos, err := parseKeyInformation(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].Reference.ID != 0x01 || infos[0].Reference.Version != 0x03 {
		t.Errorf("wrong reference: %v", infos[0].Reference)
	}
	if infos[0].Components[0x88] != 0x10 {
		t.Error("expected component 0x88=0x10")
	}
}

func TestParseKeyInformation_Empty(t *testing.T) {
	infos, err := parseKeyInformation(nil)
	if err != nil {
		t.Fatal(err)
	}
	if infos != nil {
		t.Error("expected nil for empty data")
	}
}

func TestParseCertificates_SingleDER(t *testing.T) {
	// A minimal structure that isn't valid TLV triggers the raw DER fallback.
	raw := []byte{0x30, 0x00} // minimal ASN.1 SEQUENCE
	certs, err := parseCertificates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
}

func TestParseGeneratedPublicKey_RawPoint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point := elliptic.Marshal(key.Curve, key.X, key.Y)

	pub, err := parseGeneratedPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestParseGeneratedPublicKey_Empty(t *testing.T) {
	_, err := parseGeneratedPublicKey(nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParsePutKeyChecksum(t *testing.T) {
	// Response: KVN(1) + KCV(3) per key component
	data := []byte{0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33}
	kcv, err := parsePutKeyChecksum(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kcv, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("unexpected KCV: %X", kcv)
	}
}

func TestParsePutKeyChecksum_TooShort(t *testing.T) {
	_, err := parsePutKeyChecksum([]byte{0x01})
	if err == nil {
		t.Error("expected error for too-short response")
	}
}

func TestParseAllowlist(t *testing.T) {
	// Build 70 { 93 { serial1 } 93 { serial2 } }
	s1, _ := hex.DecodeString("aabbccdd")
	s2, _ := hex.DecodeString("11223344")
	data := []byte{0x70, byte(2 + len(s1) + 2 + len(s2)),
		0x93, byte(len(s1))}
	data = append(data, s1...)
	data = append(data, 0x93, byte(len(s2)))
	data = append(data, s2...)

	serials, err := parseAllowlist(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(serials) != 2 {
		t.Fatalf("expected 2 serials, got %d", len(serials))
	}
	if serials[0] != "aabbccdd" || serials[1] != "11223344" {
		t.Errorf("unexpected serials: %v", serials)
	}
}

// --- Store data construction tests ---

func TestStoreAllowlistData_Valid(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	data, err := storeAllowlistData(ref, []string{"aabb", "ccdd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestStoreAllowlistData_InvalidHex(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	_, err := storeAllowlistData(ref, []string{"not-hex"})
	if err == nil {
		t.Error("expected error for invalid hex serial")
	}
}

func TestStoreCertificatesData(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP11b, 0x01)
	cert1 := []byte{0x30, 0x82, 0x01, 0x00} // fake DER
	cert2 := []byte{0x30, 0x82, 0x02, 0x00}

	data := storeCertificatesData(ref, [][]byte{cert1, cert2})
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
	// Should start with BF21 tag
	if data[0] != 0xBF || data[1] != 0x21 {
		t.Errorf("expected BF21 prefix, got %02X%02X", data[0], data[1])
	}
}

func TestStoreCaIssuerData(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	ski := []byte{0x01, 0x02, 0x03, 0x04}

	data := storeCaIssuerData(ref, ski)
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
	// Should contain the SKI bytes
	if !bytes.Contains(data, ski) {
		t.Error("data should contain SKI bytes")
	}
}

// --- Session auth guard tests ---

func TestRequireAuth_Unauthenticated(t *testing.T) {
	s := &Session{authenticated: false}
	err := s.requireAuth()
	if err != ErrNotAuthenticated {
		t.Errorf("expected ErrNotAuthenticated, got: %v", err)
	}
}

func TestRequireAuth_Authenticated(t *testing.T) {
	s := &Session{authenticated: true}
	err := s.requireAuth()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSession_Protocol_Unauthenticated(t *testing.T) {
	s := &Session{authenticated: false}
	if s.Protocol() != "none" {
		t.Errorf("expected 'none', got %q", s.Protocol())
	}
}

func TestSession_IsAuthenticated(t *testing.T) {
	s := &Session{authenticated: false}
	if s.IsAuthenticated() {
		t.Error("expected false")
	}
	s.authenticated = true
	if !s.IsAuthenticated() {
		t.Error("expected true")
	}
}
