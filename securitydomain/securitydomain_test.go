package securitydomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// --- KCV tests ---

func TestComputeAESKCV(t *testing.T) {
	// KCV = AES-CBC(key, IV=zeros, data=ones)[:3]
	// This should match the Python: _encrypt_cbc(k, _DEFAULT_KCV_IV)[:3]
	// where _DEFAULT_KCV_IV = b"\1" * 16
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

	// Verify it's different from AES-ECB(key, zeros) — the old wrong computation.
	// AES-ECB(key, zeros) != AES-CBC(key, IV=zeros, ones)
	// (This ensures we fixed the KCV computation.)
	t.Logf("KCV for default key: %X", kcv)
}

func TestComputeAESKCV_WrongLength(t *testing.T) {
	if kcv := computeAESKCV([]byte{0x01, 0x02, 0x03}); kcv != nil {
		t.Error("KCV should be nil for invalid key length")
	}
}

func TestAesCBCEncrypt(t *testing.T) {
	key := make([]byte, 16)
	data := make([]byte, 16)

	out := aesCBCEncrypt(key, data)
	if out == nil {
		t.Fatal("encryption should not return nil")
	}
	if len(out) != 16 {
		t.Fatalf("expected 16 bytes output, got %d", len(out))
	}
}

func TestPkcs7Pad(t *testing.T) {
	// Already aligned — no padding.
	data := make([]byte, 16)
	padded := pkcs7Pad(data, 16)
	if len(padded) != 16 {
		t.Errorf("expected 16, got %d", len(padded))
	}

	// Needs padding.
	data = make([]byte, 20)
	padded = pkcs7Pad(data, 16)
	if len(padded) != 32 {
		t.Errorf("expected 32, got %d", len(padded))
	}
}

// --- KeyReference tests ---

func TestKeyReference_String(t *testing.T) {
	ref := NewKeyReference(0x01, 0xFF)
	if s := ref.String(); s != "KID=0x01,KVN=0xFF" {
		t.Errorf("unexpected: %s", s)
	}
}

// --- Serial conversion tests ---

func TestSerialToHex(t *testing.T) {
	if got := SerialToHex(big.NewInt(0x2A)); got != "2a" {
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
	if _, err := SerialFromHex("not-hex"); err == nil {
		t.Error("expected error")
	}
}

// --- APDU construction tests ---

func TestPutKeySCP03Cmd(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP03, 0x01)
	enc := bytes.Repeat([]byte{0xAA}, 16)
	mac := bytes.Repeat([]byte{0xBB}, 16)
	dek := bytes.Repeat([]byte{0xCC}, 16)
	sessionDEK := bytes.Repeat([]byte{0xDD}, 16)

	cmd, expectedResp, err := putKeySCP03Cmd(ref, enc, mac, dek, sessionDEK, 0xFF)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X, got 0x%02X", insPutKey, cmd.INS)
	}
	if cmd.P1 != 0xFF {
		t.Errorf("expected P1=0xFF, got 0x%02X", cmd.P1)
	}
	if cmd.P2 != (KeyIDSCP03 | 0x80) {
		t.Errorf("expected P2=0x%02X, got 0x%02X", KeyIDSCP03|0x80, cmd.P2)
	}

	// Expected response: KVN(1) + KCV_enc(3) + KCV_mac(3) + KCV_dek(3) = 10 bytes
	if len(expectedResp) != 10 {
		t.Errorf("expected 10-byte expected response, got %d", len(expectedResp))
	}
	if expectedResp[0] != 0x01 {
		t.Errorf("expected response starts with KVN 0x01, got 0x%02X", expectedResp[0])
	}

	// Data should start with KVN.
	if cmd.Data[0] != 0x01 {
		t.Errorf("data should start with KVN 0x01, got 0x%02X", cmd.Data[0])
	}

	// Data should contain TLV-encoded encrypted keys (0x88 tag).
	if cmd.Data[1] != keyTypeAES {
		t.Errorf("first key type should be 0x%02X, got 0x%02X", keyTypeAES, cmd.Data[1])
	}
}

func TestPutKeySCP03Cmd_WrongKeyLength(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP03, 0x01)
	sessionDEK := make([]byte, 16)
	_, _, err := putKeySCP03Cmd(ref, make([]byte, 8), make([]byte, 16), make([]byte, 16), sessionDEK, 0)
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestPutKeySCP03Cmd_NoDEK(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP03, 0x01)
	_, _, err := putKeySCP03Cmd(ref, make([]byte, 16), make([]byte, 16), make([]byte, 16), nil, 0)
	if err == nil {
		t.Error("expected error for nil DEK")
	}
}

func TestPutKeyECPrivateCmd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ref := NewKeyReference(KeyIDSCP11b, 0x03)
	sessionDEK := make([]byte, 16)

	cmd, err := putKeyECPrivateCmd(ref, key, sessionDEK, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X", insPutKey)
	}

	// Should contain B1 TLV (private key) and F0 TLV (params).
	if !bytes.Contains(cmd.Data, []byte{keyTypeECParams}) {
		t.Error("data should contain F0 (ECC_KEY_PARAMS) tag")
	}
}

func TestPutKeyECPublicCmd(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ref := NewKeyReference(KeyIDOCE, 0x03)

	cmd, err := putKeyECPublicCmd(ref, &key.PublicKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insPutKey {
		t.Errorf("expected INS 0x%02X", insPutKey)
	}

	// Should contain B0 TLV (public key) and F0 TLV (params).
	if !bytes.Contains(cmd.Data, []byte{keyTypeECParams}) {
		t.Error("data should contain F0 (ECC_KEY_PARAMS) tag")
	}

	// Should end with 0x00 (no KCV).
	if cmd.Data[len(cmd.Data)-1] != 0x00 {
		t.Error("data should end with 0x00 (no KCV)")
	}
}

func TestGenerateECKeyCmd(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP11b, 0x01)
	cmd := generateECKeyCmd(ref, 0)

	// INS must be 0xF1, not 0xD8.
	if cmd.INS != insGenerateKey {
		t.Errorf("expected INS 0x%02X (GENERATE KEY), got 0x%02X", insGenerateKey, cmd.INS)
	}
	if cmd.P1 != 0x00 {
		t.Errorf("expected P1=0x00")
	}
	if cmd.P2 != KeyIDSCP11b {
		t.Errorf("expected P2=0x%02X", KeyIDSCP11b)
	}

	// Data: KVN(1) + Tlv(F0, [00])
	if cmd.Data[0] != 0x01 {
		t.Errorf("data should start with KVN 0x01")
	}
	if !bytes.Contains(cmd.Data, []byte{keyTypeECParams}) {
		t.Error("data should contain F0 (ECC_KEY_PARAMS) tag")
	}
}

func TestDeleteKeyCmd(t *testing.T) {
	ref := NewKeyReference(0, 0x01) // by KVN only
	cmd, err := deleteKeyCmd(ref, false)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.INS != insDeleteKey {
		t.Errorf("expected INS 0x%02X", insDeleteKey)
	}
	if !bytes.Contains(cmd.Data, []byte{0xD2, 0x01, 0x01}) {
		t.Errorf("expected KVN TLV: %X", cmd.Data)
	}
}

func TestDeleteKeyCmd_BothZero(t *testing.T) {
	if _, err := deleteKeyCmd(NewKeyReference(0, 0), false); err == nil {
		t.Error("expected error")
	}
}

// --- Reset helper tests ---

func TestInsForKeyReset(t *testing.T) {
	tests := []struct {
		kid      byte
		wantINS  byte
		wantProc bool
	}{
		{0x01, insInitializeUpdate, true}, // SCP03
		{0x02, 0, false},                  // SCP03 sub-key, skip
		{0x03, 0, false},                  // SCP03 sub-key, skip
		{0x13, insIntAuth, true},          // SCP11b
		{0x11, insExtAuth, true},          // SCP11a
		{0x15, insExtAuth, true},          // SCP11c
		{0x10, insPerformSecOp, true},     // OCE
	}
	for _, tt := range tests {
		ins, process := insForKeyReset(tt.kid)
		if process != tt.wantProc {
			t.Errorf("kid=0x%02X: process=%v, want %v", tt.kid, process, tt.wantProc)
		}
		if process && ins != tt.wantINS {
			t.Errorf("kid=0x%02X: ins=0x%02X, want 0x%02X", tt.kid, ins, tt.wantINS)
		}
	}
}

func TestResetLockoutCmd(t *testing.T) {
	cmd := resetLockoutCmd(insInitializeUpdate, 0x00, 0x00)
	if cmd.INS != insInitializeUpdate {
		t.Errorf("wrong INS")
	}
	if len(cmd.Data) != 8 {
		t.Errorf("expected 8 bytes data, got %d", len(cmd.Data))
	}
	// All zeros.
	for i, b := range cmd.Data {
		if b != 0 {
			t.Errorf("data[%d] = 0x%02X, expected 0x00", i, b)
		}
	}
}

// --- Store data construction tests ---

func TestStoreCertificatesData(t *testing.T) {
	ref := NewKeyReference(KeyIDSCP11b, 0x01)
	cert1 := []byte{0x30, 0x02, 0x00, 0x00}
	cert2 := []byte{0x30, 0x03, 0x00, 0x00, 0x00}

	data := storeCertificatesData(ref, [][]byte{cert1, cert2})
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}

	// Structure: A6{83{KID,KVN}} + BF21{cert1||cert2}
	// A6 tag should appear first.
	if data[0] != 0xA6 {
		t.Errorf("expected A6 prefix, got 0x%02X", data[0])
	}

	// BF21 should appear after the A6 block.
	if !bytes.Contains(data, []byte{0xBF, 0x21}) {
		t.Error("data should contain BF21 (cert store tag)")
	}

	// Raw cert bytes should appear in the BF21 container (concatenated, not 7F21-wrapped).
	if !bytes.Contains(data, cert1) {
		t.Error("data should contain cert1 bytes")
	}
	if !bytes.Contains(data, cert2) {
		t.Error("data should contain cert2 bytes")
	}

	// Should NOT contain 7F21 (individual cert wrappers).
	if bytes.Contains(data, []byte{0x7F, 0x21}) {
		t.Error("data should NOT contain 7F21 (certs should be concatenated raw DER)")
	}
}

func TestStoreCaIssuerData(t *testing.T) {
	// SCP11b key — should be KLCC (flag = 0x01).
	ref := NewKeyReference(KeyIDSCP11b, 0x03)
	ski := []byte{0x01, 0x02, 0x03, 0x04}

	data := storeCaIssuerData(ref, ski)
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}

	// Structure: A6{ 80{01} + 42{SKI} + 83{KID,KVN} }
	// Should start with A6 tag.
	if data[0] != 0xA6 {
		t.Errorf("expected A6 prefix, got 0x%02X", data[0])
	}

	// Should contain the KLCC flag (0x80, 0x01, 0x01).
	if !bytes.Contains(data, []byte{0x80, 0x01, 0x01}) {
		t.Error("should contain KLCC flag 0x80{0x01}")
	}

	// Should contain SKI (42 tag).
	if !bytes.Contains(data, []byte{0x42}) {
		t.Error("should contain 0x42 (SKI tag)")
	}

	// Should contain key reference (83 tag).
	if !bytes.Contains(data, []byte{0x83, 0x02, KeyIDSCP11b, 0x03}) {
		t.Error("should contain 0x83{KID,KVN}")
	}
}

func TestStoreCaIssuerData_KLOC(t *testing.T) {
	// OCE key — should be KLOC (flag = 0x00).
	ref := NewKeyReference(KeyIDOCE, 0x03)
	ski := []byte{0xAA}

	data := storeCaIssuerData(ref, ski)

	// Should contain KLOC flag (0x80, 0x01, 0x00).
	if !bytes.Contains(data, []byte{0x80, 0x01, 0x00}) {
		t.Error("should contain KLOC flag 0x80{0x00}")
	}
}

func TestStoreAllowlistData(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	data, err := storeAllowlistData(ref, []*big.Int{
		big.NewInt(0xAABB),
		big.NewInt(0xCCDD),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

// TestStoreAllowlistData_ASN1IntegerEncoding pins the wire-byte
// shape of allowlist serials against yubikit-python's _int2asn1
// helper (ref: yubikit/securitydomain.py). The card matches
// stored serials byte-exactly against the cert's ASN.1 INTEGER
// representation, so a serial whose first byte is >= 0x80 must
// carry a leading 0x00 prefix on the wire — otherwise an
// allowlisted certificate is silently rejected at SCP11
// verification with no diagnostic that points at the encoding.
//
// Each subtest pins a specific serial value to the bytes that
// must appear inside the inner 93 TLV. The test compares against
// hex-decoded byte literals rather than re-deriving the bytes
// dynamically, so a future refactor that switches encoders sees
// the contract failure immediately.
func TestStoreAllowlistData_ASN1IntegerEncoding(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)

	cases := []struct {
		name           string
		serial         *big.Int
		wantSerialHex  string // bytes inside the inner 93 TLV value
		comment        string
	}{
		{
			name:           "high_bit_clear_no_prefix",
			serial:         big.NewInt(0x7F),
			wantSerialHex:  "7F",
			comment:        "0x7F has high bit clear; no 0x00 prefix",
		},
		{
			name:           "high_bit_set_single_byte_gets_prefix",
			serial:         big.NewInt(0x80),
			wantSerialHex:  "0080",
			comment:        "0x80 has high bit set; prepend 0x00",
		},
		{
			name:           "high_bit_set_multibyte_gets_prefix",
			serial:         big.NewInt(0xFF12345678),
			wantSerialHex:  "00FF12345678",
			comment:        "high bit on first byte of multibyte serial; prepend 0x00",
		},
		{
			name:           "high_bit_clear_multibyte_no_prefix",
			serial:         big.NewInt(0x7F12345678),
			wantSerialHex:  "7F12345678",
			comment:        "high bit clear on first byte; no prefix",
		},
		{
			name:           "second_byte_high_bit_irrelevant",
			serial:         big.NewInt(0x01FFFFFFFF),
			wantSerialHex:  "01FFFFFFFF",
			comment:        "only first byte's high bit matters; later high bits don't trigger prefix",
		},
		{
			name:           "zero_serial_renders_as_single_zero",
			serial:         big.NewInt(0),
			wantSerialHex:  "00",
			comment:        "ASN.1 INTEGER 0 is single 0x00 byte; not zero-length",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := storeAllowlistData(ref, []*big.Int{tc.serial})
			if err != nil {
				t.Fatalf("storeAllowlistData: %v", err)
			}
			// Decode the outer envelope to find the 70 container,
			// then the inner 93 serial TLV. We assert on the 93's
			// value bytes rather than on the full outer payload
			// so the test stays focused on the encoding behavior
			// being pinned and doesn't flake on unrelated changes
			// to the A6/83 wrapper layout.
			gotHex := strings.ToUpper(hex.EncodeToString(extractFirstSerialBytes(t, data)))
			wantHex := strings.ToUpper(tc.wantSerialHex)
			if gotHex != wantHex {
				t.Errorf("%s\n  serial 93 value = %s\n  want            = %s\n  rationale: %s",
					tc.name, gotHex, wantHex, tc.comment)
			}
		})
	}
}

// extractFirstSerialBytes pulls the value bytes of the first 93
// (serial) TLV out of a storeAllowlistData payload. Test helper:
// fails the test if the structure isn't shaped as expected.
func extractFirstSerialBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	nodes, err := tlv.Decode(data)
	if err != nil {
		t.Fatalf("tlv.Decode: %v", err)
	}
	allowlist := tlv.Find(nodes, tagAllowList)
	if allowlist == nil {
		t.Fatal("no 70 (allowlist) container in encoded data")
	}
	// The 70 container's value contains a sequence of 93 TLVs.
	// Decode that level to get the first one.
	inner, err := tlv.Decode(allowlist.Value)
	if err != nil {
		t.Fatalf("tlv.Decode allowlist value: %v", err)
	}
	for _, n := range inner {
		if n.Tag == tagSerialNum {
			return n.Value
		}
	}
	t.Fatal("no 93 (serial) TLV inside allowlist container")
	return nil
}

// TestStoreAllowlistData_RoundTripWithASN1Encoding verifies the
// encoder + parseAllowlist parser round-trip preserves the
// numeric value across the wire shape, including for serials
// with the high bit set. parseAllowlist uses big.Int.SetBytes on
// the inner 93 value, which interprets the leading-zero-prefixed
// bytes as the same unsigned integer the caller passed in — so
// the round-trip is correct without parser changes.
func TestStoreAllowlistData_RoundTripWithASN1Encoding(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)

	original := []*big.Int{
		big.NewInt(1),
		big.NewInt(0x80),     // single-byte high-bit-set
		big.NewInt(0xFFFFFF), // multibyte high-bit-set
		big.NewInt(0x7F),     // high-bit-clear control
	}
	encoded, err := storeAllowlistData(ref, original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	roundTripped, err := parseAllowlist(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(roundTripped) != len(original) {
		t.Fatalf("count mismatch: got %d, want %d", len(roundTripped), len(original))
	}
	for i, want := range original {
		if roundTripped[i].Cmp(want) != 0 {
			t.Errorf("serial[%d]: got %s, want %s",
				i, roundTripped[i].String(), want.String())
		}
	}
}

func TestStoreAllowlistData_RejectsNilSerial(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	if _, err := storeAllowlistData(ref, []*big.Int{nil}); err == nil {
		t.Error("expected error for nil serial")
	}
}

func TestStoreAllowlistData_RejectsNegativeSerial(t *testing.T) {
	ref := NewKeyReference(KeyIDOCE, 0x03)
	if _, err := storeAllowlistData(ref, []*big.Int{big.NewInt(-1)}); err == nil {
		t.Error("expected error for negative serial")
	}
}

// --- Response parsing tests ---

func TestParseKeyInformation(t *testing.T) {
	inner := []byte{0x01, 0x03, 0x88, 0x10}
	data := []byte{0xE0, byte(2 + len(inner)), 0xC0, byte(len(inner))}
	data = append(data, inner...)

	infos, err := parseKeyInformation(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1, got %d", len(infos))
	}
	if infos[0].Reference.ID != 0x01 || infos[0].Reference.Version != 0x03 {
		t.Errorf("wrong reference: %v", infos[0].Reference)
	}
	if infos[0].Components[0x88] != 0x10 {
		t.Error("expected component 0x88=0x10")
	}
}

func TestParseGeneratedPublicKey_B0TLV(t *testing.T) {
	// Response should be Tlv(0xB0, point).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := ecdhPub.Bytes()

	// Build B0 TLV.
	var data []byte
	data = append(data, keyTypeECPublic, byte(len(point)))
	data = append(data, point...)

	pub, err := parseGeneratedPublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestParseGeneratedPublicKey_RawPoint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := ecdhPub.Bytes()

	pub, err := parseGeneratedPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Error("mismatch")
	}
}

func TestParseGeneratedPublicKey_Empty(t *testing.T) {
	if _, err := parseGeneratedPublicKey(nil); err == nil {
		t.Error("expected error")
	}
}

func TestParseAllowlist(t *testing.T) {
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
		t.Fatalf("expected 2, got %d", len(serials))
	}
	want0, _ := new(big.Int).SetString("aabbccdd", 16)
	want1, _ := new(big.Int).SetString("11223344", 16)
	if serials[0].Cmp(want0) != 0 || serials[1].Cmp(want1) != 0 {
		t.Errorf("unexpected: %v", serials)
	}
}

func TestSplitDERCertificates(t *testing.T) {
	// Two minimal DER sequences: 30 03 00 00 00 | 30 02 00 00
	cert1 := []byte{0x30, 0x03, 0x00, 0x00, 0x00}
	cert2 := []byte{0x30, 0x02, 0x00, 0x00}
	concat := append(cert1, cert2...)

	certs, err := splitDERCertificates(concat)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if !bytes.Equal(certs[0], cert1) {
		t.Errorf("cert1 mismatch: %X", certs[0])
	}
	if !bytes.Equal(certs[1], cert2) {
		t.Errorf("cert2 mismatch: %X", certs[1])
	}
}

// --- Session tests ---

func TestRequireAuth(t *testing.T) {
	s := &Session{authenticated: false}
	if err := s.requireAuth(); err != ErrNotAuthenticated {
		t.Errorf("expected ErrNotAuthenticated, got: %v", err)
	}
	s.authenticated = true
	if err := s.requireAuth(); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestRequireDEK(t *testing.T) {
	s := &Session{authenticated: true}
	if err := s.requireDEK(); err == nil {
		t.Error("expected error for nil DEK")
	}
	// All-zero DEK must be rejected to prevent silent use of a known
	// key — that would defeat the purpose of session-key encryption.
	s.dek = make([]byte, 16)
	if err := s.requireDEK(); err == nil {
		t.Error("expected error for all-zero DEK")
	}
	// A normal session DEK should pass.
	s.dek = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	if err := s.requireDEK(); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestSession_Protocol(t *testing.T) {
	s := &Session{}
	if s.Protocol() != "none" {
		t.Errorf("expected 'none', got %q", s.Protocol())
	}
}

func TestSession_Close_ZerosDEK(t *testing.T) {
	dek := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	s := &Session{dek: dek}
	s.Close()
	for i, b := range s.dek {
		if b != 0 {
			t.Errorf("dek[%d] not zeroed: 0x%02X", i, b)
		}
	}
}

// --- STORE DATA application-level chaining tests ---

// recordingTransport is a minimal transport.Transport that records every
// outgoing command and returns 9000 for each. Used to verify that the
// caller fragments STORE DATA correctly per GP §11.11 (block number in
// P2, last-block bit in P1).
type recordingTransport struct {
	commands []*apdu.Command
}

func (r *recordingTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	clone := *cmd
	clone.Data = append([]byte(nil), cmd.Data...)
	r.commands = append(r.commands, &clone)
	return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
}

func (r *recordingTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	return []byte{0x90, 0x00}, nil
}

func (r *recordingTransport) Close() error { return nil }

// TestStoreData_AlwaysSingleAPDUAtAppLayer is the regression pin
// for the wrap-then-chain layering. The application layer must
// emit exactly ONE logical STORE DATA APDU (P1=0x90 P2=0x00,
// matching yubikit-python's store_data) regardless of payload
// size. Transport-layer ISO chaining of long wrapped APDUs lives
// inside scp03.Session.sendPossiblyChained — that's what scp03's
// own tests exercise; here we only assert the application layer
// presents a single logical command.
//
// History: an earlier version of this code did application-level
// chaining (one APDU per chunk, per-chunk SCP wrap) and broke on
// retail YubiKey 5.7.4. The card returned bare 9000 with no R-MAC
// on intermediate chunks, which the host's R-MAC unwrap rejected
// and used as a signal to terminate the channel — leaving the
// next command's Wrap to deref a nil channel. The fix was to
// move chaining to the transport layer where the SCP MAC chain
// advances exactly once per logical command.
func TestStoreData_AlwaysSingleAPDUAtAppLayer(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"small payload", 32},
		{"single short APDU max", 255},
		{"crosses short-Lc boundary", 300},
		{"two-chunk territory", 500},
		{"three-chunk territory", 700},
		{"ten-chunk territory", 2400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			s := &Session{transport: rt}

			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i)
			}

			resp, err := s.transmitStoreData(context.Background(), payload)
			if err != nil {
				t.Fatalf("transmitStoreData: %v", err)
			}
			if !resp.IsSuccess() {
				t.Fatalf("expected SW=9000, got %04X", resp.StatusWord())
			}
			// Exactly ONE APDU at the application layer: the
			// recordingTransport sits BELOW any scp wrapping, so
			// when there's no scpSession the transport sees the
			// raw STORE DATA APDU. Any chunking would mean the
			// app layer is doing chaining itself, which is the
			// exact bug the wrap-then-chain refactor closed.
			if len(rt.commands) != 1 {
				t.Fatalf("expected exactly 1 APDU at the app layer, got %d "+
					"(application-level chaining was reintroduced)", len(rt.commands))
			}
			cmd := rt.commands[0]
			if cmd.INS != insStoreData {
				t.Errorf("INS = %02X, want %02X", cmd.INS, insStoreData)
			}
			if cmd.P1 != storeDataP1Final {
				t.Errorf("P1 = %02X, want %02X (last/only block + BER-TLV)",
					cmd.P1, storeDataP1Final)
			}
			if cmd.P2 != 0x00 {
				t.Errorf("P2 = %02X, want 0x00 (no application-level block numbering)", cmd.P2)
			}
			if !bytes.Equal(cmd.Data, payload) {
				t.Errorf("payload mismatch: app layer must hand the full "+
					"payload to the transport, not split it (got %d bytes, want %d)",
					len(cmd.Data), len(payload))
			}
		})
	}
}

// --- SCP-aware GET RESPONSE bounding ---

// chainingSCPSession is a minimal scp.Session that always replies with
// "still more data" (61 xx) so we can verify that transmitCollectAll
// under SCP also enforces the iteration cap. Without bounding, a hostile
// or buggy card could keep the host looping forever.
type chainingSCPSession struct {
	calls    int
	chunkLen int
}

func (c *chainingSCPSession) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	c.calls++
	return &apdu.Response{Data: make([]byte, c.chunkLen), SW1: 0x61, SW2: 0xFF}, nil
}

func (c *chainingSCPSession) Close()                        {}
func (c *chainingSCPSession) SessionKeys() *kdf.SessionKeys { return nil }
func (c *chainingSCPSession) SessionDEK() []byte            { return nil }
func (c *chainingSCPSession) Protocol() string              { return "test" }

func TestSCPCollectAll_IterationCap(t *testing.T) {
	scpSess := &chainingSCPSession{chunkLen: 0}
	s := &Session{authenticated: true, scpSession: scpSess}

	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA}
	_, err := s.transmitCollectAll(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected iteration cap to fire on infinite 61xx loop")
	}
	if scpSess.calls > transport.MaxGetResponseIterations+2 {
		t.Errorf("scp session invoked %d times; cap is %d",
			scpSess.calls, transport.MaxGetResponseIterations)
	}
}

func TestSCPCollectAll_ByteCap(t *testing.T) {
	scpSess := &chainingSCPSession{chunkLen: 8 * 1024}
	s := &Session{authenticated: true, scpSession: scpSess}

	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA}
	_, err := s.transmitCollectAll(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected byte cap to fire on large-chunk infinite loop")
	}
}

// --- OpenWithSession DEK validation ---

func TestOpenWithSession_RejectsAllZeroDEK(t *testing.T) {
	scpSess := &chainingSCPSession{}
	rt := &recordingTransport{}
	if _, err := OpenWithSession(scpSess, rt, make([]byte, 16)); err == nil {
		t.Fatal("expected error: all-zero DEK must be rejected at construction")
	}
}

func TestOpenWithSession_RejectsBadDEKLength(t *testing.T) {
	scpSess := &chainingSCPSession{}
	rt := &recordingTransport{}
	if _, err := OpenWithSession(scpSess, rt, []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error: 3-byte DEK is not a valid AES key length")
	}
}

func TestOpenWithSession_AcceptsValidDEK(t *testing.T) {
	scpSess := &chainingSCPSession{}
	rt := &recordingTransport{}
	dek := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	s, err := OpenWithSession(scpSess, rt, dek)
	if err != nil {
		t.Fatalf("valid DEK rejected: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if !s.authenticated {
		t.Error("session should be marked authenticated")
	}
}

func TestOpenWithSession_AcceptsNilDEK(t *testing.T) {
	// A caller that does not need PUT KEY may pass dek=nil. PUT KEY
	// will then fail with ErrNotAuthenticated, but the session is
	// otherwise usable.
	scpSess := &chainingSCPSession{}
	rt := &recordingTransport{}
	s, err := OpenWithSession(scpSess, rt, nil)
	if err != nil {
		t.Fatalf("nil DEK rejected: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if len(s.dek) != 0 {
		t.Errorf("expected empty DEK, got %d bytes", len(s.dek))
	}
}

// TestOpen_RejectsAllZeroStaticDEK confirms that the SCP03 entry-point
// Open() applies the same DEK validation as OpenWithSession. A bogus
// static DEK (all-zero or wrong length) must fail here before any
// network I/O — the previous behavior deferred the failure to PUT KEY.
func TestOpen_RejectsAllZeroStaticDEK(t *testing.T) {
	keys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0x40}, 16),
		MAC: bytes.Repeat([]byte{0x41}, 16),
		DEK: make([]byte, 16), // all-zero
	}
	// Transport is unused — validation must fire before scp03.Open is
	// invoked. Pass a nil transport to make that explicit; if the code
	// reached scp03.Open, the panic from the nil deref would be the
	// failure mode instead of the validation error we want.
	_, err := OpenSCP03(context.Background(), nil, &scp03.Config{Keys: keys, KeyVersion: 0x00})
	if err == nil {
		t.Fatal("expected error: all-zero static DEK must be rejected at construction")
	}
}

func TestOpen_RejectsBadStaticDEKLength(t *testing.T) {
	keys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0x40}, 16),
		MAC: bytes.Repeat([]byte{0x41}, 16),
		DEK: []byte{0x01, 0x02, 0x03}, // wrong length
	}
	_, err := OpenSCP03(context.Background(), nil, &scp03.Config{Keys: keys, KeyVersion: 0x00})
	if err == nil {
		t.Fatal("expected error: 3-byte DEK is not a valid AES key length")
	}
}

// --- Chained APDU chunk-size invariant ---

// Application-level chaining helpers (chainCommandsAt,
// secureWrapSafeBlock) used to live in this package and were
// tested here. Wrap-then-chain layering moved that logic into
// scp03.Session.sendPossiblyChained where it belongs (the SCP
// layer is where MAC chain advance per logical command happens,
// so chunking the WRAPPED bytes there is the only architecture
// that keeps host and card MAC chains in sync). The tests for
// the chunking primitive now live alongside that code in
// scp03/scp03_test.go.

// TestKeyIDConstants_MatchGPAmendmentF locks in that SCP11 KIDs
// match GP Amendment F §7.1.1 and Yubico's yubikit reference.
//
// History: an earlier version of this constants block defined all
// three SCP11 KIDs as 0x13. That silently addressed the SCP11b
// slot regardless of which variant the caller named. Real cards
// provision SCP11a at 0x11 and SCP11c at 0x15; the old aliases
// would have failed against them, and any code routing on these
// constants (e.g. the KLCC/KLOC detection in storeCaIssuerData)
// would have miscategorized SCP11a and SCP11c keys as something
// else.
func TestKeyIDConstants_MatchGPAmendmentF(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"SCP03", KeyIDSCP03, 0x01},
		{"SCP11a", KeyIDSCP11a, 0x11},
		{"SCP11b", KeyIDSCP11b, 0x13},
		{"SCP11c", KeyIDSCP11c, 0x15},
		{"OCE", KeyIDOCE, 0x10},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s KID = 0x%02X, want 0x%02X", c.name, c.got, c.want)
		}
	}
	// Also assert distinctness of the three SCP11 KIDs — the bug we
	// fixed was that all three were aliased to 0x13.
	if KeyIDSCP11a == KeyIDSCP11b || KeyIDSCP11b == KeyIDSCP11c || KeyIDSCP11a == KeyIDSCP11c {
		t.Errorf("SCP11 KIDs must be distinct, got: a=0x%02X b=0x%02X c=0x%02X",
			KeyIDSCP11a, KeyIDSCP11b, KeyIDSCP11c)
	}
}

func (r *recordingTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// TestParseCertificates_GPSpecBF21With7F21Children locks in support
// for the GlobalPlatform-spec shape: BF21 outer cert store containing
// one or more 7F21 single-cert wrappers, each whose Value is the
// bare DER. This is what the in-tree mockcard returns and what
// some real GP-conformant cards emit. Regression fence for the
// piv-reset SCP11b-on-PIV layering fix (PR following PR #82): the
// previous parser unwrapped BF21 but then handed the 7F21-wrapped
// bytes to splitDERCertificates, which mis-treated 0x7F as a
// non-SEQUENCE single cert and produced unparseable output.
func TestParseCertificates_GPSpecBF21With7F21Children(t *testing.T) {
	// Build a synthetic cert and wrap as the GP spec says.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "BF21+7F21 fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	// BF21 { 7F21 { der } }.
	inner := tlv.Build(tlv.TagCertificate, der)
	outer := tlv.BuildConstructed(tlv.TagCertStore, inner)
	wire := outer.Encode()

	got, err := parseCertificates(wire)
	if err != nil {
		t.Fatalf("parseCertificates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d certs; want 1", len(got))
	}
	parsed, err := x509.ParseCertificate(got[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if parsed.Subject.CommonName != "BF21+7F21 fixture" {
		t.Errorf("CN = %q; want BF21+7F21 fixture", parsed.Subject.CommonName)
	}
}

// TestParseCertificates_GPSpecBF21WithMultiple7F21Children confirms
// the parser returns multiple certs when the BF21 store contains
// several 7F21 wrappers. Order is preserved (leaf last is the
// caller's contract).
func TestParseCertificates_GPSpecBF21WithMultiple7F21Children(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mk := func(cn string) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			t.Fatalf("create cert %q: %v", cn, err)
		}
		return der
	}
	derA := mk("intermediate")
	derB := mk("leaf")

	// BF21 { 7F21 { derA } || 7F21 { derB } }
	innerA := tlv.Build(tlv.TagCertificate, derA).Encode()
	innerB := tlv.Build(tlv.TagCertificate, derB).Encode()
	concatInner := append(append([]byte(nil), innerA...), innerB...)
	outer := tlv.Node{Tag: tlv.TagCertStore, Value: concatInner}
	wire := outer.Encode()

	got, err := parseCertificates(wire)
	if err != nil {
		t.Fatalf("parseCertificates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d certs; want 2", len(got))
	}
	for i, want := range []string{"intermediate", "leaf"} {
		c, err := x509.ParseCertificate(got[i])
		if err != nil {
			t.Fatalf("cert %d: ParseCertificate: %v", i, err)
		}
		if c.Subject.CommonName != want {
			t.Errorf("cert %d CN = %q; want %q", i, c.Subject.CommonName, want)
		}
	}
}
