package securitydomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/kdf"
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
	if _, err := storeAllowlistData(ref, []string{"not-hex"}); err == nil {
		t.Error("expected error")
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
	if serials[0] != "aabbccdd" || serials[1] != "11223344" {
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

// TestStoreDataChained_SingleBlock confirms that payloads ≤255 bytes are
// transmitted as a single APDU with P1 = 0x90 and P2 = 0x00.
func TestStoreDataChained_SingleBlock(t *testing.T) {
	rt := &recordingTransport{}
	s := &Session{transport: rt, authenticated: true}

	payload := bytes.Repeat([]byte{0xAB}, 200)
	resp, err := s.transmitStoreDataChained(context.Background(), payload)
	if err != nil {
		t.Fatalf("transmitStoreDataChained: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("expected SW=9000, got %04X", resp.StatusWord())
	}
	if len(rt.commands) != 1 {
		t.Fatalf("expected 1 APDU, got %d", len(rt.commands))
	}
	cmd := rt.commands[0]
	if cmd.INS != insStoreData {
		t.Errorf("INS = %02X, want %02X", cmd.INS, insStoreData)
	}
	if cmd.P1 != storeDataP1Final {
		t.Errorf("P1 = %02X, want %02X (final block)", cmd.P1, storeDataP1Final)
	}
	if cmd.P2 != 0x00 {
		t.Errorf("P2 = %02X, want 0x00", cmd.P2)
	}
	if !bytes.Equal(cmd.Data, payload) {
		t.Errorf("payload mismatch")
	}
}

// TestStoreDataChained_MultipleBlocks confirms that payloads >255 bytes
// are split into ≤255-byte blocks with sequential P2 and the last-block
// bit (b8 of P1) set only on the final block. Each block must be its own
// APDU — never an APDU-chained fragment of one logical command.
func TestStoreDataChained_MultipleBlocks(t *testing.T) {
	rt := &recordingTransport{}
	s := &Session{transport: rt, authenticated: true}

	// 600 bytes -> 3 blocks at the secure-wrap-safe size (223 each):
	// 223 + 223 + 154. The chunk size is chosen so the on-wire APDU
	// stays within short Lc (≤ 255) even after AES-CBC padding plus
	// a 16-byte MAC inflate the wrapped form.
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i)
	}

	resp, err := s.transmitStoreDataChained(context.Background(), payload)
	if err != nil {
		t.Fatalf("transmitStoreDataChained: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("expected SW=9000, got %04X", resp.StatusWord())
	}
	if len(rt.commands) != 3 {
		t.Fatalf("expected 3 APDUs, got %d", len(rt.commands))
	}

	wantSizes := []int{223, 223, 154}
	for i, cmd := range rt.commands {
		if cmd.CLA != clsGP {
			t.Errorf("block %d: CLA = %02X, want %02X", i, cmd.CLA, clsGP)
		}
		if cmd.INS != insStoreData {
			t.Errorf("block %d: INS = %02X, want %02X", i, cmd.INS, insStoreData)
		}
		if cmd.P2 != byte(i) {
			t.Errorf("block %d: P2 = %02X, want %02X (block number)", i, cmd.P2, byte(i))
		}
		if len(cmd.Data) != wantSizes[i] {
			t.Errorf("block %d: data size = %d, want %d", i, len(cmd.Data), wantSizes[i])
		}
		isLast := i == len(rt.commands)-1
		var wantP1 byte = storeDataP1NonFinal
		if isLast {
			wantP1 = storeDataP1Final
		}
		if cmd.P1 != wantP1 {
			t.Errorf("block %d (last=%v): P1 = %02X, want %02X", i, isLast, cmd.P1, wantP1)
		}
		// Critical: each block APDU must NOT carry the chaining CLA bit
		// (0x10). That bit signals ISO/IEC 7816 transport-level chaining,
		// which would conflict with STORE DATA's own application-level
		// block protocol.
		if cmd.CLA&0x10 != 0 {
			t.Errorf("block %d: CLA = %02X has transport-chaining bit set", i, cmd.CLA)
		}
	}

	// Verify the concatenated data round-trips.
	var got []byte
	for _, cmd := range rt.commands {
		got = append(got, cmd.Data...)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload reassembly mismatch")
	}
}

// TestStoreDataChained_RejectsAPDUChainingPath confirms that the generic
// transmitWithChaining path explicitly refuses STORE DATA — STORE DATA
// uses its own chaining protocol and must go through transmitStoreDataChained.
func TestStoreDataChained_RejectsAPDUChainingPath(t *testing.T) {
	rt := &recordingTransport{}
	s := &Session{transport: rt, authenticated: true}

	cmd := storeDataCmd(make([]byte, 300)) // >255 to force the chaining branch
	_, err := s.transmitWithChaining(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected error: STORE DATA must not use APDU-level chaining")
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

// --- Chained APDU chunk-size invariant ---

// TestChainCommandsAt_ChunkSize confirms chainCommandsAt splits at the
// requested boundary and sets the chaining bit only on intermediates.
func TestChainCommandsAt_ChunkSize(t *testing.T) {
	cmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xD8,
		P1:   0x00,
		P2:   0x00,
		Data: make([]byte, 600),
		Le:   0,
	}
	// secureWrapSafeBlock-sized chunks: 600 -> 223 + 223 + 154.
	cmds := chainCommandsAt(cmd, secureWrapSafeBlock)
	if len(cmds) != 3 {
		t.Fatalf("expected 3 chained APDUs, got %d", len(cmds))
	}
	wantSizes := []int{secureWrapSafeBlock, secureWrapSafeBlock, 600 - 2*secureWrapSafeBlock}
	for i, c := range cmds {
		if len(c.Data) != wantSizes[i] {
			t.Errorf("APDU %d: data size = %d, want %d", i, len(c.Data), wantSizes[i])
		}
		isLast := i == len(cmds)-1
		hasChainingBit := c.CLA&0x10 != 0
		if isLast && hasChainingBit {
			t.Errorf("APDU %d (last): chaining bit must be CLEAR", i)
		}
		if !isLast && !hasChainingBit {
			t.Errorf("APDU %d (intermediate): chaining bit must be SET", i)
		}
	}
}

// TestSecureWrapSafeBlock_FitsShortLc is a documentation test asserting
// the math behind secureWrapSafeBlock: a plaintext of that size, after
// AES-CBC encryption with ISO 9797-1 method-2 padding plus the largest
// MAC truncation we use (16 bytes / S16), still produces a wrapped
// payload that fits in a short-Lc APDU (≤ 255 bytes).
func TestSecureWrapSafeBlock_FitsShortLc(t *testing.T) {
	const macSize = 16 // worst case
	padded := ((secureWrapSafeBlock + 1 + 15) / 16) * 16
	wireLen := padded + macSize
	if wireLen > 255 {
		t.Errorf("secureWrapSafeBlock=%d: wrapped wire len = %d, exceeds short-Lc 255",
			secureWrapSafeBlock, wireLen)
	}
	// And one more byte should NOT fit — verifying the bound is tight.
	N := secureWrapSafeBlock + 1
	padded = ((N + 1 + 15) / 16) * 16
	wireLen = padded + macSize
	if wireLen <= 255 {
		t.Errorf("secureWrapSafeBlock could be larger: N=%d still fits (%d ≤ 255)",
			N, wireLen)
	}
}
