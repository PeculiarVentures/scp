package pivapdu

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/scp/tlv"
)

func TestChangePIN_WireBytes(t *testing.T) {
	cmd, err := ChangePIN([]byte("123456"), []byte("654321"))
	if err != nil {
		t.Fatalf("ChangePIN: %v", err)
	}
	if cmd.CLA != 0x00 || cmd.INS != 0x24 || cmd.P1 != 0x00 || cmd.P2 != PINKeyRef {
		t.Errorf("header CLA/INS/P1/P2 = %02X %02X %02X %02X, want 00 24 00 80",
			cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	}
	if len(cmd.Data) != 16 {
		t.Errorf("data length = %d, want 16 (8+8 padded)", len(cmd.Data))
	}
	wantOld := []byte{'1', '2', '3', '4', '5', '6', 0xFF, 0xFF}
	wantNew := []byte{'6', '5', '4', '3', '2', '1', 0xFF, 0xFF}
	if !bytes.Equal(cmd.Data[:8], wantOld) {
		t.Errorf("old PIN bytes = %X, want %X", cmd.Data[:8], wantOld)
	}
	if !bytes.Equal(cmd.Data[8:], wantNew) {
		t.Errorf("new PIN bytes = %X, want %X", cmd.Data[8:], wantNew)
	}
}

func TestChangePIN_Lengths(t *testing.T) {
	if _, err := ChangePIN(nil, []byte("12345678")); err == nil {
		t.Error("expected error on empty old PIN")
	}
	if _, err := ChangePIN([]byte("12345678"), nil); err == nil {
		t.Error("expected error on empty new PIN")
	}
	tooLong := []byte("123456789")
	if _, err := ChangePIN(tooLong, []byte("12345678")); err == nil {
		t.Error("expected error on 9-byte old PIN")
	}
}

func TestChangePUK_WireBytes(t *testing.T) {
	cmd, err := ChangePUK([]byte("12345678"), []byte("87654321"))
	if err != nil {
		t.Fatalf("ChangePUK: %v", err)
	}
	if cmd.P2 != PUKKeyRef {
		t.Errorf("P2 = %02X, want %02X (PUKKeyRef)", cmd.P2, PUKKeyRef)
	}
	if cmd.INS != 0x24 {
		t.Errorf("INS = %02X, want 24", cmd.INS)
	}
}

func TestGetData_WireBytes(t *testing.T) {
	objID := []byte{0x5F, 0xC1, 0x05} // 9a slot
	cmd, err := GetData(objID)
	if err != nil {
		t.Fatalf("GetData: %v", err)
	}
	if cmd.INS != 0xCB {
		t.Errorf("INS = %02X, want CB (GET DATA)", cmd.INS)
	}
	// The data should be a 0x5C tag wrapping the object ID.
	nodes, err := tlv.Decode(cmd.Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	tag5c := tlv.Find(nodes, 0x5C)
	if tag5c == nil {
		t.Fatal("missing 0x5C tag in command data")
	}
	if !bytes.Equal(tag5c.Value, objID) {
		t.Errorf("0x5C value = %X, want %X", tag5c.Value, objID)
	}
}

func TestGetData_EmptyID(t *testing.T) {
	if _, err := GetData(nil); err == nil {
		t.Error("expected error on nil object ID")
	}
}

func TestPutData_WireBytes(t *testing.T) {
	objID := []byte{0x5F, 0xC1, 0x05}
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	cmd, err := PutData(objID, value)
	if err != nil {
		t.Fatalf("PutData: %v", err)
	}
	if cmd.INS != 0xDB {
		t.Errorf("INS = %02X, want DB (PUT DATA)", cmd.INS)
	}
	nodes, err := tlv.Decode(cmd.Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	tag5c := tlv.Find(nodes, 0x5C)
	if tag5c == nil || !bytes.Equal(tag5c.Value, objID) {
		t.Errorf("missing or wrong 0x5C: %v", tag5c)
	}
	tag53 := tlv.Find(nodes, 0x53)
	if tag53 == nil || !bytes.Equal(tag53.Value, value) {
		t.Errorf("missing or wrong 0x53: %v", tag53)
	}
}

func TestSlotToObjectID(t *testing.T) {
	cases := []struct {
		slot byte
		want []byte
	}{
		{0x9A, []byte{0x5F, 0xC1, 0x05}},
		{0x9C, []byte{0x5F, 0xC1, 0x0A}},
		{0x9D, []byte{0x5F, 0xC1, 0x0B}},
		{0x9E, []byte{0x5F, 0xC1, 0x01}},
		{0x82, []byte{0x5F, 0xC1, 0x0D}}, // retired 1
		{0x95, []byte{0x5F, 0xC1, 0x20}}, // retired 20
	}
	for _, c := range cases {
		got, err := SlotToObjectID(c.slot)
		if err != nil {
			t.Errorf("SlotToObjectID(%02X) err = %v", c.slot, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("SlotToObjectID(%02X) = %X, want %X", c.slot, got, c.want)
		}
	}
	if _, err := SlotToObjectID(0xF9); err == nil {
		t.Error("expected error on attestation slot (no cert object)")
	}
}

func TestGetCertificate_DispatchesToCorrectSlot(t *testing.T) {
	cmd, err := GetCertificate(0x9A)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	nodes, err := tlv.Decode(cmd.Data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	tag5c := tlv.Find(nodes, 0x5C)
	if tag5c == nil {
		t.Fatal("missing 0x5C")
	}
	if !bytes.Equal(tag5c.Value, []byte{0x5F, 0xC1, 0x05}) {
		t.Errorf("9a object ID wrong: %X", tag5c.Value)
	}
}

func TestDeleteCertificate_EmptyValue(t *testing.T) {
	cmd, err := DeleteCertificate(0x9A)
	if err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	nodes, _ := tlv.Decode(cmd.Data)
	tag53 := tlv.Find(nodes, 0x53)
	if tag53 == nil {
		t.Fatal("missing 0x53")
	}
	if len(tag53.Value) != 0 {
		t.Errorf("0x53 value length = %d, want 0 (empty for delete)", len(tag53.Value))
	}
}

func TestParseCertificateFromObject_Roundtrip(t *testing.T) {
	// Build a synthetic certificate object: 53 wrapping (70 cert, 71 01 00, FE 00).
	cert := []byte{0x30, 0x82, 0x01, 0x00, 0xFA, 0xCE} // pretend cert
	cert70 := tlv.Build(tlv.Tag(0x70), cert)
	cert71 := tlv.Build(tlv.Tag(0x71), []byte{0x00})
	certFE := tlv.Build(tlv.Tag(0xFE), nil)
	wrapper := tlv.BuildConstructed(tlv.Tag(0x53), cert70, cert71, certFE)

	got, err := ParseCertificateFromObject(wrapper.Encode())
	if err != nil {
		t.Fatalf("ParseCertificateFromObject: %v", err)
	}
	if !bytes.Equal(got, cert) {
		t.Errorf("got %X, want %X", got, cert)
	}
}

func TestParseCertificateFromObject_Empty(t *testing.T) {
	// Empty 0x53 wrapper should return (nil, nil) so callers can
	// distinguish absence from a parse error.
	wrapper := tlv.Build(tlv.Tag(0x53), nil)
	got, err := ParseCertificateFromObject(wrapper.Encode())
	if err != nil {
		t.Errorf("expected nil error on empty wrapper, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil bytes on empty wrapper, got %X", got)
	}
}

func TestParseCertificateFromObject_Malformed(t *testing.T) {
	if _, err := ParseCertificateFromObject(nil); err == nil {
		t.Error("expected error on nil input")
	}
	if _, err := ParseCertificateFromObject([]byte{0x70, 0x02, 0xDE, 0xAD}); err == nil {
		t.Error("expected error when 0x53 wrapper is missing")
	}
}
