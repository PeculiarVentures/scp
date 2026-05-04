package piv

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSlot(t *testing.T) {
	cases := []struct {
		in      string
		want    Slot
		wantErr bool
	}{
		{"9a", SlotPIVAuthentication, false},
		{"9A", SlotPIVAuthentication, false},
		{"0x9a", SlotPIVAuthentication, false},
		{"9c", SlotDigitalSignature, false},
		{"9d", SlotKeyMgmt, false},
		{"9e", SlotCardAuthentication, false},
		{"f9", SlotYubiKeyAttestation, false},
		{"82", SlotRetiredKeyMgmt1, false},
		{"95", SlotRetiredKeyMgmt20, false},
		{"88", Slot(0x88), false}, // mid-range retired
		{"81", 0, true},           // below retired range
		{"96", 0, true},           // above retired range
		{"00", 0, true},
		{"zz", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSlot(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseSlot(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSlot(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSlot(%q) = %02x, want %02x", c.in, byte(got), byte(c.want))
		}
	}
}

func TestSlotIsRetiredAndYubiKey(t *testing.T) {
	if !SlotRetiredKeyMgmt1.IsRetired() {
		t.Error("SlotRetiredKeyMgmt1.IsRetired() = false")
	}
	if !SlotRetiredKeyMgmt20.IsRetired() {
		t.Error("SlotRetiredKeyMgmt20.IsRetired() = false")
	}
	if SlotPIVAuthentication.IsRetired() {
		t.Error("SlotPIVAuthentication.IsRetired() = true")
	}
	if !SlotYubiKeyAttestation.IsYubiKeyOnly() {
		t.Error("SlotYubiKeyAttestation.IsYubiKeyOnly() = false")
	}
	if SlotPIVAuthentication.IsYubiKeyOnly() {
		t.Error("SlotPIVAuthentication.IsYubiKeyOnly() = true")
	}
}

func TestSlotString(t *testing.T) {
	cases := []struct {
		s    Slot
		want string
	}{
		{SlotPIVAuthentication, "9a (PIV Authentication)"},
		{SlotDigitalSignature, "9c (Digital Signature)"},
		{SlotYubiKeyAttestation, "f9 (YubiKey Attestation)"},
		{SlotRetiredKeyMgmt1, "82 (Retired Key Mgmt 1)"},
		{SlotRetiredKeyMgmt20, "95 (Retired Key Mgmt 20)"},
		{Slot(0x88), "88 (Retired Key Mgmt 7)"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Slot(%02x).String() = %q, want %q", byte(c.s), got, c.want)
		}
	}
}

func TestParseAlgorithm(t *testing.T) {
	cases := []struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		{"rsa2048", AlgorithmRSA2048, false},
		{"RSA2048", AlgorithmRSA2048, false},
		{"rsa-2048", AlgorithmRSA2048, false},
		{"eccp256", AlgorithmECCP256, false},
		{"ecc-p256", AlgorithmECCP256, false},
		{"p256", AlgorithmECCP256, false},
		{"P256", AlgorithmECCP256, false},
		{"eccp384", AlgorithmECCP384, false},
		{"p384", AlgorithmECCP384, false},
		{"ed25519", AlgorithmEd25519, false},
		{"x25519", AlgorithmX25519, false},
		{"rsa3072", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := ParseAlgorithm(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseAlgorithm(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAlgorithm(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseAlgorithm(%q) = %02x, want %02x", c.in, byte(got), byte(c.want))
		}
	}
}

func TestAlgorithmIsStandardPIV(t *testing.T) {
	if !AlgorithmRSA2048.IsStandardPIV() {
		t.Error("RSA-2048 should be standard PIV")
	}
	if !AlgorithmECCP256.IsStandardPIV() {
		t.Error("ECC P-256 should be standard PIV")
	}
	if !AlgorithmECCP384.IsStandardPIV() {
		t.Error("ECC P-384 should be standard PIV")
	}
	if AlgorithmEd25519.IsStandardPIV() {
		t.Error("Ed25519 is YubiKey 5.7+, not standard PIV")
	}
	if AlgorithmX25519.IsStandardPIV() {
		t.Error("X25519 is YubiKey 5.7+, not standard PIV")
	}
}

func TestParsePINPolicy(t *testing.T) {
	cases := []struct {
		in      string
		want    PINPolicy
		wantErr bool
	}{
		{"", PINPolicyDefaultPIV, false},
		{"default", PINPolicyDefaultPIV, false},
		{"DEFAULT", PINPolicyDefaultPIV, false},
		{"never", PINPolicyNeverPIV, false},
		{"once", PINPolicyOncePIV, false},
		{"always", PINPolicyAlwaysPIV, false},
		{"match", PINPolicyMatchPIV, false},
		{"sometimes", 0, true},
	}
	for _, c := range cases {
		got, err := ParsePINPolicy(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePINPolicy(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePINPolicy(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePINPolicy(%q) = %02x, want %02x", c.in, byte(got), byte(c.want))
		}
	}
}

func TestParseTouchPolicy(t *testing.T) {
	cases := []struct {
		in      string
		want    TouchPolicy
		wantErr bool
	}{
		{"", TouchPolicyDefaultPIV, false},
		{"default", TouchPolicyDefaultPIV, false},
		{"never", TouchPolicyNeverPIV, false},
		{"always", TouchPolicyAlwaysPIV, false},
		{"cached", TouchPolicyCachedPIV, false},
		{"sometimes", 0, true},
	}
	for _, c := range cases {
		got, err := ParseTouchPolicy(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTouchPolicy(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTouchPolicy(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseTouchPolicy(%q) = %02x, want %02x", c.in, byte(got), byte(c.want))
		}
	}
}

func TestPolicyIsStandardPIV(t *testing.T) {
	// PIN policy and touch policy are YubiKey extensions; SP 800-73-4
	// has no equivalent. All values must report non-standard.
	for _, p := range []PINPolicy{
		PINPolicyDefaultPIV, PINPolicyNeverPIV, PINPolicyOncePIV,
		PINPolicyAlwaysPIV, PINPolicyMatchPIV,
	} {
		if p.IsStandardPIV() {
			t.Errorf("PINPolicy %v should not be standard PIV", p)
		}
	}
	for _, t2 := range []TouchPolicy{
		TouchPolicyDefaultPIV, TouchPolicyNeverPIV,
		TouchPolicyAlwaysPIV, TouchPolicyCachedPIV,
	} {
		if t2.IsStandardPIV() {
			t.Errorf("TouchPolicy %v should not be standard PIV", t2)
		}
	}
}

func TestParseManagementKeyAlgorithm(t *testing.T) {
	cases := []struct {
		in      string
		want    ManagementKeyAlgorithm
		wantErr bool
	}{
		{"3des", ManagementKeyAlg3DES, false},
		{"tdes", ManagementKeyAlg3DES, false},
		{"3DES", ManagementKeyAlg3DES, false},
		{"aes128", ManagementKeyAlgAES128, false},
		{"aes-128", ManagementKeyAlgAES128, false},
		{"aes192", ManagementKeyAlgAES192, false},
		{"aes256", ManagementKeyAlgAES256, false},
		{"des", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := ParseManagementKeyAlgorithm(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseManagementKeyAlgorithm(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseManagementKeyAlgorithm(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseManagementKeyAlgorithm(%q) = %02x, want %02x", c.in, byte(got), byte(c.want))
		}
	}
}

func TestManagementKeyKeyLen(t *testing.T) {
	cases := []struct {
		alg  ManagementKeyAlgorithm
		want int
	}{
		{ManagementKeyAlg3DES, 24},
		{ManagementKeyAlgAES128, 16},
		{ManagementKeyAlgAES192, 24},
		{ManagementKeyAlgAES256, 32},
		{ManagementKeyAlgorithm(0xFF), 0},
	}
	for _, c := range cases {
		if got := c.alg.KeyLen(); got != c.want {
			t.Errorf("%s.KeyLen() = %d, want %d", c.alg, got, c.want)
		}
	}
}

func TestParseManagementKeyDefault(t *testing.T) {
	for _, alg := range []string{"3des", "aes192"} {
		mk, err := ParseManagementKey("default", alg)
		if err != nil {
			t.Errorf("ParseManagementKey(default, %s): %v", alg, err)
			continue
		}
		if !bytes.Equal(mk.Key, DefaultMgmtKey) {
			t.Errorf("ParseManagementKey(default, %s) returned %x, want default %x",
				alg, mk.Key, DefaultMgmtKey)
		}
	}
	// Default not allowed for AES-128 or AES-256.
	for _, alg := range []string{"aes128", "aes256"} {
		if _, err := ParseManagementKey("default", alg); err == nil {
			t.Errorf("ParseManagementKey(default, %s) succeeded; expected refusal", alg)
		}
	}
}

func TestParseManagementKeyHex(t *testing.T) {
	good := strings.Repeat("01", 24)
	mk, err := ParseManagementKey(good, "3des")
	if err != nil {
		t.Fatalf("ParseManagementKey: %v", err)
	}
	if len(mk.Key) != 24 {
		t.Errorf("key length = %d, want 24", len(mk.Key))
	}

	// Whitespace and colons stripped.
	pretty := "01:02:03 04:05:06 07:08 01:02:03:04:05:06:07:08 01:02:03:04:05:06:07:08"
	mk2, err := ParseManagementKey(pretty, "aes192")
	if err != nil {
		t.Fatalf("ParseManagementKey pretty: %v", err)
	}
	want := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(mk2.Key, want) {
		t.Errorf("pretty parse = %x, want %x", mk2.Key, want)
	}

	// Length mismatch.
	if _, err := ParseManagementKey(strings.Repeat("01", 16), "3des"); err == nil {
		t.Error("16-byte key parsed as 3DES; expected length mismatch")
	}

	// Bad hex.
	if _, err := ParseManagementKey("zz"+strings.Repeat("00", 23), "3des"); err == nil {
		t.Error("bad hex accepted")
	}
}

func TestObjectID(t *testing.T) {
	o, err := ParseObjectID("5fc105")
	if err != nil {
		t.Fatalf("ParseObjectID: %v", err)
	}
	if got := o.String(); got != "5fc105" {
		t.Errorf("String() = %q, want 5fc105", got)
	}
	if !o.Equal(ObjectID{0x5f, 0xc1, 0x05}) {
		t.Error("Equal mismatch")
	}
	if o.Equal(ObjectID{0x5f, 0xc1, 0x06}) {
		t.Error("Equal returned true for different IDs")
	}

	// 0x prefix accepted.
	o2, err := ParseObjectID("0x5FC105")
	if err != nil {
		t.Fatalf("ParseObjectID with prefix: %v", err)
	}
	if !o2.Equal(o) {
		t.Error("0x-prefixed parse does not match")
	}

	// Empty rejected.
	if _, err := ParseObjectID(""); err == nil {
		t.Error("empty object-id accepted")
	}
	// Bad hex rejected.
	if _, err := ParseObjectID("zz"); err == nil {
		t.Error("non-hex object-id accepted")
	}
}
