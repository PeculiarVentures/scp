package gp

import (
	"bytes"
	"testing"
)

func TestParseAIDHex(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		want      string // hex of expected bytes; empty if expecting error
		wantError string
	}{
		{
			name:  "no separators",
			input: "A0000001510000",
			want:  "A0000001510000",
		},
		{
			name:  "lowercase no separators",
			input: "a0000001510000",
			want:  "A0000001510000",
		},
		{
			name:  "colon separators",
			input: "A0:00:00:01:51:00:00:00",
			want:  "A000000151000000",
		},
		{
			name:  "space separators",
			input: "A0 00 00 01 51 00 00 00",
			want:  "A000000151000000",
		},
		{
			name:  "hyphen separators",
			input: "A0-00-00-01-51-00-00-00",
			want:  "A000000151000000",
		},
		{
			name:  "underscore separators",
			input: "A0_00_00_01_51_00_00_00",
			want:  "A000000151000000",
		},
		{
			name:  "mixed separators",
			input: "A0:00 00-01_51:00 00 00",
			want:  "A000000151000000",
		},
		{
			name:  "minimum length 5 bytes",
			input: "A000000151",
			want:  "A000000151",
		},
		{
			name:  "maximum length 16 bytes",
			input: "A000000151000000010203040506070A",
			want:  "A000000151000000010203040506070A",
		},
		{
			name:      "empty string",
			input:     "",
			wantError: "empty",
		},
		{
			name:      "odd hex length",
			input:     "A00000015",
			wantError: "odd length",
		},
		{
			name:      "non-hex characters",
			input:     "A0000001ZZ",
			wantError: "decode aid hex",
		},
		{
			name:      "too short, 4 bytes",
			input:     "A0000001",
			wantError: "aid length 4 invalid",
		},
		{
			name:      "too long, 17 bytes",
			input:     "A000000151000000010203040506070A0B",
			wantError: "aid length 17 invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAIDHex(tc.input)
			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil; result=%X", tc.wantError, got)
				}
				if !contains(err.Error(), tc.wantError) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("ParseAIDHex(%q) = %s, want %s", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateAID(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"empty", []byte{}, true},
		{"length 1", []byte{0xA0}, true},
		{"length 4", []byte{0xA0, 0x00, 0x00, 0x01}, true},
		{"length 5 (min)", []byte{0xA0, 0x00, 0x00, 0x01, 0x51}, false},
		{"length 8", []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, false},
		{"length 16 (max)", make([]byte, 16), false},
		{"length 17", make([]byte, 17), true},
		{"length 32", make([]byte, 32), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAID(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateAID(%X) = nil, want error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateAID(%X) = %v, want nil", tc.input, err)
			}
		})
	}
}

func TestAID_LV(t *testing.T) {
	cases := []struct {
		name string
		aid  AID
		want []byte
	}{
		{
			name: "5-byte AID",
			aid:  AID{0xA0, 0x00, 0x00, 0x01, 0x51},
			want: []byte{0x05, 0xA0, 0x00, 0x00, 0x01, 0x51},
		},
		{
			name: "8-byte ISD AID",
			aid:  AID{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			want: []byte{0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
		},
		{
			name: "16-byte AID (max)",
			aid:  AID(bytes.Repeat([]byte{0xCC}, 16)),
			want: append([]byte{0x10}, bytes.Repeat([]byte{0xCC}, 16)...),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.aid.LV()
			if err != nil {
				t.Fatalf("LV() error = %v, want nil", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("LV() = %X, want %X", got, tc.want)
			}
		})
	}
}

// TestAID_LV_RejectsInvalid pins the fail-closed contract: empty
// or out-of-range AIDs cause LV to return an error rather than a
// silently-malformed encoding. A caller doing
//
//	apdu.Data = append(apdu.Data, sd.LV()...)
//
// against an empty sd would otherwise produce a wire byte sequence
// missing both the length and the AID, which would be diagnosed
// only as "card returned weird SW" downstream.
func TestAID_LV_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		aid  AID
	}{
		{"empty (nil slice)", nil},
		{"empty (zero-length non-nil)", AID{}},
		{"too short (4 bytes)", AID{0xA0, 0x00, 0x00, 0x01}},
		{"too long (17 bytes)", AID(bytes.Repeat([]byte{0xCC}, 17))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.aid.LV()
			if err == nil {
				t.Fatalf("LV() = %X, want error", out)
			}
			if out != nil {
				t.Errorf("LV() returned %X on error path, want nil", out)
			}
		})
	}
}

// TestEmptyAIDLV pins the "no AID match criterion" wire encoding.
// Distinct from AID.LV() returning an error on an empty AID: the
// empty-LV form here is a meaningful wire value used by GP as
// "match every entry in the scope," whereas LV()'s error path
// catches programming errors where the caller meant to pass a
// real AID and didn't.
func TestEmptyAIDLV(t *testing.T) {
	got := EmptyAIDLV()
	want := []byte{0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("EmptyAIDLV() = %X, want %X", got, want)
	}
	// Each call returns an independent slice so a caller mutating
	// the returned slice cannot poison subsequent callers.
	got[0] = 0xFF
	if EmptyAIDLV()[0] != 0x00 {
		t.Error("EmptyAIDLV() callers share backing storage; later mutation visible")
	}
}

func TestAID_Bytes_IsCopy(t *testing.T) {
	aid := AID{0xA0, 0x00, 0x00, 0x01, 0x51}
	got := aid.Bytes()
	if !bytes.Equal(got, []byte(aid)) {
		t.Fatalf("Bytes() returned different content: %X vs %X", got, []byte(aid))
	}

	// Mutating the returned slice must not affect the original AID.
	got[0] = 0x00
	if aid[0] != 0xA0 {
		t.Errorf("mutation of Bytes() result corrupted AID: aid[0]=%02X, want A0", aid[0])
	}
}

func TestAID_String(t *testing.T) {
	cases := []struct {
		aid  AID
		want string
	}{
		{AID{0xA0, 0x00, 0x00, 0x01, 0x51}, "A000000151"},
		{AID{0xab, 0xcd, 0xef, 0x01, 0x23}, "ABCDEF0123"},
		{AID{}, ""},
	}
	for _, tc := range cases {
		if got := tc.aid.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func TestAID_Equal(t *testing.T) {
	a := AID{0xA0, 0x00, 0x00, 0x01, 0x51}
	b := AID{0xA0, 0x00, 0x00, 0x01, 0x51}
	c := AID{0xA0, 0x00, 0x00, 0x01, 0x52}
	d := AID{0xA0, 0x00, 0x00, 0x01}

	if !a.Equal(b) {
		t.Error("identical AIDs should be Equal")
	}
	if a.Equal(c) {
		t.Error("AIDs differing in last byte should not be Equal")
	}
	if a.Equal(d) {
		t.Error("AIDs of different lengths should not be Equal")
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) > 0 && bytes.Contains([]byte(s), []byte(substr)))
}
