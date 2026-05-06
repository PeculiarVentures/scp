package gp

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// importHexLookup builds an AID from hex at test time. Wrapped
// here rather than littering tests with encoding/hex calls.
// Panics on a malformed literal — programmer error caught at
// the first build, not a runtime path.
func importHexLookup(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("test: invalid hex: " + err.Error())
	}
	return b
}

// buildImportPayload encodes an Import.cap payload per JC VM
// Spec §6.5 for test fixtures: count u1, then count records of
// (minor u1, major u1, AID_length u1, AID).
func buildImportPayload(entries ...importEntry) []byte {
	var b []byte
	b = append(b, byte(len(entries)))
	for _, e := range entries {
		b = append(b, e.minor, e.major, byte(len(e.aid)))
		b = append(b, e.aid...)
	}
	return b
}

type importEntry struct {
	minor, major byte
	aid          []byte
}

// TestDecodeImport_HappyPath: count=2 with javacard.framework
// 1.4 + javacardx.crypto 1.0; both AIDs resolve to standard
// names; JavaCardVersion returns "JC 2.2.2".
func TestDecodeImport_HappyPath(t *testing.T) {
	frameworkAID := importHexLookup("A0000000620101")
	cryptoAID := importHexLookup("A000000062020101")

	payload := buildImportPayload(
		importEntry{minor: 4, major: 1, aid: frameworkAID},
		importEntry{minor: 0, major: 1, aid: cryptoAID},
	)
	out := &CAPFile{}
	if err := decodeImportPayload(payload, out); err != nil {
		t.Fatalf("decodeImportPayload: %v", err)
	}
	if len(out.Imports) != 2 {
		t.Fatalf("Imports = %d, want 2", len(out.Imports))
	}

	got := out.Imports[0]
	if !bytes.Equal(got.AID, frameworkAID) {
		t.Errorf("Imports[0].AID = %X, want %X", got.AID, frameworkAID)
	}
	if got.MajorVersion != 1 || got.MinorVersion != 4 {
		t.Errorf("Imports[0] version = %d.%d, want 1.4", got.MajorVersion, got.MinorVersion)
	}
	if got.Name != "javacard.framework" {
		t.Errorf("Imports[0].Name = %q, want javacard.framework", got.Name)
	}

	got = out.Imports[1]
	if got.Name != "javacardx.crypto" {
		t.Errorf("Imports[1].Name = %q, want javacardx.crypto", got.Name)
	}

	if jc := out.JavaCardVersion(); jc != "JC 2.2.2" {
		t.Errorf("JavaCardVersion = %q, want JC 2.2.2", jc)
	}
}

// TestDecodeImport_LibraryCAP_Empty: empty payload is treated
// as count=0 (some toolchains emit empty Import for libraries
// that depend on nothing observable). Imports stays nil and
// JavaCardVersion returns empty.
func TestDecodeImport_LibraryCAP_Empty(t *testing.T) {
	out := &CAPFile{}
	if err := decodeImportPayload(nil, out); err != nil {
		t.Fatalf("decodeImportPayload(nil): %v", err)
	}
	if out.Imports != nil {
		t.Errorf("Imports = %v, want nil for empty payload", out.Imports)
	}
	if jc := out.JavaCardVersion(); jc != "" {
		t.Errorf("JavaCardVersion = %q, want empty (no framework imported)", jc)
	}
}

// TestDecodeImport_CountZero: a single byte 0x00 is the
// count=0 conformant form. Same outcome as empty payload.
func TestDecodeImport_CountZero(t *testing.T) {
	out := &CAPFile{}
	if err := decodeImportPayload([]byte{0x00}, out); err != nil {
		t.Fatalf("decodeImportPayload([0]): %v", err)
	}
	if len(out.Imports) != 0 {
		t.Errorf("Imports = %v, want empty", out.Imports)
	}
}

// TestDecodeImport_TruncatedRecord: count claims 1 but payload
// runs out before the AID is complete. Decoder returns a clear
// error; CAPFile is not corrupted with a partial entry.
func TestDecodeImport_TruncatedRecord(t *testing.T) {
	// count=1, minor=0, major=1, aidLen=8, then only 4 AID bytes.
	payload := []byte{0x01, 0x00, 0x01, 0x08, 0xA0, 0x00, 0x00, 0x00}
	out := &CAPFile{}
	err := decodeImportPayload(payload, out)
	if err == nil {
		t.Fatal("expected truncation error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error should mention truncation: %v", err)
	}
	if out.Imports != nil {
		t.Errorf("Imports should not be populated on error: %v", out.Imports)
	}
}

// TestDecodeImport_TrailingBytes: well-formed records but
// stray bytes after them. Strict per spec.
func TestDecodeImport_TrailingBytes(t *testing.T) {
	frameworkAID := importHexLookup("A0000000620101")
	payload := buildImportPayload(importEntry{minor: 4, major: 1, aid: frameworkAID})
	payload = append(payload, 0xFF, 0xFF) // garbage

	out := &CAPFile{}
	err := decodeImportPayload(payload, out)
	if err == nil {
		t.Fatal("expected trailing-bytes error")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error should mention trailing bytes: %v", err)
	}
}

// TestDecodeImport_MissingAIDLength: count=1 with no record
// bytes at all (truncation before minor/major/aidLen prefix).
func TestDecodeImport_MissingAIDLength(t *testing.T) {
	payload := []byte{0x01} // count=1, no record
	out := &CAPFile{}
	err := decodeImportPayload(payload, out)
	if err == nil {
		t.Fatal("expected truncation error on missing record prefix")
	}
}

// TestJavaCardVersion_Mapping: every documented framework
// version maps to the expected JC label.
func TestJavaCardVersion_Mapping(t *testing.T) {
	frameworkAID := importHexLookup("A0000000620101")
	cases := []struct {
		major, minor byte
		want         string
	}{
		{1, 0, "JC 2.1"},
		{1, 1, "JC 2.1.1"},
		{1, 2, "JC 2.2.0"},
		{1, 3, "JC 2.2.1"},
		{1, 4, "JC 2.2.2"},
		{1, 5, "JC 3.0.1"},
		{1, 6, "JC 3.0.4"},
		{1, 7, "JC 3.0.5 / 3.1"},
		{1, 8, "JC 3.1"},
	}
	for _, c := range cases {
		out := &CAPFile{
			Imports: []CAPImport{{
				AID:          frameworkAID,
				MajorVersion: c.major,
				MinorVersion: c.minor,
				Name:         "javacard.framework",
			}},
		}
		if got := out.JavaCardVersion(); got != c.want {
			t.Errorf("framework %d.%d: JavaCardVersion = %q, want %q",
				c.major, c.minor, got, c.want)
		}
	}
}

// TestJavaCardVersion_UnknownMapping: an out-of-range version
// returns a string mentioning the framework version + flagging
// the unknown mapping. Useful for inspecting CAPs built against
// JC versions newer than this code knows about.
func TestJavaCardVersion_UnknownMapping(t *testing.T) {
	frameworkAID := importHexLookup("A0000000620101")
	out := &CAPFile{
		Imports: []CAPImport{{
			AID:          frameworkAID,
			MajorVersion: 2,
			MinorVersion: 0,
			Name:         "javacard.framework",
		}},
	}
	got := out.JavaCardVersion()
	if !strings.Contains(got, "javacard.framework 2.0") {
		t.Errorf("unknown mapping should mention version: %q", got)
	}
	if !strings.Contains(got, "unknown") {
		t.Errorf("unknown mapping should say 'unknown': %q", got)
	}
}

// TestJavaCardVersion_NoFrameworkImport: Imports does not
// contain javacard.framework -> empty string.
func TestJavaCardVersion_NoFrameworkImport(t *testing.T) {
	javaLangAID := importHexLookup("A0000000620001")
	out := &CAPFile{
		Imports: []CAPImport{{
			AID:          javaLangAID,
			MajorVersion: 1,
			MinorVersion: 0,
			Name:         "java.lang",
		}},
	}
	if got := out.JavaCardVersion(); got != "" {
		t.Errorf("no framework -> JavaCardVersion = %q, want empty", got)
	}
}

// TestDecodeImport_UnknownAID_NameEmpty: an AID not in the
// standard table or registry resolves to empty Name; the AID
// bytes are still preserved.
func TestDecodeImport_UnknownAID_NameEmpty(t *testing.T) {
	customAID := []byte{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6}
	payload := buildImportPayload(importEntry{minor: 1, major: 1, aid: customAID})

	out := &CAPFile{}
	if err := decodeImportPayload(payload, out); err != nil {
		t.Fatalf("decodeImportPayload: %v", err)
	}
	if len(out.Imports) != 1 {
		t.Fatalf("Imports = %d, want 1", len(out.Imports))
	}
	if !bytes.Equal(out.Imports[0].AID, customAID) {
		t.Errorf("AID lost: %X vs %X", out.Imports[0].AID, customAID)
	}
	if out.Imports[0].Name != "" {
		t.Errorf("custom AID should not resolve to a name: %q", out.Imports[0].Name)
	}
}
