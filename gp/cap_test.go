package gp

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests build minimal synthetic CAP files inline using only the
// JC VM Spec layout. Component framing is the union of (tag byte,
// big-endian u2 size, payload). Header and Applet have parsed
// payloads; every other component carries an empty payload to
// keep fixtures tiny while still exercising the framing-only code
// paths.

// --- builders -----------------------------------------------------------

// frameForComponent returns (tag, size, payload) bytes for a
// component file. payload is the raw payload (without framing).
func frameForComponent(tag byte, payload []byte) []byte {
	out := make([]byte, 3+len(payload))
	out[0] = tag
	binary.BigEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[3:], payload)
	return out
}

type appletEntry struct {
	aid    []byte
	offset uint16
}

// buildHeaderPayload assembles the Header component payload per
// JC VM Spec §6.7. opts let individual tests perturb specific
// fields to exercise validation paths.
type headerOpts struct {
	pkgAID         []byte
	pkgName        []byte // nil = no package_name_info; non-nil (incl. empty) = present
	pkgMinor       byte
	pkgMajor       byte
	overrideMagic  *uint32  // non-nil = use this instead of capMagic
	overrideAIDLen *byte    // non-nil = put this in the AID_length field instead of len(pkgAID)
	trailing       []byte   // appended after package_name_info
}

func buildHeaderPayload(o headerOpts) []byte {
	var p []byte
	magic := capMagic
	if o.overrideMagic != nil {
		magic = *o.overrideMagic
	}
	p = binary.BigEndian.AppendUint32(p, magic)
	p = append(p, 0x02, 0x02) // CAP minor, major
	p = append(p, 0x00)       // flags
	p = append(p, o.pkgMinor, o.pkgMajor)

	aidLen := byte(len(o.pkgAID))
	if o.overrideAIDLen != nil {
		aidLen = *o.overrideAIDLen
	}
	p = append(p, aidLen)
	p = append(p, o.pkgAID...)

	if o.pkgName != nil {
		p = append(p, byte(len(o.pkgName)))
		p = append(p, o.pkgName...)
	}
	p = append(p, o.trailing...)
	return p
}

func buildAppletPayload(applets []appletEntry) []byte {
	p := []byte{byte(len(applets))}
	for _, a := range applets {
		p = append(p, byte(len(a.aid)))
		p = append(p, a.aid...)
		p = binary.BigEndian.AppendUint16(p, a.offset)
	}
	return p
}

// capBuilder collects components into a synthetic CAP ZIP. Tests
// configure which components to include and what bytes to put in
// each. The default set used by happy-path tests is established
// in defaultCAP().
type capBuilder struct {
	dir   string // directory inside the ZIP, defaults to "com/example/javacard"
	files map[string][]byte
}

func newCAPBuilder() *capBuilder {
	return &capBuilder{
		dir:   "com/example/javacard",
		files: make(map[string][]byte),
	}
}

func (b *capBuilder) put(basename string, raw []byte) *capBuilder {
	b.files[basename] = raw
	return b
}

func (b *capBuilder) bytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, raw := range b.files {
		w, err := zw.Create(b.dir + "/" + name)
		if err != nil {
			t.Fatalf("zip.Create %s: %v", name, err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// defaultCAP returns a builder pre-populated with valid framing
// for every component. Header and Applet carry caller-supplied
// payloads; the rest are empty (tag + size=0).
func defaultCAP(headerPayload, appletPayload []byte) *capBuilder {
	b := newCAPBuilder()
	b.put(componentNameHeader, frameForComponent(ComponentTagHeader, headerPayload))
	if appletPayload != nil {
		b.put(componentNameApplet, frameForComponent(ComponentTagApplet, appletPayload))
	}
	b.put(componentNameDirectory, frameForComponent(ComponentTagDirectory, nil))
	b.put(componentNameImport, frameForComponent(ComponentTagImport, nil))
	b.put(componentNameClass, frameForComponent(ComponentTagClass, nil))
	b.put(componentNameMethod, frameForComponent(ComponentTagMethod, nil))
	b.put(componentNameStaticField, frameForComponent(ComponentTagStaticField, nil))
	b.put(componentNameConstantPool, frameForComponent(ComponentTagConstantPool, nil))
	b.put(componentNameReferenceLocation, frameForComponent(ComponentTagReferenceLocation, nil))
	b.put(componentNameDescriptor, frameForComponent(ComponentTagDescriptor, nil))
	return b
}

// --- happy-path tests --------------------------------------------------

func TestParseCAP_OneApplet_WithPackageName(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}

	hp := buildHeaderPayload(headerOpts{
		pkgAID:   pkgAID,
		pkgName:  []byte("com.example"),
		pkgMinor: 0x01,
		pkgMajor: 0x02,
	})
	ap := buildAppletPayload([]appletEntry{{aid: appletAID, offset: 0x0042}})
	zipBytes := defaultCAP(hp, ap).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if got, want := cap.PackageAID.String(), "D27600012401"; got != want {
		t.Errorf("PackageAID = %s, want %s", got, want)
	}
	if got, want := cap.PackageVersionMajor, byte(0x02); got != want {
		t.Errorf("PackageVersionMajor = 0x%02X, want 0x%02X", got, want)
	}
	if got, want := cap.PackageVersionMinor, byte(0x01); got != want {
		t.Errorf("PackageVersionMinor = 0x%02X, want 0x%02X", got, want)
	}
	if got, want := string(cap.PackageName), "com.example"; got != want {
		t.Errorf("PackageName = %q, want %q", got, want)
	}
	if len(cap.Applets) != 1 {
		t.Fatalf("len(Applets) = %d, want 1", len(cap.Applets))
	}
	if got, want := cap.Applets[0].AID.String(), "D276000124010101"; got != want {
		t.Errorf("Applet[0].AID = %s, want %s", got, want)
	}
	if got, want := cap.Applets[0].InstallMethodOffset, uint16(0x0042); got != want {
		t.Errorf("Applet[0].InstallMethodOffset = 0x%04X, want 0x%04X", got, want)
	}
	if len(cap.Components) == 0 {
		t.Error("Components is empty; expected at least Header")
	}
}

func TestParseCAP_TwoApplets(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	a1 := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	a2 := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x02}

	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})
	ap := buildAppletPayload([]appletEntry{
		{aid: a1, offset: 0x0042},
		{aid: a2, offset: 0x0099},
	})
	zipBytes := defaultCAP(hp, ap).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if len(cap.Applets) != 2 {
		t.Fatalf("len(Applets) = %d, want 2", len(cap.Applets))
	}
	if cap.Applets[0].AID.String() != "D276000124010101" || cap.Applets[1].AID.String() != "D276000124010202" {
		t.Errorf("applet AIDs unexpected: [%s, %s]",
			cap.Applets[0].AID, cap.Applets[1].AID)
	}
	if cap.Applets[1].InstallMethodOffset != 0x0099 {
		t.Errorf("Applet[1].InstallMethodOffset = 0x%04X, want 0x0099",
			cap.Applets[1].InstallMethodOffset)
	}
}

func TestParseCAP_LibraryPackage_NoApplet(t *testing.T) {
	pkgAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})

	// No Applet.cap entry.
	zipBytes := defaultCAP(hp, nil).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if cap.Applets != nil {
		t.Errorf("Applets = %v, want nil for library package", cap.Applets)
	}
	if cap.PackageAID.String() != "A0000006472F0001" {
		t.Errorf("PackageAID = %s", cap.PackageAID)
	}
}

func TestParseCAP_NoPackageName(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	// pkgName: nil = omit package_name_info entirely (JC 2.1 style).
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: nil})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if cap.PackageName != nil {
		t.Errorf("PackageName = %q, want nil when package_name_info absent", cap.PackageName)
	}
}

func TestParseCAP_EmptyPackageName(t *testing.T) {
	// Distinct from the absent case: name_length=0 with no bytes.
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: []byte{}})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if cap.PackageName != nil {
		t.Errorf("PackageName = %q, want nil for name_length=0", cap.PackageName)
	}
}

func TestParseCAP_AppletCount_Zero(t *testing.T) {
	// Applet.cap with count=0 is unusual but spec-permitted.
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})
	ap := []byte{0x00} // count=0, nothing else
	zipBytes := defaultCAP(hp, ap).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	if len(cap.Applets) != 0 {
		t.Errorf("Applets = %v, want empty for count=0", cap.Applets)
	}
}

// --- error-path tests --------------------------------------------------

func TestParseCAP_MissingHeader(t *testing.T) {
	b := newCAPBuilder()
	b.put(componentNameApplet, frameForComponent(ComponentTagApplet, []byte{0x00})) // count=0
	zipBytes := b.bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for missing Header.cap")
	}
	if !strings.Contains(err.Error(), "Header.cap") {
		t.Errorf("error should mention Header.cap; got %v", err)
	}
}

func TestParseCAP_BadMagic(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	wrong := uint32(0xDEADBEEF)
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, overrideMagic: &wrong})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for bad Header magic")
	}
	if !strings.Contains(err.Error(), "magic") || !strings.Contains(err.Error(), "DEADBEEF") {
		t.Errorf("error should mention bad magic 0xDEADBEEF; got %v", err)
	}
}

func TestParseCAP_BadComponentSize(t *testing.T) {
	// Manually frame: declare 100 bytes of payload but include only 1.
	bad := []byte{ComponentTagHeader, 0x00, 0x64, 0x00}
	b := newCAPBuilder()
	b.put(componentNameHeader, bad)
	zipBytes := b.bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for size mismatch")
	}
	if !strings.Contains(err.Error(), "declared size") {
		t.Errorf("error should mention declared size; got %v", err)
	}
}

func TestParseCAP_TagMismatch(t *testing.T) {
	// Frame Header.cap with the Applet tag (0x03 instead of 0x01).
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})
	wrongTagged := frameForComponent(ComponentTagApplet, hp) // tag=3
	b := newCAPBuilder()
	b.put(componentNameHeader, wrongTagged)
	zipBytes := b.bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for tag mismatch")
	}
	if !strings.Contains(err.Error(), "tag") {
		t.Errorf("error should mention tag; got %v", err)
	}
}

func TestParseCAP_TruncatedAID_InHeader(t *testing.T) {
	// Declare AID_length=8 but supply only 5 bytes before package_name_info.
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24} // 5 bytes
	overLen := byte(8)
	hp := buildHeaderPayload(headerOpts{
		pkgAID:         pkgAID,
		overrideAIDLen: &overLen,
	})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for truncated AID")
	}
	if !strings.Contains(err.Error(), "truncated") && !strings.Contains(err.Error(), "AID") {
		t.Errorf("error should mention truncated AID; got %v", err)
	}
}

func TestParseCAP_AIDLengthOutOfRange(t *testing.T) {
	// 4-byte AID violates ISO/IEC 7816-5 (5..16). The integration
	// confirms ValidateAID from gp/aid.go is wired up correctly.
	pkgAID := []byte{0xA0, 0x00, 0x00, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for short AID")
	}
	if !strings.Contains(err.Error(), "aid length") {
		t.Errorf("error should mention AID length validation; got %v", err)
	}
}

func TestParseCAP_DuplicateComponent(t *testing.T) {
	// Same basename in two ZIP entries under different paths.
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, dir := range []string{"a/javacard", "b/javacard"} {
		w, err := zw.Create(dir + "/Header.cap")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(frameForComponent(ComponentTagHeader, hp)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := ParseCAP(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err == nil {
		t.Fatal("expected error for duplicate Header.cap")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate; got %v", err)
	}
}

func TestParseCAP_TrailingBytes_InHeader(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{
		pkgAID:   pkgAID,
		pkgName:  []byte("ok"),
		trailing: []byte{0xFF, 0xFF, 0xFF},
	})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for trailing Header bytes")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error should mention trailing bytes; got %v", err)
	}
}

func TestParseCAP_TrailingBytes_InApplet(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})

	ap := buildAppletPayload([]appletEntry{{aid: appletAID, offset: 0x0042}})
	ap = append(ap, 0xAA, 0xBB) // garbage tail
	zipBytes := defaultCAP(hp, ap).bytes(t)

	_, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err == nil {
		t.Fatal("expected error for trailing Applet bytes")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error should mention trailing bytes; got %v", err)
	}
}

// --- ParseCAPFile (file path) ---------------------------------------------

func TestParseCAPFile_HappyPath(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: []byte("x.y")})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.cap")
	if err := os.WriteFile(path, zipBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	cap, err := ParseCAPFile(path)
	if err != nil {
		t.Fatalf("ParseCAPFile: %v", err)
	}
	if cap.PackageAID.String() != "D27600012401" {
		t.Errorf("PackageAID = %s", cap.PackageAID)
	}
}

func TestParseCAPFile_RejectsOversized(t *testing.T) {
	// Write a file just over MaxCAPFileSize. Content doesn't need to
	// be a valid ZIP because the size check rejects before parsing.
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.cap")
	if err := os.WriteFile(path, make([]byte, MaxCAPFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ParseCAPFile(path)
	if err == nil {
		t.Fatal("expected size-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error should mention size limit; got %v", err)
	}
}

// --- component manifest -----------------------------------------------

func TestParseCAP_ComponentsInLoadOrder(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID})
	zipBytes := defaultCAP(hp, nil).bytes(t)

	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}

	// First component must be Header. Subsequent components follow
	// JC VM Spec load order whenever present.
	if len(cap.Components) == 0 || cap.Components[0].Name != componentNameHeader {
		t.Fatalf("first component should be Header.cap; got %v", cap.Components)
	}

	// Verify monotonic load-order positions of present components.
	order := loadOrder()
	posOf := map[string]int{}
	for i, n := range order {
		posOf[n] = i
	}
	for i := 1; i < len(cap.Components); i++ {
		if posOf[cap.Components[i].Name] <= posOf[cap.Components[i-1].Name] {
			t.Errorf("Components not in load order: %s came after %s",
				cap.Components[i].Name, cap.Components[i-1].Name)
		}
	}
}
