package gp

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// This file implements a Java Card CAP (Converted Applet) file
// parser. The CAP file format is documented in the Java Card
// Virtual Machine Specification §6, "The Structure of a CAP File".
// AID structural rules come from ISO/IEC 7816-5.
//
// Scope. The MVP parser extracts the metadata needed by the
// gp cap inspect operator command:
//
//   - Package AID and package version from the Header component.
//   - Optional package name from Header (Java Card 2.2+).
//   - Applet AID list from the Applet component (when present;
//     library packages omit it).
//   - Component inventory: name, tag byte, and total byte length.
//
// What this parser does NOT do (intentionally, deferred to
// Appendix B work):
//
//   - Concatenate components into a LOAD-ready byte stream. That
//     belongs with the INSTALL/LOAD command builders that consume
//     it; building the helper here without an executable consumer
//     is dead code. CAPComponent.Raw is exposed so future builders
//     can compose it themselves.
//   - Parse Method, Class, ConstantPool, Descriptor, or any other
//     component beyond Header and Applet. Those are required for
//     bytecode verification or full applet inspection but are not
//     needed to describe a CAP on disk for an operator.
//   - Validate cross-component references (constant pool offsets
//     into Class, install_method_offset into Method, etc.). A
//     malformed CAP that would fail card-side validation can still
//     parse here as long as Header and Applet are well-formed.
//
// References:
//   - Java Card VM Specification §6 (CAP file format).
//   - ISO/IEC 7816-5 (AID structure: 5..16 bytes).

const (
	// capMagic is the four-byte magic at the start of every Header
	// component payload, per JC VM Spec §6.7.
	capMagic uint32 = 0xDECAFFED

	// MaxCAPFileSize is the upper bound on file size accepted by
	// ParseCAPFile. Real-world CAP files are kilobytes, occasionally
	// hundreds of kilobytes for large applets. 4 MiB is an order of
	// magnitude beyond anything observed; rejecting larger inputs
	// guards against a path-supplied DoS.
	MaxCAPFileSize int64 = 4 << 20
)

// Component tag values from JC VM Spec Table 6-1. Exposed because
// they identify which structural piece of the CAP a component is,
// and a CAP file with a tag/name mismatch (Header.cap whose first
// byte is tag 7 = Method) is a producer bug worth surfacing.
const (
	ComponentTagHeader            byte = 1
	ComponentTagDirectory         byte = 2
	ComponentTagApplet            byte = 3
	ComponentTagImport            byte = 4
	ComponentTagConstantPool      byte = 5
	ComponentTagClass             byte = 6
	ComponentTagMethod            byte = 7
	ComponentTagStaticField       byte = 8
	ComponentTagReferenceLocation byte = 9
	ComponentTagExport            byte = 10
	ComponentTagDescriptor        byte = 11
	ComponentTagDebug             byte = 12
)

// Standard component file basenames inside a CAP ZIP. The
// containing directory path varies by producer (ant-javacard,
// the Oracle converter, IDE plugins) so the parser indexes by
// basename only.
const (
	componentNameHeader            = "Header.cap"
	componentNameDirectory         = "Directory.cap"
	componentNameApplet            = "Applet.cap"
	componentNameImport            = "Import.cap"
	componentNameConstantPool      = "ConstantPool.cap"
	componentNameClass             = "Class.cap"
	componentNameMethod            = "Method.cap"
	componentNameStaticField       = "StaticField.cap"
	componentNameReferenceLocation = "RefLocation.cap"
	componentNameExport            = "Export.cap"
	componentNameDescriptor        = "Descriptor.cap"
	componentNameDebug             = "Debug.cap"
)

// expectedTagFor returns the JC VM Spec tag value that must appear
// at offset 0 of the named component file's payload. Components
// with no entry in this table (an unrecognized basename) bypass the
// tag check; the parser only validates known names.
func expectedTagFor(name string) (byte, bool) {
	switch name {
	case componentNameHeader:
		return ComponentTagHeader, true
	case componentNameDirectory:
		return ComponentTagDirectory, true
	case componentNameApplet:
		return ComponentTagApplet, true
	case componentNameImport:
		return ComponentTagImport, true
	case componentNameConstantPool:
		return ComponentTagConstantPool, true
	case componentNameClass:
		return ComponentTagClass, true
	case componentNameMethod:
		return ComponentTagMethod, true
	case componentNameStaticField:
		return ComponentTagStaticField, true
	case componentNameReferenceLocation:
		return ComponentTagReferenceLocation, true
	case componentNameExport:
		return ComponentTagExport, true
	case componentNameDescriptor:
		return ComponentTagDescriptor, true
	case componentNameDebug:
		return ComponentTagDebug, true
	}
	return 0, false
}

// CAPFile is a parsed Java Card CAP file at the MVP scope: package
// metadata, applet inventory, and a component manifest. Per
// JC VM Spec, the CAP "describes a Java Card package" — exactly
// one package per CAP, possibly containing zero or more applets.
type CAPFile struct {
	// CAPVersion is the format version from Header (minor.major).
	// Stored as separate bytes rather than a struct because the
	// JC VM Spec presents them that way and downstream code may
	// want either piece independently.
	CAPVersionMajor byte
	CAPVersionMinor byte

	// PackageVersion is the developer-supplied package version,
	// also from Header. Distinct from CAPVersion: a CAP built with
	// a 3.0.5 toolchain may carry a developer-versioned package.
	PackageVersionMajor byte
	PackageVersionMinor byte

	// PackageAID is the Java package's AID, validated against the
	// ISO/IEC 7816-5 5..16-byte length range during parsing.
	PackageAID AID

	// PackageName is the Java fully-qualified package name. Sourced
	// from Header.cap's package_name_info when present (JC 2.2+);
	// otherwise derived from the CAP's ZIP directory layout when
	// possible (Oracle converter and most tooling place components
	// under <package-path>/javacard/, e.g. com/example/javacard/).
	// Nil only when neither source produces a name. PackageNameSource
	// reports which source was used.
	PackageName []byte

	// PackageNameSource records how PackageName was determined.
	// One of "header_component", "zip_path", or "absent".
	// Useful for inspector output when the operator wants to
	// distinguish a CAP that explicitly declares its package name
	// from one whose name was inferred from directory layout (the
	// inferred name can be wrong if a producer reorganized the ZIP
	// after the converter ran).
	PackageNameSource string

	// Applets lists the applets declared in Applet.cap, in file
	// order. Library packages have no Applet.cap and Applets is
	// nil; that is not an error.
	Applets []CAPApplet

	// Components is the inventory of component files found in the
	// CAP, in JC VM Spec load order. The parser populates this
	// from whichever recognized components the ZIP contains; an
	// absent component is silently skipped because library CAPs
	// omit Applet, debug-stripped CAPs omit Debug, etc.
	Components []CAPComponent
}

// CAPApplet describes one applet entry from the Applet component.
type CAPApplet struct {
	// AID is the applet's instance-class identifier as it appears
	// in Applet.cap. Validated for length per ISO/IEC 7816-5.
	AID AID

	// InstallMethodOffset is the u2 offset into the Method
	// component identifying the applet's install() entry point.
	// Stored for completeness; not used by gp cap inspect.
	InstallMethodOffset uint16
}

// CAPComponent is one component file's framing and bytes.
type CAPComponent struct {
	// Name is the component file basename, e.g. "Header.cap".
	Name string

	// Tag is the first byte of the component payload, expected
	// to match the value in JC VM Spec Table 6-1 for the named
	// component. Mismatches are caught during parsing.
	Tag byte

	// DeclaredSize is the u2 size field at offset 1..2 of the
	// component file. The parser cross-checks this against the
	// actual byte count and rejects mismatches.
	DeclaredSize uint16

	// Raw is the complete component file content: tag (1 byte) +
	// size (2 bytes) + payload (DeclaredSize bytes). Total length
	// is therefore 3 + DeclaredSize. The MVP inspector reads
	// len(Raw) for the size column and never concatenates.
	//
	// Future LOAD command builders (Appendix B) must NOT blindly
	// concatenate Raw across every component in CAPFile.Components.
	// Convention across Java Card converters and tooling excludes
	// the Debug component (source line numbers, method names) and
	// the Descriptor component (reflection metadata) from the on-
	// card load image: neither is needed for execution, both waste
	// EEPROM, and some card runtimes reject the load when they're
	// included. The future LoadImage helper should accept an
	// inclusion policy (default: exclude Debug and Descriptor)
	// rather than treat Components as a flat byte stream.
	Raw []byte
}

// ParseCAPFile opens a CAP file from disk, enforces an upper size
// bound, and parses it. The size bound only applies here, not in
// ParseCAP, because callers passing an io.ReaderAt explicitly
// know the size already.
func ParseCAPFile(filename string) (*CAPFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("gp/cap: open %s: %w", filename, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("gp/cap: stat %s: %w", filename, err)
	}
	if st.Size() > MaxCAPFileSize {
		return nil, fmt.Errorf("gp/cap: %s is %d bytes, exceeds max %d",
			filename, st.Size(), MaxCAPFileSize)
	}
	return ParseCAP(f, st.Size())
}

// ParseCAP parses a CAP file from any io.ReaderAt of the given
// total byte length. Used directly by tests with bytes.Reader and
// by ParseCAPFile under the hood.
//
// The flow is:
//
//  1. Open as a ZIP.
//  2. Index ZIP entries by component basename, rejecting duplicates
//     (which would indicate either a malformed CAP or an ambiguous
//     multi-package CAP that this parser does not support).
//  3. Parse Header (mandatory).
//  4. Parse Applet (optional).
//  5. Frame-parse every other recognized component for the
//     Components manifest.
//
// Component byte order in the resulting Components slice follows
// JC VM Spec load order (Header, Directory, Import, Applet,
// Class, ...). Producers can place ZIP entries in any order; the
// parser normalizes.
func ParseCAP(r io.ReaderAt, size int64) (*CAPFile, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("gp/cap: open zip: %w", err)
	}

	entries, dirs, err := indexComponents(zr)
	if err != nil {
		return nil, err
	}

	headerRaw, ok := entries[componentNameHeader]
	if !ok {
		return nil, fmt.Errorf("gp/cap: missing required %s", componentNameHeader)
	}

	out := &CAPFile{}

	headerComp, err := frameComponent(componentNameHeader, headerRaw)
	if err != nil {
		return nil, err
	}
	if err := decodeHeaderPayload(payloadOf(headerComp), out); err != nil {
		return nil, err
	}

	// Set PackageNameSource based on what decodeHeaderPayload did.
	// decodeHeaderPayload only assigns out.PackageName when the
	// Header component carried a non-empty package_name_info. If
	// it stayed nil, fall back to ZIP directory derivation. If
	// derivation also fails, mark as absent.
	if out.PackageName != nil {
		out.PackageNameSource = "header_component"
	} else if derived, ok := derivePackageNameFromZipDirs(dirs); ok {
		out.PackageName = []byte(derived)
		out.PackageNameSource = "zip_path"
	} else {
		out.PackageNameSource = "absent"
	}

	if appletRaw, ok := entries[componentNameApplet]; ok {
		appletComp, err := frameComponent(componentNameApplet, appletRaw)
		if err != nil {
			return nil, err
		}
		if err := decodeAppletPayload(payloadOf(appletComp), out); err != nil {
			return nil, err
		}
	}

	for _, name := range loadOrder() {
		raw, present := entries[name]
		if !present {
			continue
		}
		comp, err := frameComponent(name, raw)
		if err != nil {
			return nil, err
		}
		out.Components = append(out.Components, comp)
	}

	return out, nil
}

// indexComponents walks the ZIP and returns recognized component
// files indexed by basename, plus a parallel map from basename to
// the directory the component lived under inside the ZIP. The
// directory map is used downstream to derive a package name when
// Header.cap's package_name_info is absent. Duplicate basenames
// (the same component appearing under two paths inside the ZIP)
// are rejected because the right behavior is ambiguous: pick
// first? pick last? merge? An error here surfaces a producer bug
// rather than picking one and proceeding silently.
//
// Files inside the ZIP that do not end in .cap or do not match a
// recognized component name are ignored. Many real CAPs contain
// Manifest.mf, .DS_Store, and Java debug auxiliary files; these
// are not parser concerns.
func indexComponents(zr *zip.Reader) (map[string][]byte, map[string]string, error) {
	out := make(map[string][]byte)
	dirs := make(map[string]string)

	for _, f := range zr.File {
		base := path.Base(f.Name)
		if !strings.HasSuffix(base, ".cap") {
			continue
		}
		if _, known := expectedTagFor(base); !known {
			// Unknown .cap basename inside the ZIP; ignore rather
			// than reject. Producers occasionally include vendor
			// extensions that this parser does not need to handle.
			continue
		}
		if _, exists := out[base]; exists {
			return nil, nil, fmt.Errorf("gp/cap: duplicate component %q (multi-package CAPs unsupported)", base)
		}

		rc, err := f.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("gp/cap: open %s in zip: %w", base, err)
		}
		buf, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("gp/cap: read %s: %w", base, err)
		}
		if len(buf) == 0 {
			return nil, nil, fmt.Errorf("gp/cap: %s is empty", base)
		}
		out[base] = buf
		dirs[base] = path.Dir(f.Name)
	}

	return out, dirs, nil
}

// derivePackageNameFromZipDirs infers a Java package name from the
// directory path inside the CAP's ZIP. Standard converters (Oracle
// JC converter, ant-javacard, IDE plugins) place components under
// <package-path>/javacard/, e.g. com/example/foo/javacard/Header.cap
// for package com.example.foo. Some minimal builds drop the
// trailing /javacard/ segment, putting components directly under
// the package directory.
//
// The function returns the derived name (with slashes converted to
// dots) and a bool indicating success. It only returns success
// when every recognized component lives under the same directory:
// mixed directories indicate a malformed or multi-package CAP and
// should not be flattened into a single package name. Empty
// directories or root-only ("." after path.Dir) yield no
// derivation.
//
// This is a tooling-convention layer: the JC VM Spec does not
// mandate where converters place components inside the JAR. The
// derivation matches the convention used by the major converters
// but cannot be relied upon for arbitrary producer output.
func derivePackageNameFromZipDirs(dirs map[string]string) (string, bool) {
	if len(dirs) == 0 {
		return "", false
	}
	var common string
	first := true
	for _, d := range dirs {
		if first {
			common = d
			first = false
			continue
		}
		if d != common {
			return "", false
		}
	}
	if common == "" || common == "." {
		return "", false
	}

	// Strip trailing "/javacard" if present (Oracle converter
	// convention). Case-sensitive match: lowercase "javacard" is
	// what the converter produces; preserving case-sensitivity
	// avoids false positives on packages legitimately named
	// "Javacard" or "JAVACARD" at the leaf.
	if strings.HasSuffix(common, "/javacard") {
		common = strings.TrimSuffix(common, "/javacard")
	} else if common == "javacard" {
		// Components under /javacard/ at the ZIP root with no
		// preceding package path; nothing meaningful to derive.
		return "", false
	}

	if common == "" {
		return "", false
	}
	return strings.ReplaceAll(common, "/", "."), true
}

// loadOrder returns component basenames in JC VM Spec load order.
// This is the order in which a card-side LOAD sequence would
// typically receive components; the MVP parser uses it to
// normalize the Components slice for predictable inspector output.
func loadOrder() []string {
	return []string{
		componentNameHeader,
		componentNameDirectory,
		componentNameImport,
		componentNameApplet,
		componentNameClass,
		componentNameMethod,
		componentNameStaticField,
		componentNameExport,
		componentNameConstantPool,
		componentNameReferenceLocation,
		componentNameDescriptor,
		componentNameDebug,
	}
}

// frameComponent validates the (tag, size, payload) outer framing
// of a component file: the 3-byte header is present, the declared
// size matches the actual payload length, and the tag matches what
// JC VM Spec Table 6-1 requires for this name.
func frameComponent(name string, raw []byte) (CAPComponent, error) {
	if len(raw) < 3 {
		return CAPComponent{}, fmt.Errorf("gp/cap: %s shorter than 3-byte header (%d bytes)", name, len(raw))
	}
	tag := raw[0]
	declared := binary.BigEndian.Uint16(raw[1:3])
	actualPayload := len(raw) - 3
	if int(declared) != actualPayload {
		return CAPComponent{}, fmt.Errorf("gp/cap: %s declared size %d does not match actual payload %d",
			name, declared, actualPayload)
	}
	if want, ok := expectedTagFor(name); ok && tag != want {
		return CAPComponent{}, fmt.Errorf("gp/cap: %s has tag 0x%02X, want 0x%02X", name, tag, want)
	}

	// Defensive copy. Callers downstream may keep the slice for the
	// lifetime of the CAPFile; sharing the ZIP reader's buffer would
	// be a footgun if archive/zip ever reuses it.
	cp := make([]byte, len(raw))
	copy(cp, raw)

	return CAPComponent{
		Name:         name,
		Tag:          tag,
		DeclaredSize: declared,
		Raw:          cp,
	}, nil
}

// payloadOf returns the bytes after the 3-byte (tag, size) framing.
// Callers that need the framing back can read CAPComponent.Raw.
func payloadOf(c CAPComponent) []byte {
	return c.Raw[3:]
}

// decodeHeaderPayload parses the Header component payload per
// JC VM Spec §6.7. Layout:
//
//	u4 magic                         (== 0xDECAFFED)
//	u1 minor_version  (CAP format)
//	u1 major_version  (CAP format)
//	u1 flags
//	package_info {
//	    u1 minor_version
//	    u1 major_version
//	    u1 AID_length
//	    u1 AID[AID_length]
//	}
//	package_name_info {                 // optional, JC 2.2+
//	    u1 name_length
//	    u1 name[name_length]
//	}
//
// Trailing bytes after package_name_info are an error: the spec
// does not allow them and a producer that emits them is misframed.
func decodeHeaderPayload(payload []byte, out *CAPFile) error {
	const fixedPrefix = 4 + 1 + 1 + 1 + 1 + 1 + 1 // magic + capVer + flags + pkgVer + AID_length
	if len(payload) < fixedPrefix {
		return fmt.Errorf("gp/cap: Header payload too short for fixed prefix (%d bytes, need >= %d)",
			len(payload), fixedPrefix)
	}

	if magic := binary.BigEndian.Uint32(payload[0:4]); magic != capMagic {
		return fmt.Errorf("gp/cap: Header magic 0x%08X, want 0x%08X", magic, capMagic)
	}

	out.CAPVersionMinor = payload[4]
	out.CAPVersionMajor = payload[5]
	// payload[6] is flags; not currently surfaced.
	out.PackageVersionMinor = payload[7]
	out.PackageVersionMajor = payload[8]

	aidLen := int(payload[9])
	cursor := 10
	if cursor+aidLen > len(payload) {
		return fmt.Errorf("gp/cap: Header package AID truncated (need %d bytes after offset %d, have %d)",
			aidLen, cursor, len(payload)-cursor)
	}
	aidBytes := payload[cursor : cursor+aidLen]
	if err := ValidateAID(aidBytes); err != nil {
		return fmt.Errorf("gp/cap: Header package AID: %w", err)
	}
	out.PackageAID = append(AID(nil), aidBytes...)
	cursor += aidLen

	// package_name_info is optional. Treat exactly cursor==len(payload)
	// as "no name" rather than an error because pre-2.2 CAPs omit it.
	switch {
	case cursor == len(payload):
		// No package name. Done.
		return nil
	case cursor+1 > len(payload):
		// Should be unreachable given the previous check, but guard
		// the index access explicitly.
		return fmt.Errorf("gp/cap: Header package_name_info length byte missing")
	}

	nameLen := int(payload[cursor])
	cursor++
	if cursor+nameLen > len(payload) {
		return fmt.Errorf("gp/cap: Header package name truncated (need %d bytes after offset %d, have %d)",
			nameLen, cursor, len(payload)-cursor)
	}
	if nameLen > 0 {
		out.PackageName = append([]byte(nil), payload[cursor:cursor+nameLen]...)
	}
	cursor += nameLen

	if cursor != len(payload) {
		return fmt.Errorf("gp/cap: Header has %d trailing bytes after package_name_info",
			len(payload)-cursor)
	}
	return nil
}

// decodeAppletPayload parses the Applet component payload per
// JC VM Spec §6.9. Layout:
//
//	u1 count
//	repeated count times:
//	    u1 AID_length
//	    u1 AID[AID_length]
//	    u2 install_method_offset
//
// count==0 is permitted (the spec does not forbid an empty Applet
// component, though typically a library package omits the file
// entirely instead). Trailing bytes after the last applet entry
// are an error.
func decodeAppletPayload(payload []byte, out *CAPFile) error {
	if len(payload) == 0 {
		return errors.New("gp/cap: Applet payload empty (need at least the count byte)")
	}
	count := int(payload[0])
	cursor := 1

	applets := make([]CAPApplet, 0, count)
	for i := 0; i < count; i++ {
		if cursor+1 > len(payload) {
			return fmt.Errorf("gp/cap: Applet[%d] missing AID length byte", i)
		}
		aidLen := int(payload[cursor])
		cursor++

		// AID + 2-byte install_method_offset must both fit in the
		// remaining payload.
		if cursor+aidLen+2 > len(payload) {
			return fmt.Errorf("gp/cap: Applet[%d] truncated (need %d bytes for AID+offset, have %d)",
				i, aidLen+2, len(payload)-cursor)
		}
		aidBytes := payload[cursor : cursor+aidLen]
		if err := ValidateAID(aidBytes); err != nil {
			return fmt.Errorf("gp/cap: Applet[%d] AID: %w", i, err)
		}
		cursor += aidLen

		offset := binary.BigEndian.Uint16(payload[cursor : cursor+2])
		cursor += 2

		applets = append(applets, CAPApplet{
			AID:                 append(AID(nil), aidBytes...),
			InstallMethodOffset: offset,
		})
	}

	if cursor != len(payload) {
		return fmt.Errorf("gp/cap: Applet has %d trailing bytes after %d applet entries",
			len(payload)-cursor, count)
	}
	out.Applets = applets
	return nil
}
