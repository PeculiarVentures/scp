package gp

import (
	"fmt"
)

// decodeImportPayload parses the Import component payload per
// JC VM Spec §6.5. Layout:
//
//	count u1
//	packages[count] {
//	    minor_version u1
//	    major_version u1
//	    AID_length    u1
//	    AID           AID_length bytes
//	}
//
// An empty payload is treated as count=0. The spec requires at
// least the count byte, but some real-world toolchains emit an
// Import component with an empty payload for library CAPs that
// import nothing observable, and there is no value in failing
// the whole parse for that. A non-empty payload that can't be
// fully consumed is still an error.
//
// A count of 0 is legal — a CAP that imports nothing is unusual
// (every applet imports javacard.framework) but valid for some
// library CAPs that depend only on java.lang. Trailing bytes
// after the last record are an error: a well-formed Import
// component packs the records tightly.
func decodeImportPayload(payload []byte, out *CAPFile) error {
	if len(payload) == 0 {
		out.Imports = nil
		return nil
	}
	count := int(payload[0])
	cursor := 1

	imports := make([]CAPImport, 0, count)
	for i := 0; i < count; i++ {
		// Each record is at minimum 3 bytes (minor, major,
		// AID_length) plus AID. Bail before the multi-step decode
		// if the fixed prefix won't fit.
		if cursor+3 > len(payload) {
			return fmt.Errorf("gp/cap: Import[%d] truncated (need 3 bytes for minor+major+aidLen, have %d)",
				i, len(payload)-cursor)
		}
		minor := payload[cursor]
		major := payload[cursor+1]
		aidLen := int(payload[cursor+2])
		cursor += 3

		if cursor+aidLen > len(payload) {
			return fmt.Errorf("gp/cap: Import[%d] AID truncated (need %d bytes, have %d)",
				i, aidLen, len(payload)-cursor)
		}
		aid := payload[cursor : cursor+aidLen]
		if err := ValidateAID(aid); err != nil {
			return fmt.Errorf("gp/cap: Import[%d] AID: %w", i, err)
		}
		cursor += aidLen

		imp := CAPImport{
			AID:          append(AID(nil), aid...),
			MajorVersion: major,
			MinorVersion: minor,
			Name:         resolveImportName(aid),
		}
		imports = append(imports, imp)
	}

	if cursor != len(payload) {
		return fmt.Errorf("gp/cap: Import has %d trailing bytes after %d records",
			len(payload)-cursor, count)
	}

	out.Imports = imports
	return nil
}

// standardJCPackages maps the AID of a Java Card or GlobalPlatform
// standard package (hex, uppercase) to the developer-facing name.
// Sourced from publicly available specs:
//
//   - JC VM Spec / JC API Spec — java.lang, javacard.framework,
//     javacard.security, javacardx.crypto, javacardx.framework
//     (each spec lists the AID it reserves).
//
//   - GP Card Spec v2.3.1 §F.1 — org.globalplatform package AIDs
//     for the GP API library (multiple variants for different
//     spec revisions; the most common production-CAP imports are
//     covered).
//
// The table is intentionally small. A missing entry means the
// CAP imports a package the registry does not know about; the
// CAPImport.Name field stays empty and the AID hex is still
// informative for the operator.
var standardJCPackages = map[string]string{
	// Java Card platform (JC VM Spec).
	"A0000000620001":   "java.lang",
	"A0000000620002":   "java.io",
	"A0000000620003":   "java.rmi",
	"A0000000620101":   "javacard.framework",
	"A0000000620102":   "javacard.security",
	"A000000062010101": "javacard.framework.service",
	"A000000062020101": "javacardx.crypto",

	// GlobalPlatform (GP Card Spec v2.3.1 §F.1).
	"A00000015100":   "org.globalplatform",
	"A0000001515350": "org.globalplatform.contactless",
}

// resolveImportName returns the human-readable package name for
// an imported AID, or empty string if not known. Lookup is
// uppercase-hex against standardJCPackages.
func resolveImportName(aid []byte) string {
	if len(aid) == 0 {
		return ""
	}
	key := upperHex(aid)
	return standardJCPackages[key]
}

func upperHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&0x0F]
	}
	return string(out)
}

// JavaCardVersion returns a human-readable Java Card runtime
// version inferred from the imported javacard.framework version.
// Returns empty string when javacard.framework is not in
// Imports — the CAP either omits Import.cap entirely (very
// stripped) or is a library CAP that imports only java.lang.
//
// Mapping per JC API Spec, derived from each release's framework
// package version declaration:
//
//	1.0  -> JC 2.1
//	1.1  -> JC 2.1.1
//	1.2  -> JC 2.2.0
//	1.3  -> JC 2.2.1
//	1.4  -> JC 2.2.2
//	1.5  -> JC 3.0.1 (Connected Edition base; Classic 3.0.1)
//	1.6  -> JC 3.0.4
//	1.7  -> JC 3.0.5 / 3.1
//	1.8  -> JC 3.1
//
// Unrecognized major.minor combinations return a string of the
// form "javacard.framework 1.x (unknown JC mapping)" so the
// inspector still surfaces what was on the wire even when the
// table is out of date for a newer release.
func (c *CAPFile) JavaCardVersion() string {
	for _, imp := range c.Imports {
		if imp.Name != "javacard.framework" {
			continue
		}
		key := uint16(imp.MajorVersion)<<8 | uint16(imp.MinorVersion)
		if jc, ok := jcFromFramework[key]; ok {
			return jc
		}
		return fmt.Sprintf("javacard.framework %d.%d (unknown JC mapping)",
			imp.MajorVersion, imp.MinorVersion)
	}
	return ""
}

// jcFromFramework maps (major<<8 | minor) of javacard.framework
// to the corresponding Java Card runtime version label. Keyed
// numerically rather than as a string so callers don't need to
// format-and-parse a "1.4" string.
var jcFromFramework = map[uint16]string{
	0x0100: "JC 2.1",
	0x0101: "JC 2.1.1",
	0x0102: "JC 2.2.0",
	0x0103: "JC 2.2.1",
	0x0104: "JC 2.2.2",
	0x0105: "JC 3.0.1",
	0x0106: "JC 3.0.4",
	0x0107: "JC 3.0.5 / 3.1",
	0x0108: "JC 3.1",
}
