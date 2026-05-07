package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/transport"
)

// Synthetic CAP-file builder for CLI-level tests. Mirrors the
// JC VM Spec §6 layout used by gp/cap_test.go but does not import
// it (helpers there are unexported). Keeps tests self-contained.

func writeSyntheticCAP(t *testing.T, path string, pkgAID, appletAID []byte, pkgName string) {
	t.Helper()

	frame := func(tag byte, payload []byte) []byte {
		out := make([]byte, 3+len(payload))
		out[0] = tag
		binary.BigEndian.PutUint16(out[1:3], uint16(len(payload)))
		copy(out[3:], payload)
		return out
	}

	// Header payload per JC VM Spec §6.7.
	var header []byte
	header = binary.BigEndian.AppendUint32(header, 0xDECAFFED) // magic
	header = append(header, 0x02, 0x02)                        // CAP minor, major
	header = append(header, 0x00)                              // flags
	header = append(header, 0x00, 0x01)                        // pkg minor, major
	header = append(header, byte(len(pkgAID)))
	header = append(header, pkgAID...)
	header = append(header, byte(len(pkgName)))
	header = append(header, []byte(pkgName)...)

	// Applet payload per JC VM Spec §6.9: u1 count + per-applet entries.
	var applet []byte
	if appletAID != nil {
		applet = []byte{0x01} // count=1
		applet = append(applet, byte(len(appletAID)))
		applet = append(applet, appletAID...)
		applet = append(applet, 0x00, 0x42) // install_method_offset
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, raw []byte) {
		t.Helper()
		w, err := zw.Create("com/example/javacard/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	put("Header.cap", frame(0x01, header))
	if applet != nil {
		put("Applet.cap", frame(0x03, applet))
	}
	put("Directory.cap", frame(0x02, nil))
	put("Import.cap", frame(0x04, nil))
	put("Class.cap", frame(0x06, nil))
	put("Method.cap", frame(0x07, nil))
	put("StaticField.cap", frame(0x08, nil))
	put("ConstantPool.cap", frame(0x05, nil))
	put("RefLocation.cap", frame(0x09, nil))
	put("Descriptor.cap", frame(0x0B, nil))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runGPCapInspect invokes 'gp cap inspect <path>' against env
// configured with a no-op connect (cap inspect should never call
// connect; the no-op fails the test if it does).
func runGPCapInspect(t *testing.T, args []string) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatalf("gp cap inspect should not call connect; this command is host-only")
			return nil, nil
		},
	}
	if err := cmdGPCap(context.Background(), env, append([]string{"inspect"}, args...)); err != nil {
		t.Fatalf("gp cap inspect: %v\n--- output ---\n%s", err, buf.String())
	}
	return buf.String()
}

// TestGPCapInspect_TextOutput exercises the happy path against a
// synthetic on-disk CAP and verifies the human-readable output
// includes file path, package metadata, applet, and component
// counts.
func TestGPCapInspect_TextOutput(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "synthetic.cap")
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	writeSyntheticCAP(t, capPath, pkgAID, appletAID, "com.example")

	out := runGPCapInspect(t, []string{capPath})

	for _, want := range []string{
		"scpctl gp cap inspect",
		"stat CAP",
		"parse CAP",
		"PASS",
		"D27600012401",      // package AID
		"D276000124010101",  // applet AID
		"package", "applet", // summary words
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("unexpected FAIL\n--- output ---\n%s", out)
	}
}

// TestGPCapInspect_JSONOutput verifies the JSON payload structure
// covers every field the spec's done criteria call for.
func TestGPCapInspect_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "x.cap")
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	writeSyntheticCAP(t, capPath, pkgAID, appletAID, "com.example")

	out := runGPCapInspect(t, []string{"--json", capPath})

	var report struct {
		Subcommand string `json:"subcommand"`
		Data       struct {
			File              string `json:"file"`
			FileSize          int64  `json:"file_size"`
			CAPVersion        string `json:"cap_version"`
			PackageVersion    string `json:"package_version"`
			PackageAID        string `json:"package_aid"`
			PackageName       string `json:"package_name"`
			PackageNameSource string `json:"package_name_source"`
			Applets           []struct {
				AID                    string `json:"aid"`
				InstallMethodOffset    int    `json:"install_method_offset"`
				InstallMethodOffsetHex string `json:"install_method_offset_hex"`
			} `json:"applets"`
			Components []struct {
				Name string `json:"name"`
				Tag  string `json:"tag"`
				Size int    `json:"size"`
			} `json:"components"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal JSON: %v\n--- output ---\n%s", err, out)
	}

	if report.Subcommand != "gp cap inspect" {
		t.Errorf("Subcommand = %q, want %q", report.Subcommand, "gp cap inspect")
	}
	if report.Data.File != capPath {
		t.Errorf("File = %q, want %q", report.Data.File, capPath)
	}
	if report.Data.FileSize <= 0 {
		t.Errorf("FileSize = %d, want > 0", report.Data.FileSize)
	}
	if report.Data.CAPVersion != "2.2" {
		t.Errorf("CAPVersion = %q, want 2.2", report.Data.CAPVersion)
	}
	if report.Data.PackageVersion != "1.0" {
		t.Errorf("PackageVersion = %q, want 1.0", report.Data.PackageVersion)
	}
	if report.Data.PackageAID != "D27600012401" {
		t.Errorf("PackageAID = %q, want D27600012401", report.Data.PackageAID)
	}
	if report.Data.PackageName != "com.example" {
		t.Errorf("PackageName = %q, want com.example", report.Data.PackageName)
	}
	// Header carried package_name_info, so the source should be
	// the header component (not derived from ZIP path).
	if report.Data.PackageNameSource != "header_component" {
		t.Errorf("PackageNameSource = %q, want header_component",
			report.Data.PackageNameSource)
	}
	if len(report.Data.Applets) != 1 {
		t.Fatalf("Applets count = %d, want 1", len(report.Data.Applets))
	}
	if report.Data.Applets[0].AID != "D276000124010101" {
		t.Errorf("Applet[0].AID = %q", report.Data.Applets[0].AID)
	}
	if report.Data.Applets[0].InstallMethodOffset != 0x42 {
		t.Errorf("Applet[0].InstallMethodOffset = %d, want 66 (0x42)",
			report.Data.Applets[0].InstallMethodOffset)
	}
	if report.Data.Applets[0].InstallMethodOffsetHex != "0x0042" {
		t.Errorf("Applet[0].InstallMethodOffsetHex = %q, want 0x0042",
			report.Data.Applets[0].InstallMethodOffsetHex)
	}
	if len(report.Data.Components) == 0 {
		t.Error("Components is empty; expected at least Header")
	}
	// Verify Header is the first component (load order).
	if len(report.Data.Components) > 0 && report.Data.Components[0].Name != "Header.cap" {
		t.Errorf("Components[0].Name = %q, want Header.cap (load order)",
			report.Data.Components[0].Name)
	}
}

// TestGPCapInspect_LibraryPackage verifies that a CAP without an
// Applet component (a library package) produces empty applets in
// the report rather than failing.
func TestGPCapInspect_LibraryPackage(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "lib.cap")
	pkgAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	writeSyntheticCAP(t, capPath, pkgAID, nil, "lib.pkg")

	out := runGPCapInspect(t, []string{capPath})
	if !strings.Contains(out, "0 applet") {
		t.Errorf("expected '0 applet' in output for library package\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("library package should not FAIL\n--- output ---\n%s", out)
	}
}

// TestGPCapInspect_LibraryPackage_JSON_EmptyArrays verifies that
// a library CAP (no Applet.cap) emits applets: [] and not
// applets: null in JSON output. A nil slice in Go marshals to
// JSON null which forces script consumers to handle two distinct
// "no entries" representations; the empty-slice convention is
// the cleaner contract.
func TestGPCapInspect_LibraryPackage_JSON_EmptyArrays(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "lib.cap")
	pkgAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	writeSyntheticCAP(t, capPath, pkgAID, nil, "lib.pkg")

	out := runGPCapInspect(t, []string{"--json", capPath})

	// Verify raw JSON contains 'applets":[' rather than 'applets":null'.
	// Looking at the rendered text rather than unmarshaling-then-checking
	// because Go's json.Marshal on a nil slice writes 'null' verbatim,
	// and the encoded form is what script consumers see.
	if !strings.Contains(out, `"applets": []`) {
		t.Errorf(`expected "applets": [] (empty array, not null); got:\n%s`, out)
	}
	// Components is populated for any valid CAP since Header is mandatory,
	// but verify the field shape is an array regardless.
	if strings.Contains(out, `"components": null`) {
		t.Errorf(`components must never be null; got:\n%s`, out)
	}
}

// TestGPCapInspect_MissingFile_PropagatesError confirms an absent
// path produces a FAIL line and a returned error rather than a
// silent zero-value report.
func TestGPCapInspect_MissingFile_PropagatesError(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}
	err := cmdGPCap(context.Background(), env, []string{"inspect", "/nonexistent/path/x.cap"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("expected FAIL line\n--- output ---\n%s", buf.String())
	}
}

// TestGPCapInspect_RejectsCorruptCAP verifies a malformed file is
// reported as a parse failure with the gp/cap error message
// surfacing through.
func TestGPCapInspect_RejectsCorruptCAP(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "broken.cap")
	if err := os.WriteFile(capPath, []byte("not a zip file at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}
	err := cmdGPCap(context.Background(), env, []string{"inspect", capPath})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("expected FAIL line\n--- output ---\n%s", buf.String())
	}
}

// TestGPCapInspect_RequiresPath confirms missing positional arg is
// a usage error rather than a silent no-op.
func TestGPCapInspect_RequiresPath(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}
	err := cmdGPCap(context.Background(), env, []string{"inspect"})
	if err == nil {
		t.Fatal("expected usage error for missing path")
	}
	var ue *usageError
	if !errorsAs(err, &ue) {
		t.Errorf("expected *usageError, got %T", err)
	}
}

// TestGPCap_UnknownSubcommand confirms 'gp cap something' is a
// usage error and prints help.
func TestGPCap_UnknownSubcommand(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}
	err := cmdGPCap(context.Background(), env, []string{"something-that-doesnt-exist"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(buf.String(), "Subcommands:") {
		t.Errorf("expected usage banner\n--- output ---\n%s", buf.String())
	}
}

// errorsAs is a tiny wrapper that mirrors errors.As without
// importing the package only for this one call site (the test
// file would otherwise import errors solely for As).
func errorsAs(err error, target **usageError) bool {
	for err != nil {
		if ue, ok := err.(*usageError); ok {
			*target = ue
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// writeSyntheticCAPWithImports is writeSyntheticCAP with a
// configurable Import.cap payload. Lets tests verify that the
// inspector surfaces imports + the inferred Java Card runtime
// version. Single-applet CAP, fixed package name, hardcoded
// component framing — only the Import payload differs.
func writeSyntheticCAPWithImports(t *testing.T, path string, pkgAID, appletAID []byte, pkgName string, importPayload []byte) {
	t.Helper()

	frame := func(tag byte, payload []byte) []byte {
		out := make([]byte, 3+len(payload))
		out[0] = tag
		binary.BigEndian.PutUint16(out[1:3], uint16(len(payload)))
		copy(out[3:], payload)
		return out
	}

	var header []byte
	header = binary.BigEndian.AppendUint32(header, 0xDECAFFED)
	header = append(header, 0x02, 0x02)
	header = append(header, 0x00)
	header = append(header, 0x00, 0x01)
	header = append(header, byte(len(pkgAID)))
	header = append(header, pkgAID...)
	header = append(header, byte(len(pkgName)))
	header = append(header, []byte(pkgName)...)

	var applet []byte
	if appletAID != nil {
		applet = []byte{0x01}
		applet = append(applet, byte(len(appletAID)))
		applet = append(applet, appletAID...)
		applet = append(applet, 0x00, 0x42)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, raw []byte) {
		t.Helper()
		w, err := zw.Create("com/example/javacard/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	put("Header.cap", frame(0x01, header))
	if applet != nil {
		put("Applet.cap", frame(0x03, applet))
	}
	put("Directory.cap", frame(0x02, nil))
	put("Import.cap", frame(0x04, importPayload))
	put("Class.cap", frame(0x06, nil))
	put("Method.cap", frame(0x07, nil))
	put("StaticField.cap", frame(0x08, nil))
	put("ConstantPool.cap", frame(0x05, nil))
	put("RefLocation.cap", frame(0x09, nil))
	put("Descriptor.cap", frame(0x0B, nil))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestGPCapInspect_ReportsImportsAndJCVersion: a CAP that
// imports javacard.framework 1.4 + javacardx.crypto 1.0
// surfaces both packages and "JC 2.2.2" in the JSON output.
func TestGPCapInspect_ReportsImportsAndJCVersion(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "with-imports.cap")

	// Hand-built Import payload: count=2, then two records.
	// AIDs are the JC standard AIDs so the parser resolves names.
	frameworkAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01}
	cryptoAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x62, 0x02, 0x01, 0x01}
	imp := []byte{0x02} // count
	imp = append(imp, 0x04, 0x01, byte(len(frameworkAID)))
	imp = append(imp, frameworkAID...)
	imp = append(imp, 0x00, 0x01, byte(len(cryptoAID)))
	imp = append(imp, cryptoAID...)

	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}
	writeSyntheticCAPWithImports(t, capPath, pkgAID, appletAID, "com.example", imp)

	out := runGPCapInspect(t, []string{"--json", capPath})

	var parsed struct {
		Data struct {
			JavaCardVersion string `json:"java_card_version"`
			Imports         []struct {
				AID     string `json:"aid"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"imports"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if parsed.Data.JavaCardVersion != "JC 2.2.2" {
		t.Errorf("java_card_version = %q, want JC 2.2.2", parsed.Data.JavaCardVersion)
	}
	if len(parsed.Data.Imports) != 2 {
		t.Fatalf("imports = %d, want 2", len(parsed.Data.Imports))
	}
	if parsed.Data.Imports[0].Name != "javacard.framework" {
		t.Errorf("imports[0].name = %q, want javacard.framework", parsed.Data.Imports[0].Name)
	}
	if parsed.Data.Imports[0].Version != "1.4" {
		t.Errorf("imports[0].version = %q, want 1.4", parsed.Data.Imports[0].Version)
	}
	if parsed.Data.Imports[1].Name != "javacardx.crypto" {
		t.Errorf("imports[1].name = %q, want javacardx.crypto", parsed.Data.Imports[1].Name)
	}

	// Text output should also mention the runtime version.
	if !strings.Contains(out, "JC 2.2.2") {
		t.Errorf("text output should mention JC version:\n%s", out)
	}
}

// TestGPCapInspect_EmptyImports_NoJCVersion: a synthetic CAP
// with empty Import.cap (no framework imported) -> no JC
// runtime line in the JSON or text output.
func TestGPCapInspect_EmptyImports_NoJCVersion(t *testing.T) {
	dir := t.TempDir()
	capPath := filepath.Join(dir, "no-imports.cap")

	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}
	writeSyntheticCAPWithImports(t, capPath, pkgAID, appletAID, "com.example", nil)

	out := runGPCapInspect(t, []string{"--json", capPath})

	var parsed struct {
		Data struct {
			JavaCardVersion string     `json:"java_card_version"`
			Imports         []struct{} `json:"imports"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if parsed.Data.JavaCardVersion != "" {
		t.Errorf("java_card_version should be empty when no framework imported, got %q",
			parsed.Data.JavaCardVersion)
	}
	if len(parsed.Data.Imports) != 0 {
		t.Errorf("imports should be empty, got %v", parsed.Data.Imports)
	}
}
