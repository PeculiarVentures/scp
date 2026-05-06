package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// CAP test fixtures: built inline using the same JC VM Spec
// layout the gp package tests use, but kept self-contained here
// so the cmd/scpctl module's tests don't reach into gp's internal
// test helpers (gp's helpers are package-private).

const capPkgName = "com/example/javacard"

func writeFixtureCAP(t *testing.T) string {
	t.Helper()
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	header := buildFixtureHeader(pkgAID, []byte("com.example"))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, payload []byte) {
		fh := capPkgName + "/" + name
		w, err := zw.Create(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	// Component framing: tag + u2 size + payload. Tags from JC
	// VM Spec Table 6-1.
	frame := func(tag byte, payload []byte) []byte {
		out := make([]byte, 3+len(payload))
		out[0] = tag
		binary.BigEndian.PutUint16(out[1:3], uint16(len(payload)))
		copy(out[3:], payload)
		return out
	}
	add("Header.cap", frame(1, header))
	add("Directory.cap", frame(2, nil))
	add("Applet.cap", frame(3, []byte{0x00})) // zero applets but present
	add("Import.cap", frame(4, nil))
	add("ConstantPool.cap", frame(5, nil))
	add("Class.cap", frame(6, nil))
	add("Method.cap", frame(7, nil))
	add("StaticField.cap", frame(8, nil))
	add("RefLocation.cap", frame(9, nil))
	add("Export.cap", frame(10, nil))
	add("Descriptor.cap", frame(11, nil))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.cap")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildFixtureHeader(pkgAID, pkgName []byte) []byte {
	var p []byte
	// magic = 0xDECAFFED per JC VM Spec
	p = binary.BigEndian.AppendUint32(p, 0xDECAFFED)
	p = append(p, 0x02, 0x02) // CAP minor, major
	p = append(p, 0x00)       // flags
	p = append(p, 0x01, 0x02) // package version minor, major
	p = append(p, byte(len(pkgAID)))
	p = append(p, pkgAID...)
	if len(pkgName) > 0 {
		p = append(p, byte(len(pkgName)))
		p = append(p, pkgName...)
	}
	return p
}

func runGPInstall(t *testing.T, makeTransport func() transport.Transport, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return makeTransport(), nil
		},
	}
	err := cmdGPInstall(context.Background(), env, args)
	return buf.String(), err
}

// --- input validation ---------------------------------------------------

func TestGPInstall_RequiresCAPPath(t *testing.T) {
	_, err := runGPInstall(t, nil, []string{
		"--applet-aid", "D2760001240101",
		"--scp03-keys-default",
	})
	if err == nil {
		t.Fatal("expected error when --cap missing")
	}
	if !strings.Contains(err.Error(), "--cap") {
		t.Errorf("error should mention --cap: %v", err)
	}
}

func TestGPInstall_RequiresAppletAID(t *testing.T) {
	path := writeFixtureCAP(t)
	_, err := runGPInstall(t, nil, []string{
		"--cap", path,
		"--scp03-keys-default",
	})
	if err == nil {
		t.Fatal("expected error when --applet-aid missing")
	}
	if !strings.Contains(err.Error(), "--applet-aid") {
		t.Errorf("error should mention --applet-aid: %v", err)
	}
}

func TestGPInstall_RequiresExplicitSCP03KeyChoice(t *testing.T) {
	path := writeFixtureCAP(t)
	_, err := runGPInstall(t, nil, []string{
		"--cap", path,
		"--applet-aid", "D2760001240101",
	})
	if err == nil {
		t.Fatal("expected error when no SCP03 key choice supplied")
	}
	if !strings.Contains(err.Error(), "explicit SCP03 key choice") {
		t.Errorf("error should mention explicit SCP03 key choice: %v", err)
	}
}

func TestGPInstall_RejectsMalformedAppletAID(t *testing.T) {
	path := writeFixtureCAP(t)
	out, err := runGPInstall(t,
		func() transport.Transport { return mockcard.NewSCP03Card(scp03.DefaultKeys).Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "AB", // 1 byte, < 5-byte minimum
			"--scp03-keys-default",
		})
	if err == nil {
		t.Fatal("expected error for AID too short")
	}
	if !strings.Contains(out, "applet-aid") {
		t.Errorf("output should mention applet-aid: %s", out)
	}
}

// --- dry-run ------------------------------------------------------------

func TestGPInstall_DryRun_DoesNotMutateCard(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
		})
	if err != nil {
		t.Fatalf("dry-run install failed: %v\n--- output ---\n%s", err, out)
	}

	// Output sanity: the SHA-256 line should appear (computed
	// even in dry-run) and at least one SKIP for the destructive
	// stages.
	for _, want := range []string{
		"scpctl gp install",
		"load image",
		"SHA-256",
		"SKIP",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}

	// Card state must be unchanged: registries empty.
	if len(mc.RegistryLoadFiles) != 0 || len(mc.RegistryApps) != 0 {
		t.Errorf("dry-run mutated card state: load=%v apps=%v",
			mc.RegistryLoadFiles, mc.RegistryApps)
	}
}

// --- end-to-end via SCP03+GP combined mock ------------------------------

func TestGPInstall_ConfirmWrite_HappyPath(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--confirm-write",
		})
	if err != nil {
		t.Fatalf("install failed: %v\n--- output ---\n%s", err, out)
	}

	for _, want := range []string{
		"INSTALL [for load]",
		"LOAD blocks",
		"INSTALL [for install]",
		"PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("happy-path install should not produce any FAIL lines\n--- output ---\n%s", out)
	}

	// Card state: load file + applet registered.
	if len(mc.RegistryLoadFiles) != 1 {
		t.Errorf("expected 1 load file registered; got %d", len(mc.RegistryLoadFiles))
	}
	if len(mc.RegistryApps) != 1 {
		t.Errorf("expected 1 applet registered; got %d", len(mc.RegistryApps))
	}
}

// TestGPInstall_ConfirmWrite_PartialFailure_PrintsCleanupHint
// verifies that a stage-2 failure (LOAD mid-stream) surfaces:
//   - PASS for INSTALL [for load] (stage 1 succeeded)
//   - FAIL for LOAD blocks with byte-progress detail
//   - SKIP for INSTALL [for install] (stage 3 not attempted)
//   - cleanup recipe mentioning DELETE
func TestGPInstall_ConfirmWrite_PartialFailure_PrintsCleanupHint(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.FailLoadAtSeq = 0 // fail the very first LOAD block

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--confirm-write",
		})
	if err == nil {
		t.Fatalf("install should have failed at LOAD stage; output:\n%s", out)
	}

	for _, want := range []string{
		"INSTALL [for load]",
		"LOAD blocks",
		"FAIL",
		"DELETE", // cleanup recipe mentions DELETE
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Stage 3 should be SKIPPED.
	if !strings.Contains(out, "SKIP") {
		t.Errorf("output should contain SKIP for the not-attempted stage 3:\n%s", out)
	}
	// Applet should NOT be registered (stage 3 never attempted).
	if len(mc.RegistryApps) != 0 {
		t.Errorf("applet should not be registered after stage-2 failure: %v", mc.RegistryApps)
	}
}
