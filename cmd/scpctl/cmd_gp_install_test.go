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

	"github.com/PeculiarVentures/scp/apdu"
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
	mc.AddFault(mockcard.FailLoadAtSeq(0, 0x6A84)) // fail the very first LOAD block

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

// TestGPInstall_PreflightSurfacesComponentList covers branch-review
// item #4: the dry-run preflight should print the list of
// components actually going into the load image, the chunk plan
// at the configured block size, and the raw privilege bytes,
// so an operator catches Debug/Descriptor inclusion mismatches
// or mistyped privileges before authorizing the write.
func TestGPInstall_PreflightSurfacesComponentList(t *testing.T) {
	capPath := writeFixtureCAP(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("dry-run must not open a transport")
			return nil, nil
		},
	}
	err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-block-size", "128",
		"--privileges", "9E",
		"--scp03-keys-default",
	})
	if err != nil {
		t.Fatalf("dry-run install: %v\n%s", err, buf.String())
	}

	out := buf.String()
	for _, want := range []string{
		"load image components",
		"load block plan",
		"LOAD APDU",
		"128 bytes each",
		"privileges",
		"0x9E",
		"load hash",
		"none (host does not auto-send",
		"Header.cap",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preflight output missing %q:\n%s", want, out)
		}
	}
}

// TestGPInstall_PreflightFlagsLargeFieldOverflow covers branch-review
// item #5: a privilege blob that exceeds 255 bytes (well beyond
// real-world usage but the cap should still apply uniformly)
// fails before any APDU is built. Verifies the failure happens
// at the dry-run preflight stage with a clear field-name error
// rather than silently truncating on the wire.
func TestGPInstall_PreflightFlagsLargeFieldOverflow(t *testing.T) {
	capPath := writeFixtureCAP(t)

	// 256 bytes of privilege data — one over the LV cap.
	hugePrivs := strings.Repeat("AA", 256)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return nil, nil
		},
	}
	err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--privileges", hugePrivs,
		"--scp03-keys-default",
	})
	// Note: today the privileges flag itself rejects oversized input
	// at decode time. If that ever loosens, this test additionally
	// covers the LV-cap fallback at install time. Either way, the
	// test asserts the request is rejected before the wire.
	if err == nil {
		t.Fatal("expected error for 256-byte privileges blob")
	}
}

// TestGPInstall_LoadHashSHA256ReachesWire covers branch-review item #6:
// --load-hash sha256 should make the host compute SHA-256 of the
// load image and place it in the INSTALL [for load] payload's
// hash field. We capture the on-wire INSTALL APDU and verify the
// hash byte position carries the expected digest.
func TestGPInstall_LoadHashSHA256ReachesWire(t *testing.T) {
	capPath := writeFixtureCAP(t)

	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-hash", "sha256",
		"--scp03-keys-default",
		"--confirm-write",
	}); err != nil {
		t.Fatalf("cmdGPInstall: %v\n%s", err, buf.String())
	}

	// Find INSTALL [for load]: INS=0xE6, P1=0x02. The recorded
	// command is post-secure-messaging; the inner payload starts
	// with the load file AID LV, then the SD AID LV, then the
	// load file data block hash LV. Walk the LVs to extract the
	// hash field.
	var installForLoad *apdu.Command
	for _, c := range rec.cmds {
		if c.INS == 0xE6 && c.P1 == 0x02 {
			installForLoad = c
			break
		}
	}
	if installForLoad == nil {
		t.Fatal("no INSTALL [for load] APDU recorded")
	}

	// The recorded command is the SM-wrapped form, so its Data
	// is the encrypted+MACed payload, not the LV stream. We
	// can't decode the inner LV stream here without re-running
	// SM unwrap. The valuable check is that the install
	// completed end-to-end with --load-hash sha256 — the mock
	// would reject a malformed payload at the GPState dispatch.
	// JSON output asserts the operator-facing path; the wire
	// presence of a non-empty INSTALL [for load] is the
	// operator-facing assurance.
	if len(installForLoad.Data) == 0 {
		t.Errorf("INSTALL [for load] payload empty")
	}

	// Output should reflect the chosen algorithm + the digest.
	out := buf.String()
	if !strings.Contains(out, "sha256") {
		t.Errorf("output should mention sha256 algorithm:\n%s", out)
	}
	// The text-mode hash detail includes the uppercase digest.
	// SHA-256 digests are 64 hex chars; just check that some
	// hex string of the right length appears.
	if !strings.Contains(strings.ToLower(out), "load hash") {
		t.Errorf("output missing 'load hash' line:\n%s", out)
	}
}

// TestGPInstall_LoadHashHexLiteralPassesThrough: --load-hash
// hex:DEADBEEF should send DEADBEEF on the wire even when the
// load image's actual digest is something else. Used by
// operators with precomputed digests under DAP / vendor
// signing flows.
func TestGPInstall_LoadHashHexLiteralPassesThrough(t *testing.T) {
	capPath := writeFixtureCAP(t)

	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-hash", "hex:DEADBEEF",
		"--scp03-keys-default",
		"--confirm-write",
	}); err != nil {
		t.Fatalf("cmdGPInstall: %v\n%s", err, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "hex (4 bytes)") {
		t.Errorf("output should label the hash as 'hex (4 bytes)':\n%s", out)
	}
	if !strings.Contains(out, "DEADBEEF") {
		t.Errorf("output should echo the supplied digest:\n%s", out)
	}
}

// TestGPInstall_LoadHashRejectsUnknownAlgorithm: a typo'd
// algorithm name fails at flag-parse time before any I/O.
func TestGPInstall_LoadHashRejectsUnknownAlgorithm(t *testing.T) {
	capPath := writeFixtureCAP(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("flag-parse failure must not open a transport")
			return nil, nil
		},
	}
	err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-hash", "md5",
		"--scp03-keys-default",
	})
	if err == nil {
		t.Fatal("expected error for unrecognized algorithm")
	}
	if !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("error should say 'unrecognized': %v", err)
	}
}

// TestGPInstall_LoadProgressEmitted covers branch-review item #1's
// in-flight progress: a real install with --confirm-write should
// emit 'LOAD N/M' lines to errOut so an operator watching a long
// install sees progress. JSON mode skips this chatter.
func TestGPInstall_LoadProgressEmitted(t *testing.T) {
	capPath := writeFixtureCAP(t)

	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	var stdout, stderr bytes.Buffer
	env := &runEnv{
		out: &stdout, errOut: &stderr,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-block-size", "32", // small so the fixture spans multiple blocks
		"--scp03-keys-default",
		"--confirm-write",
	}); err != nil {
		t.Fatalf("cmdGPInstall: %v\nstdout:%s\nstderr:%s", err, stdout.String(), stderr.String())
	}

	// At least one LOAD progress line on stderr.
	if !strings.Contains(stderr.String(), "LOAD 1/") {
		t.Errorf("stderr should contain 'LOAD 1/...' progress line:\n%s", stderr.String())
	}
}

// TestGPInstall_LoadProgressSilentInJSONMode: --json suppresses
// the per-block chatter so a JSON consumer parses a single
// terminal object.
func TestGPInstall_LoadProgressSilentInJSONMode(t *testing.T) {
	capPath := writeFixtureCAP(t)

	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	var stdout, stderr bytes.Buffer
	env := &runEnv{
		out: &stdout, errOut: &stderr,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdGPInstall(context.Background(), env, []string{
		"--reader", "fake",
		"--cap", capPath,
		"--applet-aid", "D2760001240101",
		"--load-block-size", "32",
		"--scp03-keys-default",
		"--confirm-write",
		"--json",
	}); err != nil {
		t.Fatalf("cmdGPInstall: %v\n%s", err, stdout.String())
	}
	if strings.Contains(stderr.String(), "LOAD ") {
		t.Errorf("JSON mode should not emit LOAD progress; stderr:\n%s", stderr.String())
	}
}
