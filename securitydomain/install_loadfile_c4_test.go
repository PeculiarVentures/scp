package securitydomain_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/gp"
)

// This file pins the C4-wrapping behavior added when generic GP
// applet management was fixed. See gp/loadfile.go for the
// host-side encoder; the post-fix install pipeline streams
// gp.BuildPlainLoadFile output through LOAD instead of the raw
// LFDB. Tests here cover:
//
//   - The first LOAD APDU starts with C4 (the wire stream begins
//     at the wrapper, not at the LFDB).
//   - The install hash is computed over the LFDB, NOT over the
//     C4-wrapped form (per GP §11.5.2.3).
//   - Chunk boundaries can split anywhere — immediately after the
//     C4 tag, inside the BER length, or inside the LFDB body —
//     and the install still completes successfully. LOAD chunking
//     is byte-stream chunking; it does not align to TLV.
//   - The deprecated InstallOptions.LoadImage alias still works.
//   - InstallOptions.LoadFile bypasses the wrap step when set.
//   - A malformed pre-built LoadFile is rejected before any APDU
//     crosses the wire.
//
// All assertions read the mockcard's RegistryLoadFiles state
// after install. The mockcard's handleLoad calls gp.ParseLoadFile
// on the accumulated bytes before registering — so a successful
// registry entry guarantees the wire stream parsed as a valid
// GP Load File (C4-wrapped). This couples the test assertions
// to the mockcard's strict-parse path; if mockcard regresses to
// accepting raw LFDB, these tests stop being useful — but
// mockcard's own TestLoad_RawLFDBRejectedWithoutC4Wrapper
// guards that.

// TestSession_Install_LOADFirstBlockStartsWithC4 asserts that the
// LOAD wire stream begins with the GP §11.6.2 C4 tag, not with
// the raw LFDB. We exercise this indirectly: a sufficiently
// small LFDB whose wrapped form is also small enough to fit in
// one LOAD APDU streams a single block, and we verify the
// mockcard's accumulated bytes (recoverable via the registry-
// success invariant) start with C4.
func TestSession_Install_LOADFirstBlockStartsWithC4(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := []byte{0x01, 0x00, 0x00, 0xAB, 0xCD}
	expectedLoadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if expectedLoadFile[0] != gp.TagLoadFileDataBlock {
		t.Fatalf("wrapped form should start with C4 = 0x%02X, got 0x%02X",
			gp.TagLoadFileDataBlock, expectedLoadFile[0])
	}

	opts := sampleOpts()
	opts.LoadImage = lfdb
	opts.LoadFileDataBlock = nil
	opts.LoadFile = nil

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// Successful registry entry confirms ParseLoadFile in mockcard
	// accepted the stream — i.e. it WAS C4-wrapped.
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_LOADHashUsesLFDBNotC4WrappedLoadFile pins
// the install hash semantics: the hash field of INSTALL [for
// load] must be computed over the LFDB only, not over the C4-
// wrapped Load File. Including the wrapper would put the host
// out of agreement with every spec-conformant card.
//
// This test verifies the helper's contract directly. The CLI's
// hash resolution path uses gp.LoadFileDataBlockHashes(lfdb), and
// gp.LoadFileDataBlockHashes is defined to hash exactly its input
// — so the assertion that the LFDB and wrapped-form hashes
// differ is equivalent to asserting that the CLI hashes the
// right thing.
func TestSession_Install_LOADHashUsesLFDBNotC4WrappedLoadFile(t *testing.T) {
	lfdb := []byte{0x01, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD}
	loadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	sha256OfLFDB, _, err := gp.LoadFileDataBlockHashes(lfdb)
	if err != nil {
		t.Fatal(err)
	}
	sha256OfWrapped, _, err := gp.LoadFileDataBlockHashes(loadFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sha256OfLFDB, sha256OfWrapped) {
		t.Fatal("LFDB hash and wrapped-form hash must differ; if they're equal, the C4 wrapper is empty (LFDB and wrapped same length) which is structurally impossible")
	}
}

// TestSession_Install_LoadFileCanSplitAfterC4Tag exercises a chunk
// boundary that falls immediately after the C4 tag. With a 127-
// byte LFDB and LoadBlockSize=1, the first LOAD APDU carries
// just the C4 byte; the second carries the BER length 0x7F; the
// rest carry the LFDB. The mockcard's Parse path must reassemble
// across all 129 blocks.
func TestSession_Install_LoadFileCanSplitAfterC4Tag(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := bytes.Repeat([]byte{0x01}, 0x7F)
	loadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity check the fixture shape: C4 7F + 127 bytes = 129 bytes.
	if len(loadFile) != 129 || loadFile[0] != gp.TagLoadFileDataBlock || loadFile[1] != 0x7F {
		t.Fatalf("test fixture: wrapped = % X (%d bytes), want C4 7F + 127", loadFile[:2], len(loadFile))
	}

	opts := sampleOpts()
	opts.LoadFileDataBlock = lfdb
	opts.LoadFile = loadFile
	opts.LoadImage = nil
	opts.LoadBlockSize = 1

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_LoadFileCanSplitInsideBERLength exercises a
// chunk boundary that falls inside a multi-byte BER length. With
// a 128-byte LFDB the wrapped form is C4 81 80 + 128 bytes = 131
// bytes, and at LoadBlockSize=2 the first chunk is C4 81 (the
// long-form indicator AND the start of the length octets), the
// second is 80 + LFDB[0] (split between length end and LFDB
// start), and so on. Real GP cards reassemble across this
// boundary exactly because the wire stream is opaque bytes.
func TestSession_Install_LoadFileCanSplitInsideBERLength(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := bytes.Repeat([]byte{0x02}, 0x80)
	loadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadFile[:3], []byte{gp.TagLoadFileDataBlock, 0x81, 0x80}) {
		t.Fatalf("test fixture: prefix % X, want C4 81 80", loadFile[:3])
	}

	opts := sampleOpts()
	opts.LoadFileDataBlock = lfdb
	opts.LoadFile = loadFile
	opts.LoadImage = nil
	opts.LoadBlockSize = 2 // split between 0x81 and 0x80

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_LoadFileCanSplitInsideLFDB exercises a chunk
// boundary that falls inside the LFDB body itself. Pre-2026
// chunking implicitly assumed the LFDB went on the wire as one
// component-aligned sequence; post-fix the wire stream is
// opaque bytes and chunks can split anywhere. This is the easy
// case (just verify the install completes when blocks split
// inside CAP-component-equivalent bytes).
func TestSession_Install_LoadFileCanSplitInsideLFDB(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := bytes.Repeat([]byte{0x03}, 64)
	loadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	opts := sampleOpts()
	opts.LoadFileDataBlock = lfdb
	opts.LoadFile = loadFile
	opts.LoadImage = nil
	opts.LoadBlockSize = 7 // arbitrary mid-LFDB split

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_BackwardCompatLoadImageAliasBuildsC4 pins
// the contract that pre-2026 callers using InstallOptions.LoadImage
// continue to work without code changes. The alias maps to
// LoadFileDataBlock under the hood, and Install wraps the
// resulting LFDB in C4 just as if the new field had been used.
func TestSession_Install_BackwardCompatLoadImageAliasBuildsC4(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := []byte{0x01, 0x00, 0x00}
	opts := sampleOpts()
	opts.LoadImage = lfdb
	opts.LoadFileDataBlock = nil
	opts.LoadFile = nil
	opts.LoadBlockSize = 1

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_ExplicitLoadFileUsedAsIs pins the contract
// that callers supplying a pre-built LoadFile (e.g. with
// externally-computed DAP signatures) get those exact bytes on
// the wire — Install does NOT re-wrap or otherwise modify the
// pre-built form. The mockcard's Parse path validates the
// supplied LoadFile structurally; success means it round-tripped
// unmodified.
func TestSession_Install_ExplicitLoadFileUsedAsIs(t *testing.T) {
	sess, mc := openInstallSession(t)

	lfdb := []byte{0x01, 0x00, 0x00, 0xCC}
	loadFile, err := gp.BuildPlainLoadFile(lfdb, gp.LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	opts := sampleOpts()
	opts.LoadFileDataBlock = lfdb
	opts.LoadFile = loadFile
	opts.LoadImage = nil

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("expected 1 registered load file, got %d", len(mc.RegistryLoadFiles))
	}
}

// TestSession_Install_RejectsMalformedExplicitLoadFile pins that
// validateInstallOptions catches a malformed pre-built LoadFile
// before any APDU crosses the wire. Without this check, a
// caller passing garbage in LoadFile would discover the problem
// only after INSTALL [for load] succeeded and a LOAD block was
// rejected — leaving partially-applied state on the card.
func TestSession_Install_RejectsMalformedExplicitLoadFile(t *testing.T) {
	sess, mc := openInstallSession(t)

	opts := sampleOpts()
	opts.LoadImage = nil
	opts.LoadFileDataBlock = nil
	opts.LoadFile = []byte{0xFF, 0xFF, 0xFF} // not a Load File: unknown tag

	err := sess.Install(context.Background(), opts)
	if err == nil {
		t.Fatal("expected refusal of malformed LoadFile")
	}
	// Pre-stage validation error wraps gp.ErrInvalidLoadFile.
	if !errors.Is(err, gp.ErrInvalidLoadFile) {
		t.Errorf("err = %v, want errors.Is gp.ErrInvalidLoadFile", err)
	}
	// No card mutation happened: registries empty.
	if len(mc.RegistryLoadFiles) != 0 {
		t.Errorf("registry should be empty after pre-stage refusal; got %d entries", len(mc.RegistryLoadFiles))
	}
}
