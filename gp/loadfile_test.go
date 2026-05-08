package gp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"errors"
	"testing"
)

// TestBuildPlainLoadFile_C4ShortLength pins the short-form (≤127
// bytes) BER length encoding: a single length byte directly after
// the C4 tag. This is the smallest, most common shape for tiny
// LFDBs (toy applets, test fixtures).
func TestBuildPlainLoadFile_C4ShortLength(t *testing.T) {
	lfdb := bytes.Repeat([]byte{0x01}, 0x7F)
	got, err := BuildPlainLoadFile(lfdb, LoadFileOptions{})
	if err != nil {
		t.Fatalf("BuildPlainLoadFile: %v", err)
	}
	if got[0] != TagLoadFileDataBlock || got[1] != 0x7F {
		t.Fatalf("prefix = % X, want C4 7F", got[:2])
	}
	if !bytes.Equal(got[2:], lfdb) {
		t.Fatal("LFDB bytes changed during wrap")
	}
}

// TestBuildPlainLoadFile_C4LongForm81Length pins the 0x81 long-form
// encoding: 0x81 indicator + one length byte. Exercised at exactly
// 128 bytes (the smallest length that overflows short form).
func TestBuildPlainLoadFile_C4LongForm81Length(t *testing.T) {
	lfdb := bytes.Repeat([]byte{0x02}, 0x80)
	got, err := BuildPlainLoadFile(lfdb, LoadFileOptions{})
	if err != nil {
		t.Fatalf("BuildPlainLoadFile: %v", err)
	}
	if !bytes.Equal(got[:3], []byte{TagLoadFileDataBlock, 0x81, 0x80}) {
		t.Fatalf("prefix = % X, want C4 81 80", got[:3])
	}
	if !bytes.Equal(got[3:], lfdb) {
		t.Fatal("LFDB bytes changed during wrap")
	}
}

// TestBuildPlainLoadFile_C4LongForm82Length pins the 0x82 long-form
// encoding for 256-65535 byte LFDBs. Most real-world JC applets
// land in this size range.
func TestBuildPlainLoadFile_C4LongForm82Length(t *testing.T) {
	lfdb := bytes.Repeat([]byte{0x03}, 0x0100)
	got, err := BuildPlainLoadFile(lfdb, LoadFileOptions{})
	if err != nil {
		t.Fatalf("BuildPlainLoadFile: %v", err)
	}
	if !bytes.Equal(got[:4], []byte{TagLoadFileDataBlock, 0x82, 0x01, 0x00}) {
		t.Fatalf("prefix = % X, want C4 82 01 00", got[:4])
	}
	if !bytes.Equal(got[4:], lfdb) {
		t.Fatal("LFDB bytes changed during wrap")
	}
}

// TestBuildPlainLoadFile_DAPThenC4 round-trips a DAP-signed Load
// File: encode {DAPBlock, LFDB}, parse, assert both halves come
// back unchanged. This pins the encode/parse symmetry the host
// uses when it has externally-computed DAP signatures to inject.
func TestBuildPlainLoadFile_DAPThenC4(t *testing.T) {
	lfdb := []byte{0x01, 0x00, 0x01}
	sdAID := []byte{0xA0, 0x00, 0x00, 0x01, 0x51}
	sig := []byte{0xAA, 0xBB, 0xCC}

	got, err := BuildPlainLoadFile(lfdb, LoadFileOptions{
		DAPBlocks: []DAPBlock{{SDAID: sdAID, Signature: sig}},
	})
	if err != nil {
		t.Fatalf("BuildPlainLoadFile: %v", err)
	}

	parsed, err := ParseLoadFile(got)
	if err != nil {
		t.Fatalf("ParseLoadFile: %v", err)
	}
	if len(parsed.DAPBlocks) != 1 {
		t.Fatalf("DAP count = %d, want 1", len(parsed.DAPBlocks))
	}
	if !bytes.Equal(parsed.DAPBlocks[0].SDAID, sdAID) {
		t.Fatalf("DAP SD AID = % X, want % X", parsed.DAPBlocks[0].SDAID, sdAID)
	}
	if !bytes.Equal(parsed.DAPBlocks[0].Signature, sig) {
		t.Fatalf("DAP sig = % X, want % X", parsed.DAPBlocks[0].Signature, sig)
	}
	if !bytes.Equal(parsed.DataBlock, lfdb) {
		t.Fatalf("LFDB = % X, want % X", parsed.DataBlock, lfdb)
	}
}

// TestBuildPlainLoadFile_RejectsEmptyLFDB pins that a zero-length
// LFDB is refused at the encoder. Encoding C4 80 with no body
// would be a structurally valid but semantically invalid load
// file (no CAP components to load).
func TestBuildPlainLoadFile_RejectsEmptyLFDB(t *testing.T) {
	_, err := BuildPlainLoadFile(nil, LoadFileOptions{})
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestBuildPlainLoadFile_RejectsCipheredFlag pins that the D4
// reservation is enforced at encode time. Setting Ciphered=true
// today would silently produce a C4 wrapped output even though
// the caller asked for D4 — the explicit error catches that.
func TestBuildPlainLoadFile_RejectsCipheredFlag(t *testing.T) {
	_, err := BuildPlainLoadFile([]byte{0x01}, LoadFileOptions{Ciphered: true})
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestBuildPlainLoadFile_RejectsICV pins that the D3 ICV
// reservation is enforced at encode time, parallel to the
// Ciphered guard.
func TestBuildPlainLoadFile_RejectsICV(t *testing.T) {
	_, err := BuildPlainLoadFile([]byte{0x01}, LoadFileOptions{ICV: []byte{0x00}})
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestParseLoadFile_RejectsMissingC4 pins that a stream containing
// only DAP blocks (no LFDB) is rejected. A real LOAD sequence
// always concludes with the LFDB.
func TestParseLoadFile_RejectsMissingC4(t *testing.T) {
	// E2 with empty body — structurally a DAP block tag + zero
	// length, but no LFDB follows.
	_, err := ParseLoadFile([]byte{TagDAPBlock, 0x00})
	if err == nil {
		t.Fatal("expected error for missing C4")
	}
	// The early DAP-validation code path (parseDAPBlock requires
	// a non-empty SD AID) catches this before the missing-C4
	// check; either is correct, so we just verify ErrInvalidLoadFile.
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestParseLoadFile_RejectsMalformedBERLength pins that truncated
// or non-minimal BER lengths fail closed.
func TestParseLoadFile_RejectsMalformedBERLength(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated 0x82 length", []byte{TagLoadFileDataBlock, 0x82, 0x01}},
		{"non-minimal 0x81 (value fits short)", []byte{TagLoadFileDataBlock, 0x81, 0x42, 0xFF}},
		{"indefinite length", []byte{TagLoadFileDataBlock, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLoadFile(tc.in)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrInvalidLoadFile) {
				t.Errorf("err = %v, want ErrInvalidLoadFile", err)
			}
		})
	}
}

// TestParseLoadFile_RejectsD4UntilImplemented pins the D4
// reservation at parse time. Until ciphered LFDB is supported,
// D4 input is rejected loudly rather than silently treated as
// raw bytes.
func TestParseLoadFile_RejectsD4UntilImplemented(t *testing.T) {
	stream := []byte{TagCipheredLoadFileDataBlock, 0x01, 0x00}
	_, err := ParseLoadFile(stream)
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestParseLoadFile_RejectsDuplicateC4 pins that a stream with two
// C4 blocks is invalid. GP §11.6.2 specifies one LFDB per Load File.
func TestParseLoadFile_RejectsDuplicateC4(t *testing.T) {
	first, _ := EncodeTLV(TagLoadFileDataBlock, []byte{0x01})
	second, _ := EncodeTLV(TagLoadFileDataBlock, []byte{0x02})
	stream := append([]byte{}, first...)
	stream = append(stream, second...)
	_, err := ParseLoadFile(stream)
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestLoadFileDataBlockHashes_ExcludeC4TagAndLength is the
// load-bearing assertion for the install hash flow: the SHA-256
// over the LFDB must NOT equal the SHA-256 over the C4-wrapped
// Load File. INSTALL [for load]'s Load File Data Block Hash
// field must be over the LFDB only per GP §11.5.2.3; including
// the wrapper would put the host out of agreement with every
// spec-conformant card.
func TestLoadFileDataBlockHashes_ExcludeC4TagAndLength(t *testing.T) {
	lfdb := []byte{0x01, 0x00, 0x01, 0x02}
	loadFile, err := BuildPlainLoadFile(lfdb, LoadFileOptions{})
	if err != nil {
		t.Fatal(err)
	}

	got256, got1, err := LoadFileDataBlockHashes(lfdb)
	if err != nil {
		t.Fatal(err)
	}
	want256 := sha256.Sum256(lfdb)
	want1 := sha1.Sum(lfdb) //nolint:gosec
	if !bytes.Equal(got256, want256[:]) {
		t.Fatalf("SHA-256 = % X, want % X", got256, want256[:])
	}
	if !bytes.Equal(got1, want1[:]) {
		t.Fatalf("SHA-1 = % X, want % X", got1, want1[:])
	}

	wrong := sha256.Sum256(loadFile)
	if bytes.Equal(got256, wrong[:]) {
		t.Fatal("hash must be over LFDB, not the C4-wrapped load file")
	}
}

// TestLoadFileDataBlockHashes_RejectsEmptyInput pins the zero-
// length guard at hash time. An empty LFDB hash would be a valid
// digest (SHA-256 of empty input is well-defined) but wouldn't
// correspond to anything real, so it's refused as a sanity check.
func TestLoadFileDataBlockHashes_RejectsEmptyInput(t *testing.T) {
	_, _, err := LoadFileDataBlockHashes(nil)
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}

// TestEncodeDecodeBERLength_RoundTrip pins the encoder/decoder
// symmetry across the four length forms.
func TestEncodeDecodeBERLength_RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFF} {
		enc, err := EncodeBERLength(n)
		if err != nil {
			t.Errorf("EncodeBERLength(%d): %v", n, err)
			continue
		}
		got, used, err := DecodeBERLength(enc)
		if err != nil {
			t.Errorf("DecodeBERLength(% X): %v", enc, err)
			continue
		}
		if got != n {
			t.Errorf("round-trip n=%d: got %d", n, got)
		}
		if used != len(enc) {
			t.Errorf("round-trip n=%d: used=%d, encoded len=%d", n, used, len(enc))
		}
	}
}

// TestEncodeBERLength_Rejects4OctetForm pins that values requiring
// 4+ length octets are refused. Real GP Load Files don't reach
// 16MB, and supporting the 0x84 form would invite encoder bloat
// for no practical gain.
func TestEncodeBERLength_RejectsTooLarge(t *testing.T) {
	_, err := EncodeBERLength(0x01000000)
	if !errors.Is(err, ErrInvalidLoadFile) {
		t.Errorf("err = %v, want ErrInvalidLoadFile", err)
	}
}
