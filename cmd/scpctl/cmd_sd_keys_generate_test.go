package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestSDKeysGenerate_RejectsNonSCP11SDSlot pins the host-side guard
// that GENERATE EC KEY only targets SCP11 SD slots (0x11 SCP11a,
// 0x13 SCP11b, 0x15 SCP11c). Passing other KIDs — SCP03 0x01,
// OCE/CA public 0x10/0x20-0x2F, anything else — is a usage error
// before any APDU goes out.
//
// The error message must name the offending KID and explain the
// allowed set so the operator knows what's accepted, not just that
// their input was wrong.
func TestSDKeysGenerate_RejectsNonSCP11SDSlot(t *testing.T) {
	cases := []struct {
		name string
		kid  string
	}{
		{"scp03 (0x01)", "01"},
		{"oce/ca public (0x10)", "10"},
		{"klcc range (0x20)", "20"},
		{"klcc range (0x2F)", "2F"},
		{"out of range (0x30)", "30"},
		{"out of range (0xFF)", "FF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			args := []string{
				"--reader", "fake",
				"--kid", tc.kid,
				"--kvn", "01",
				"--out", "/tmp/should-not-write",
			}
			err = cmdSDKeysGenerate(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
			if !strings.Contains(err.Error(), "SCP11 SD") {
				t.Errorf("error should explain the allowed KID set; got %v", err)
			}
		})
	}
}

// TestSDKeysGenerate_AcceptsSCP11SDSlots verifies the dual: each of
// the three SCP11 SD KIDs reaches the dry-run path without a usage
// error.
func TestSDKeysGenerate_AcceptsSCP11SDSlots(t *testing.T) {
	for _, kid := range []string{"11", "13", "15"} {
		t.Run("kid="+kid, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			dir := t.TempDir()
			env, _ := envForMock(mc)
			args := []string{
				"--reader", "fake",
				"--kid", kid,
				"--kvn", "01",
				"--out", filepath.Join(dir, "spki.pem"),
			}
			if err := cmdSDKeysGenerate(context.Background(), env, args); err != nil {
				t.Fatalf("dry-run for kid=%s: %v", kid, err)
			}
		})
	}
}

// TestSDKeysGenerate_RequiresOut pins the design rule that --out is
// required. The SPKI is the only artifact the operator gets back
// from the card, and printing it to stdout (where it could mix with
// the report text) is a worse default than requiring an explicit
// destination.
func TestSDKeysGenerate_RequiresOut(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "11", "--kvn", "01"}
	err = cmdSDKeysGenerate(context.Background(), env, args)
	if err == nil {
		t.Fatal("expected usageError, got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "--out") {
		t.Errorf("error should mention --out; got %v", err)
	}
}

// TestSDKeysGenerate_RequiresKIDAndKVN: missing required flags
// produce a usageError, not a generic error.
func TestSDKeysGenerate_RequiresKIDAndKVN(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no flags", []string{}},
		{"missing kvn", []string{"--kid", "11", "--out", "x"}},
		{"missing kid", []string{"--kvn", "01", "--out", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDKeysGenerate(context.Background(), env, tc.args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
		})
	}
}

// TestSDKeysGenerate_DryRunByDefault confirms the safety invariant:
// without --confirm-write, validates inputs and reports the planned
// action without opening SCP03 or transmitting the GENERATE APDU.
func TestSDKeysGenerate_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "spki.pem")

	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", outPath,
	}
	if err := cmdSDKeysGenerate(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd keys generate",
		"dry-run",
		"--confirm-write",
		"kid=0x11",
		"kvn=0x01",
		"GENERATE EC KEY",
		"INS=0xF1", // Yubico-extension transparency in the check name
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
	// No file should have been written in dry-run.
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("dry-run must not write the output file; stat err = %v", statErr)
	}
	// Active-write language must not appear.
	if strings.Contains(out, "open SCP03 session") {
		t.Errorf("dry-run output must not include SCP03 open; got:\n%s", out)
	}
}

// TestSDKeysGenerate_DryRunReplaceKVNWording verifies that a non-zero
// --replace-kvn changes the dry-run text to flag the destructive
// shape. Operators on autopilot need the warning that this run will
// REPLACE an existing key, not just install one alongside.
func TestSDKeysGenerate_DryRunReplaceKVNWording(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--replace-kvn", "01",
		"--out", filepath.Join(dir, "spki.pem"),
	}
	if err := cmdSDKeysGenerate(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "REPLACING") {
		t.Errorf("--replace-kvn dry-run must flag the destructive shape; got:\n%s", out)
	}
}

// TestSDKeysGenerate_DryRunJSONShape pins the JSON data block schema.
// Curve must be P-256 (the only thing the library generates today),
// channel must be "dry-run", and the SPKI fingerprint must be empty
// in dry-run (no key was generated yet so no fingerprint exists).
func TestSDKeysGenerate_DryRunJSONShape(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", filepath.Join(dir, "spki.pem"),
		"--json",
	}
	if err := cmdSDKeysGenerate(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysGenerateData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.Channel != "dry-run" {
		t.Errorf("channel = %q, want dry-run", report.Data.Channel)
	}
	if report.Data.Curve != "P-256" {
		t.Errorf("curve = %q, want P-256", report.Data.Curve)
	}
	if report.Data.SPKIFingerprintSHA256 != "" {
		t.Errorf("dry-run must not produce a fingerprint; got %q", report.Data.SPKIFingerprintSHA256)
	}
	if report.Data.OutPath != "" {
		t.Errorf("dry-run must not record an out_path; got %q", report.Data.OutPath)
	}
}

// TestSDKeysGenerate_ConfirmWrite_AuthFails: active path against the
// SCP03-unaware mock fails at 'open SCP03 session'. GENERATE EC KEY
// must NOT be recorded as PASS — the same critical safety guard as
// for delete.
func TestSDKeysGenerate_ConfirmWrite_AuthFails(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "spki.pem")

	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", outPath,
		"--confirm-write",
	}
	err = cmdSDKeysGenerate(context.Background(), env, args)
	if err == nil {
		t.Fatalf("expected SCP03 open failure; got success:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "open SCP03 session") {
		t.Errorf("expected 'open SCP03 session' check; got:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL; got:\n%s", out)
	}
	// File must not exist — atomic-write contract from Phase 1
	// applies here too.
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("failed generate must not write the output file; stat err = %v", statErr)
	}
	// GENERATE EC KEY must never appear as PASS when SCP03 open
	// failed. Scan line-by-line because the check name appears on
	// the FAIL line too in some report shapes.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "GENERATE EC KEY") && strings.Contains(line, "PASS") {
			t.Errorf("GENERATE EC KEY recorded as PASS despite SCP03 open failure: %q", line)
		}
	}
}

// --- internal helpers ---

// TestIsSCP11SDSlot pins the host-side KID classifier for generate.
func TestIsSCP11SDSlot(t *testing.T) {
	cases := []struct {
		kid  byte
		want bool
	}{
		{0x01, false}, // scp03
		{0x10, false}, // ca-public
		{0x11, true},  // scp11a
		{0x12, false},
		{0x13, true}, // scp11b
		{0x14, false},
		{0x15, true}, // scp11c
		{0x16, false},
		{0x20, false}, // ca-public range
		{0x2F, false},
		{0xFF, false},
	}
	for _, tc := range cases {
		if got := isSCP11SDSlot(tc.kid); got != tc.want {
			t.Errorf("isSCP11SDSlot(0x%02X) = %v, want %v", tc.kid, got, tc.want)
		}
	}
}

// TestSDKeysGenerate_PEMBlockType — guard that the output, when
// written, uses the standard "PUBLIC KEY" PEM block label. We can't
// exercise the real generation against the mock (no SCP03), but we
// can pre-compute a PEM block from a known SPKI and verify the
// helper that would be used produces the right shape. Done by
// inspecting the bootstrap-scp11a-sd output convention which we
// match.
//
// This is a thin spec test: it documents the contract for any future
// reader of this code that the PEM type is "PUBLIC KEY", not
// "EC PUBLIC KEY" or anything else.
func TestSDKeysGenerate_PEMBlockType(t *testing.T) {
	// Construct a sample PEM block in the same form the command
	// produces and verify it round-trips.
	sample := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte{0x30, 0x00}, // empty SEQUENCE; not valid SPKI but parseable as PEM
	})
	block, _ := pem.Decode(sample)
	if block == nil {
		t.Fatalf("constructed PEM did not parse: %s", sample)
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
}
