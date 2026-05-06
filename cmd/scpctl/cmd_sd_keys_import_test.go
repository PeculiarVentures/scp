package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestSDKeysImport_DispatchByKID verifies the KID-category dispatch:
// each KID lands at the right handler, with the not-yet-implemented
// categories returning a clear "Phase 5c" message rather than a
// generic error. Phase 5a (SCP03) and Phase 5b (SCP11 SD) both reach
// real handlers; only the CA/OCE category remains stubbed.
func TestSDKeysImport_DispatchByKID(t *testing.T) {
	cases := []struct {
		name             string
		kid              string
		stillStubbed     bool   // true if this category hasn't landed yet
		wantPhaseInErr   string // for stillStubbed: "5c"
		wantInHandlerErr string // for !stillStubbed: distinguishing token
	}{
		{name: "scp03", kid: "01", stillStubbed: false, wantInHandlerErr: "new-scp03"},
		{name: "scp11a-sd", kid: "11", stillStubbed: false, wantInHandlerErr: "--key-pem"},
		{name: "scp11b-sd", kid: "13", stillStubbed: false, wantInHandlerErr: "--key-pem"},
		{name: "scp11c-sd", kid: "15", stillStubbed: false, wantInHandlerErr: "--key-pem"},
		{name: "oce", kid: "10", stillStubbed: true, wantPhaseInErr: "5c"},
		{name: "klcc-low", kid: "20", stillStubbed: true, wantPhaseInErr: "5c"},
		{name: "klcc-high", kid: "2F", stillStubbed: true, wantPhaseInErr: "5c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, buf := envForMock(mc)
			args := []string{"--reader", "fake", "--kid", tc.kid, "--kvn", "01"}
			err = cmdSDKeysImport(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected error from dispatch (stub or handler-level usage); got nil. output:\n%s", buf.String())
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
			switch tc.stillStubbed {
			case true:
				if !strings.Contains(err.Error(), "Phase "+tc.wantPhaseInErr) {
					t.Errorf("stub error should name Phase %s; got %v", tc.wantPhaseInErr, err)
				}
			case false:
				if !strings.Contains(err.Error(), tc.wantInHandlerErr) {
					t.Errorf("handler-level error should mention %q (proves real handler was reached, not stub); got %v",
						tc.wantInHandlerErr, err)
				}
				// And the message must NOT mention any Phase tag — that
				// would mean we hit the stub instead of the real handler.
				for _, phaseTag := range []string{"Phase 5a", "Phase 5b", "Phase 5c"} {
					if strings.Contains(err.Error(), phaseTag) {
						t.Errorf("dispatch hit a stub instead of the real handler (%s in error): %v",
							phaseTag, err)
					}
				}
			}
		})
	}
}

// TestSDKeysImport_RejectsUnknownKID verifies KIDs outside the three
// recognized categories produce a clear usage error that lists the
// valid KID set.
func TestSDKeysImport_RejectsUnknownKID(t *testing.T) {
	for _, kid := range []string{"30", "FE", "FF"} {
		t.Run("kid="+kid, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			args := []string{"--reader", "fake", "--kid", kid, "--kvn", "01"}
			err = cmdSDKeysImport(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected usageError for unknown KID; got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError", err)
			}
			if !strings.Contains(err.Error(), "not a recognized SD import category") {
				t.Errorf("error should name the unknown-category condition; got %v", err)
			}
		})
	}
}

// TestSDKeysImport_RequiresKID verifies the missing --kid case.
func TestSDKeysImport_RequiresKID(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImport(context.Background(), env, []string{"--reader", "fake", "--kvn", "01"})
	if err == nil {
		t.Fatal("expected usageError for missing --kid; got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "--kid") {
		t.Errorf("error should mention --kid; got %v", err)
	}
}

// --- SCP03 path (Phase 5a) ---

// TestSDKeysImportSCP03_RequiresAllNewKeys pins the all-or-nothing
// rule for the new-key triple. Partial specification is rejected
// before any APDU goes out so a half-completed rotation can't misfire.
func TestSDKeysImportSCP03_RequiresAllNewKeys(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "no new keys",
			args: []string{"--kid", "01", "--kvn", "FE"},
		},
		{
			name: "enc only",
			args: []string{
				"--kid", "01", "--kvn", "FE",
				"--new-scp03-enc", strings.Repeat("00", 16),
			},
		},
		{
			name: "missing dek",
			args: []string{
				"--kid", "01", "--kvn", "FE",
				"--new-scp03-enc", strings.Repeat("00", 16),
				"--new-scp03-mac", strings.Repeat("11", 16),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			args := append([]string{"--reader", "fake"}, tc.args...)
			err = cmdSDKeysImport(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected usageError for partial new-key set; got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError", err)
			}
			if !strings.Contains(err.Error(), "all required") {
				t.Errorf("error should explain all-or-nothing rule; got %v", err)
			}
		})
	}
}

// TestSDKeysImportSCP03_RejectsNonAES128 pins the AES-128 scope
// limit. The library currently rejects 24/32-byte components; we
// surface that host-side with a flag-named error rather than letting
// it bubble up from PUT KEY as a generic ErrInvalidKey.
func TestSDKeysImportSCP03_RejectsNonAES128(t *testing.T) {
	cases := []struct {
		name      string
		bytesEach int
	}{
		{"AES-192 (24 bytes)", 24},
		{"AES-256 (32 bytes)", 32},
		{"too short (8 bytes)", 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			hex := strings.Repeat("00", tc.bytesEach)
			args := []string{
				"--reader", "fake",
				"--kid", "01", "--kvn", "FE",
				"--new-scp03-enc", hex,
				"--new-scp03-mac", hex,
				"--new-scp03-dek", hex,
			}
			err = cmdSDKeysImport(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected usageError for %d-byte components; got nil", tc.bytesEach)
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError", err)
			}
			// Error must identify the offending flag and note AES-128.
			if !strings.Contains(err.Error(), "AES-128") {
				t.Errorf("error should mention AES-128 scope; got %v", err)
			}
			if !strings.Contains(err.Error(), "--new-scp03-") {
				t.Errorf("error should name the offending flag; got %v", err)
			}
		})
	}
}

// TestSDKeysImportSCP03_DryRunByDefault confirms the safety
// invariant: without --confirm-write, validates inputs and reports
// the planned action without opening SCP03 or transmitting PUT KEY.
func TestSDKeysImportSCP03_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	hex16 := strings.Repeat("AB", 16)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FE",
		"--new-scp03-enc", hex16,
		"--new-scp03-mac", hex16,
		"--new-scp03-dek", hex16,
	}
	if err := cmdSDKeysImport(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd keys import",
		"dry-run",
		"--confirm-write",
		"PUT KEY (SCP03 AES-128)",
		"kid=0x01",
		"kvn=0xFE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
	// No private material in the output — the new-key bytes must
	// never be echoed back.
	if strings.Contains(out, hex16) {
		t.Errorf("dry-run output leaked the imported key bytes:\n%s", out)
	}
}

// TestSDKeysImportSCP03_DryRunReplaceKVNWording: --replace-kvn flips
// dry-run text to flag the destructive shape, mirroring generate.
func TestSDKeysImportSCP03_DryRunReplaceKVNWording(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	hex16 := strings.Repeat("AB", 16)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FE",
		"--replace-kvn", "FF",
		"--new-scp03-enc", hex16,
		"--new-scp03-mac", hex16,
		"--new-scp03-dek", hex16,
	}
	if err := cmdSDKeysImport(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "REPLACING") {
		t.Errorf("--replace-kvn dry-run must flag destructive shape; got:\n%s", buf.String())
	}
}

// TestSDKeysImportSCP03_DryRunJSONShape pins the JSON data block
// schema for the SCP03 path.
func TestSDKeysImportSCP03_DryRunJSONShape(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	hex16 := strings.Repeat("AB", 16)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FE",
		"--new-scp03-enc", hex16,
		"--new-scp03-mac", hex16,
		"--new-scp03-dek", hex16,
		"--json",
	}
	if err := cmdSDKeysImport(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.Channel != "dry-run" {
		t.Errorf("channel = %q, want dry-run", report.Data.Channel)
	}
	if report.Data.Category != "scp03-key-set" {
		t.Errorf("category = %q, want scp03-key-set", report.Data.Category)
	}
	if report.Data.KIDHex != "0x01" {
		t.Errorf("kid_hex = %q, want 0x01", report.Data.KIDHex)
	}
	if report.Data.KVNHex != "0xFE" {
		t.Errorf("kvn_hex = %q, want 0xFE", report.Data.KVNHex)
	}
}

// TestSDKeysImportSCP03_ConfirmWrite_AuthFails: active path against
// the SCP03-unaware mock fails at 'open SCP03 session'. PUT KEY
// must NOT be recorded as PASS — same critical safety guard as
// delete and generate.
func TestSDKeysImportSCP03_ConfirmWrite_AuthFails(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	hex16 := strings.Repeat("AB", 16)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FE",
		"--new-scp03-enc", hex16,
		"--new-scp03-mac", hex16,
		"--new-scp03-dek", hex16,
		"--confirm-write",
	}
	err = cmdSDKeysImport(context.Background(), env, args)
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
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "PUT KEY SCP03") && strings.Contains(line, "PASS") {
			t.Errorf("PUT KEY recorded as PASS despite SCP03 open failure: %q", line)
		}
	}
	// And the key bytes must NEVER appear in output — even on
	// failure paths.
	if strings.Contains(out, hex16) {
		t.Errorf("output leaked imported key bytes on failure path:\n%s", out)
	}
}

// --- internal helpers ---

// TestImportCategoryForKID pins the dispatch table.
func TestImportCategoryForKID(t *testing.T) {
	cases := []struct {
		kid      byte
		category string
		phase    string
		ok       bool
	}{
		{0x01, "scp03-key-set", "5a", true},
		{0x10, "ca-trust-anchor", "5c", true},
		{0x11, "scp11-sd-key", "5b", true},
		{0x13, "scp11-sd-key", "5b", true},
		{0x15, "scp11-sd-key", "5b", true},
		{0x20, "ca-trust-anchor", "5c", true},
		{0x2F, "ca-trust-anchor", "5c", true},
		{0x12, "", "", false}, // gap in the SCP11 range
		{0x14, "", "", false}, // gap
		{0x16, "", "", false},
		{0x30, "", "", false},
		{0xFF, "", "", false},
	}
	for _, tc := range cases {
		gotCat, gotPhase, gotOK := importCategoryForKID(tc.kid)
		if gotOK != tc.ok || gotCat != tc.category || gotPhase != tc.phase {
			t.Errorf("importCategoryForKID(0x%02X) = (%q, %q, %v), want (%q, %q, %v)",
				tc.kid, gotCat, gotPhase, gotOK,
				tc.category, tc.phase, tc.ok)
		}
	}
}

// TestPeekKIDFlag pins the lightweight flag-peek used for first-pass
// KID extraction. Both `--kid 11` and `--kid=11` forms must work;
// missing or empty values are clear errors.
func TestPeekKIDFlag(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    byte
		wantErr bool
	}{
		{"separate", []string{"--kid", "11"}, 0x11, false},
		{"equals", []string{"--kid=01"}, 0x01, false},
		{"with other flags", []string{"--reader", "x", "--kid", "13", "--kvn", "01"}, 0x13, false},
		{"missing", []string{"--kvn", "01"}, 0, true},
		{"value-less", []string{"--kid"}, 0, true},
		{"bad value", []string{"--kid", "ZZ"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := peekKIDFlag(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("peekKIDFlag(%v) err = %v, wantErr = %v",
					tc.args, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("peekKIDFlag(%v) = 0x%02X, want 0x%02X",
					tc.args, got, tc.want)
			}
		})
	}
}
