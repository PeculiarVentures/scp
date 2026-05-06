package main

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// --- sd allowlist set ---

// TestSDAllowlistSet_DryRunByDefault confirms the dry-run safety
// invariant: without --confirm-write, sd allowlist set validates
// inputs and reports the planned action without opening SCP03 or
// transmitting STORE DATA. Same dry-run pattern as sd lock / unlock /
// terminate; if a future change accidentally flips the default to
// active mode this test catches it.
func TestSDAllowlistSet_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--serial", "12345",
		"--serial", "0xCAFEBABE",
	}
	if err := cmdSDAllowlistSet(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDAllowlistSet dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd allowlist set",
		"dry-run",
		"--confirm-write",
		"2 serial(s)",
		"kid=0x11",
		"kvn=0x01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Active-write language must not appear in dry-run output.
	if strings.Contains(out, "installed") {
		t.Errorf("dry-run output should not announce destructive completion\n--- output ---\n%s", out)
	}
}

// TestSDAllowlistSet_DryRunSerialsCanonical verifies that the JSON
// data block carries the canonical decimal form of every supplied
// serial, regardless of whether the input was decimal or hex. Audit
// logs need a single representation; mixed-form inputs that happen
// to denote the same number should produce identical recorded values.
func TestSDAllowlistSet_DryRunSerialsCanonical(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--serial", "0xFF", // 255 in hex
		"--serial", "255", // same value in decimal
		"--json",
	}
	if err := cmdSDAllowlistSet(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDAllowlistSet: %v\n%s", err, buf.String())
	}

	var report struct {
		Data struct {
			Serials []string `json:"serials"`
		} `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if len(report.Data.Serials) != 2 {
		t.Fatalf("serials length = %d, want 2", len(report.Data.Serials))
	}
	for i, s := range report.Data.Serials {
		if s != "255" {
			t.Errorf("serials[%d] = %q, want canonical decimal %q", i, s, "255")
		}
	}
}

// TestSDAllowlistSet_RequiresAtLeastOneSerial pins the design rule
// that an empty --serial set is rejected. The wire effect would be
// identical to clear, but the operator's intent is ambiguous; force
// them to use 'sd allowlist clear' so the audit log records the
// right verb.
func TestSDAllowlistSet_RequiresAtLeastOneSerial(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "11", "--kvn", "01", "--confirm-write"}
	err = cmdSDAllowlistSet(context.Background(), env, args)
	if err == nil {
		t.Fatal("expected usageError for empty --serial set, got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "clear") {
		t.Errorf("error should redirect operator to 'sd allowlist clear'; got %v", err)
	}
}

// TestSDAllowlistSet_RequiresKIDAndKVN verifies missing required
// flags produce a usageError, not a generic error.
func TestSDAllowlistSet_RequiresKIDAndKVN(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no flags", []string{}},
		{"missing kvn", []string{"--kid", "11", "--serial", "1"}},
		{"missing kid", []string{"--kvn", "01", "--serial", "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDAllowlistSet(context.Background(), env, tc.args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
		})
	}
}

// TestSDAllowlistSet_BadSerial verifies non-numeric and negative
// --serial values produce a usageError naming the offending token.
func TestSDAllowlistSet_BadSerial(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"alpha", "not-a-number"},
		{"empty hex", "0x"},
		{"bad hex", "0xZZZ"},
		{"negative", "-5"},
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
				"--kid", "11", "--kvn", "01",
				"--serial", tc.token,
			}
			err = cmdSDAllowlistSet(context.Background(), env, args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
			// The error message must echo the bad token verbatim so
			// the operator sees which input failed.
			if !strings.Contains(err.Error(), tc.token) {
				t.Errorf("error should echo %q verbatim; got %v", tc.token, err)
			}
		})
	}
}

// TestSDAllowlistSet_ConfirmWrite_AuthFails exercises the active path
// against a mock that does not speak SCP03. The handshake fails, and
// the report records a FAIL on 'open SCP03 session' — distinguishing
// the auth-failure case from a usage error or transport error. The
// active-mode branch is exercised even though no real STORE DATA can
// be transmitted.
func TestSDAllowlistSet_ConfirmWrite_AuthFails(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--serial", "1",
		"--confirm-write",
	}
	err = cmdSDAllowlistSet(context.Background(), env, args)
	if err == nil {
		t.Fatalf("expected SCP03 open failure against SCP03-unaware mock; got success:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "open SCP03 session") {
		t.Errorf("expected 'open SCP03 session' check line; got:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL for SCP03 open; got:\n%s", out)
	}
	// Must not have transmitted STORE DATA — that comes after a
	// successful open.
	if strings.Contains(out, "STORE DATA allowlist kid=") && strings.Contains(out, "PASS") {
		t.Errorf("STORE DATA should not have been recorded as PASS when SCP03 open failed; got:\n%s", out)
	}
}

// --- sd allowlist clear ---

// TestSDAllowlistClear_DryRunByDefault mirrors the set test for the
// clear verb. Specifically checks that the dry-run text warns the
// operator that 'clear' means 'accept any cert from the CA,' NOT
// 'reject all certs' — a real foot-gun for someone who's pattern-
// matching on the verb name.
func TestSDAllowlistClear_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "11", "--kvn", "01"}
	if err := cmdSDAllowlistClear(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDAllowlistClear dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd allowlist clear",
		"dry-run",
		"--confirm-write",
		"any certificate signed by the associated CA",
		"NOT", // the warning that clear ≠ deny-all
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDAllowlistClear_RequiresKIDAndKVN: same flag-validation
// surface as set.
func TestSDAllowlistClear_RequiresKIDAndKVN(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no flags", []string{}},
		{"missing kvn", []string{"--kid", "11"}},
		{"missing kid", []string{"--kvn", "01"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDAllowlistClear(context.Background(), env, tc.args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError", err)
			}
		})
	}
}

// --- internal helpers ---

// TestParseSerial pins the input grammar for --serial values:
// decimal, 0x-prefixed hex, both case-insensitive on the prefix;
// negative and malformed values are rejected.
func TestParseSerial(t *testing.T) {
	cases := []struct {
		in      string
		want    *big.Int
		wantErr bool
	}{
		{"0", big.NewInt(0), false},
		{"1", big.NewInt(1), false},
		{"255", big.NewInt(255), false},
		{"0xFF", big.NewInt(255), false},
		{"0xff", big.NewInt(255), false},
		{"0XFF", big.NewInt(255), false},
		{"", nil, true},
		{"-1", nil, true},
		{"abc", nil, true},
		{"0x", nil, true},
		{"0xZZZ", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSerial(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseSerial(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got.Cmp(tc.want) != 0 {
				t.Errorf("parseSerial(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
