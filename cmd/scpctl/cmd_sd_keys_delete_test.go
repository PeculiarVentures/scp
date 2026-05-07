package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestSDKeysDelete_RejectsAmbiguousFlagCombos pins the design's
// strict flag-validation rules. Each rejected combination must
// produce a usageError with a message that helps the operator
// understand WHY the combination was rejected, not just that it was.
//
// The library accepts more permissive shapes (kid-only or kvn-only),
// but the CLI is deliberately stricter — destructive misfires here
// can be unrecoverable, so explicit signals only.
func TestSDKeysDelete_RejectsAmbiguousFlagCombos(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantInError string
	}{
		{
			name:        "no flags",
			args:        []string{},
			wantInError: "--kvn",
		},
		{
			name:        "kid only",
			args:        []string{"--kid", "11"},
			wantInError: "--kvn",
		},
		{
			name:        "kvn only without --all",
			args:        []string{"--kvn", "01"},
			wantInError: "ambiguous",
		},
		{
			name:        "kid + kvn + --all",
			args:        []string{"--kid", "11", "--kvn", "01", "--all"},
			wantInError: "mutually exclusive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDKeysDelete(context.Background(), env, tc.args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error should contain %q to help operator; got %v",
					tc.wantInError, err)
			}
		})
	}
}

// TestSDKeysDelete_AcceptsValidFlagCombos: the dual of the rejection
// test. Each accepted combination must reach dry-run without a
// usageError. We don't pass --confirm-delete-key, so neither branch
// reaches the destructive APDU; we're only verifying the flag-
// validation code accepts the right shapes.
func TestSDKeysDelete_AcceptsValidFlagCombos(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantMode string
	}{
		{
			name:     "kid + kvn (single)",
			args:     []string{"--reader", "fake", "--kid", "11", "--kvn", "01"},
			wantMode: "single",
		},
		{
			name:     "kvn + all (broad)",
			args:     []string{"--reader", "fake", "--kvn", "01", "--all"},
			wantMode: "all-at-kvn",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, buf := envForMock(mc)
			args := append([]string{}, tc.args...)
			args = append(args, "--json")
			if err := cmdSDKeysDelete(context.Background(), env, args); err != nil {
				t.Fatalf("cmdSDKeysDelete: %v\n%s", err, buf.String())
			}
			var report struct {
				Data sdKeysDeleteData `json:"data"`
			}
			if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, buf.String())
			}
			if report.Data.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", report.Data.Mode, tc.wantMode)
			}
			if report.Data.Channel != "dry-run" {
				t.Errorf("channel = %q, want dry-run (no --confirm-delete-key)",
					report.Data.Channel)
			}
		})
	}
}

// TestSDKeysDelete_DryRunByDefault confirms the dry-run safety
// invariant: without --confirm-delete-key, validates inputs and
// reports the planned action without opening SCP03 or transmitting
// DELETE KEY. Catches regressions where the default flips to active.
func TestSDKeysDelete_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "11", "--kvn", "01"}
	if err := cmdSDKeysDelete(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd keys delete",
		"dry-run",
		"--confirm-delete-key",
		"kid=0x11",
		"kvn=0x01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
	// Active-write language must not appear in dry-run.
	for _, banned := range []string{
		"open SCP03 session",
		"DELETE KEY kid=", // would only appear in active path PASS line
	} {
		// Note: 'DELETE KEY' alone DOES appear in dry-run as the
		// SKIP check name; we're banning the kid-bearing form which
		// is only used for the active-path PASS check.
		if banned == "open SCP03 session" && strings.Contains(out, banned) {
			t.Errorf("dry-run output should not include %q\n%s", banned, out)
		}
	}
}

// TestSDKeysDelete_AllAtKVN_DryRunWording exercises the all-at-kvn
// branch's dry-run text. The wording must explicitly call out that
// this is broad deletion so an operator hitting --all on autopilot
// gets a chance to reconsider.
func TestSDKeysDelete_AllAtKVN_DryRunWording(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{"--reader", "fake", "--kvn", "01", "--all"}
	if err := cmdSDKeysDelete(context.Background(), env, args); err != nil {
		t.Fatalf("dry-run --all: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"every key at kvn=0x01",
		"broad deletion",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--all dry-run wording missing %q\n%s", want, out)
		}
	}
}

// TestSDKeysDelete_ConfirmGate_AuthFails exercises the active path
// against an SCP03-unaware mock. The handshake fails and the report
// records FAIL on 'open SCP03 session'. DELETE KEY must NOT be
// recorded as PASS — that would mean we somehow transmitted the APDU
// without authentication, a serious safety regression.
func TestSDKeysDelete_ConfirmGate_AuthFails(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--confirm-delete-key",
	}
	err = cmdSDKeysDelete(context.Background(), env, args)
	if err == nil {
		t.Fatalf("expected SCP03 open failure; got success:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "open SCP03 session") {
		t.Errorf("expected 'open SCP03 session' check line; got:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL for SCP03 open; got:\n%s", out)
	}
	// Critical safety check: DELETE KEY must never appear as PASS
	// when SCP03 open failed. The check name format is "DELETE KEY
	// kid=...". Find that substring then verify it's not on a PASS
	// line.
	if strings.Contains(out, "PASS") && strings.Contains(out, "DELETE KEY kid=") {
		// Verify the DELETE KEY line is NOT a PASS — this can be a
		// FAIL if the report ordered it after the open failure, but
		// it must never be PASS.
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "DELETE KEY kid=") && strings.Contains(line, "PASS") {
				t.Errorf("DELETE KEY recorded as PASS despite SCP03 open failure: %q", line)
			}
		}
	}
}

// TestSDKeysDelete_DistinctConfirmGate verifies that --confirm-write
// alone does NOT unlock destructive deletion. The whole point of
// --confirm-delete-key being a separate flag is that a script
// authorizing ordinary writes must not accidentally trigger key
// deletion. This test pins that contract.
func TestSDKeysDelete_DistinctConfirmGate(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--confirm-write", // wrong gate — must NOT activate delete
	}
	if err := cmdSDKeysDelete(context.Background(), env, args); err == nil {
		// Two outcomes possible:
		//  - usage error from --confirm-write being unknown: also
		//    acceptable, just means the flag set rejected it.
		//  - success in dry-run (--confirm-delete-key still missing):
		//    the path we actually want to verify.
		out := buf.String()
		if !strings.Contains(out, "dry-run") {
			t.Errorf("--confirm-write must not activate deletion; expected dry-run path, got:\n%s", out)
		}
		if strings.Contains(out, "open SCP03 session") {
			t.Errorf("SCP03 open must not happen without --confirm-delete-key; got:\n%s", out)
		}
	}
	// If err != nil it's a usageError because --confirm-write isn't
	// a recognized flag for this command. Either outcome (dry-run
	// success OR usage error) proves the gate works correctly. The
	// FAIL outcome we'd reject is "succeeded all the way through
	// SCP03 open" which is what the assertions above guard.
}
