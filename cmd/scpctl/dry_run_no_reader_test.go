package main

// Tests asserting that 'sd keys generate', 'sd keys delete', and
// 'sd allowlist set/clear' run their dry-run paths to completion
// without invoking env.connect. This is a UX/testability fix:
// dry-runs should produce a preview of the planned APDUs without
// requiring a reader to be attached, so CI pipelines, code
// reviewers, and operators previewing changes against a card
// they don't have physical access to all see the same output.
//
// Each test installs a connect callback that fails the test if
// invoked (the dry-run path must not reach it). Without the fix
// this file accompanies, the connect callback would fire before
// the --confirm gate and dry-run would be unusable in
// reader-less environments.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/transport"
)

// failingConnectEnv builds a runEnv whose connect always fails.
// Any verb that calls env.connect during its dry-run path will
// surface as a test error.
func failingConnectEnv() (*runEnv, *bytes.Buffer) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return nil, errors.New("DRY-RUN-CONNECT-VIOLATION: env.connect was called during a dry-run path; this command should not require a reader when --confirm is absent")
		},
	}
	return env, &buf
}

// TestSDKeysGenerate_DryRunDoesNotConnect: 'sd keys generate'
// without --confirm-write must not call env.connect. The dry-run
// preview is a static "I would generate kid/kvn" message and
// has no reason to talk to a reader.
func TestSDKeysGenerate_DryRunDoesNotConnect(t *testing.T) {
	env, buf := failingConnectEnv()
	err := cmdSDKeysGenerate(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", t.TempDir() + "/dryrun.pem",
	})
	if err != nil {
		t.Fatalf("dry-run should succeed without connect; got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "DRY-RUN-CONNECT-VIOLATION") {
		t.Errorf("env.connect was called during dry-run path; output:\n%s", buf.String())
	}
}

// TestSDKeysDelete_DryRunDoesNotConnect: 'sd keys delete' without
// --confirm-delete-key must not call env.connect. The orphan-auth
// preflight that DOES inspect the card runs only on the
// confirmed-destructive path, which is the right design — dry-run
// is a what-will-happen preview, not a what-can-happen check.
func TestSDKeysDelete_DryRunDoesNotConnect(t *testing.T) {
	env, buf := failingConnectEnv()
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
	})
	if err != nil {
		t.Fatalf("dry-run should succeed without connect; got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "DRY-RUN-CONNECT-VIOLATION") {
		t.Errorf("env.connect was called during dry-run path; output:\n%s", buf.String())
	}
}

// TestSDAllowlistSet_DryRunDoesNotConnect: 'sd allowlist set'
// without --confirm-write must not call env.connect. The
// canonical serial list is computed entirely from --serials
// input bytes; no card interaction is needed for the preview.
func TestSDAllowlistSet_DryRunDoesNotConnect(t *testing.T) {
	env, buf := failingConnectEnv()
	err := cmdSDAllowlistSet(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--serial", "1", "--serial", "2", "--serial", "3",
	})
	if err != nil {
		t.Fatalf("dry-run should succeed without connect; got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "DRY-RUN-CONNECT-VIOLATION") {
		t.Errorf("env.connect was called during dry-run path; output:\n%s", buf.String())
	}
}

// TestSDAllowlistClear_DryRunDoesNotConnect: 'sd allowlist clear'
// without --confirm-write — symmetric with set.
func TestSDAllowlistClear_DryRunDoesNotConnect(t *testing.T) {
	env, buf := failingConnectEnv()
	err := cmdSDAllowlistClear(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
	})
	if err != nil {
		t.Fatalf("dry-run should succeed without connect; got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "DRY-RUN-CONNECT-VIOLATION") {
		t.Errorf("env.connect was called during dry-run path; output:\n%s", buf.String())
	}
}

// TestSDKeysGenerate_ActivePathDoesConnect: the inverse direction
// — with --confirm-write, env.connect MUST fire. Captures the
// regression where the reorder accidentally skipped the connect
// call entirely on the confirmed path.
func TestSDKeysGenerate_ActivePathDoesConnect(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			// Fail the connect after recording the call so the
			// test stops here rather than running the full
			// generate against a real mock — we're only
			// asserting that connect is reached.
			return nil, fmt.Errorf("test stop after connect")
		},
	}
	_ = cmdSDKeysGenerate(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", t.TempDir() + "/active.pem",
		"--confirm-write",
	})
	if !connectCalled {
		t.Errorf("active path (--confirm-write) must call env.connect; output:\n%s", buf.String())
	}
}
