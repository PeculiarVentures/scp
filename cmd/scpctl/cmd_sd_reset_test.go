package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDReset_DryRunByDefault confirms `scpctl sd reset` without
// --confirm-reset-sd reads the inventory but does not transmit any
// mutating APDUs. The output should clearly indicate dry-run mode
// and reference the gate flag.
func TestSDReset_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDReset(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDReset (dry-run): %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"read pre-reset inventory",
		"PASS",
		"SD reset",
		"SKIP",
		"--confirm-reset-sd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Destructive language must NOT appear in dry-run output.
	if strings.Contains(out, "factory SCP03 keys restored") {
		t.Errorf("dry-run output should not announce destructive completion\n--- output ---\n%s", out)
	}
}

// TestSDReset_RequiresSpecificFlag confirms --confirm-write alone
// (without --confirm-reset-sd) does NOT trigger the destructive
// path. The spec is explicit that overloading --confirm-write
// across applet/SD scopes is a foot-gun.
func TestSDReset_RequiresSpecificFlag(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	// Pass --confirm-write but NOT --confirm-reset-sd. Either
	// outcome is acceptable: the command may reject --confirm-write
	// as an unknown flag, or it may run dry-run silently. What is
	// NOT acceptable is destructive completion. We assert on output
	// below rather than the error so both shapes pass.
	_ = cmdSDReset(context.Background(), env, []string{
		"--reader", "fake",
		"--confirm-write",
	})
	out := buf.String()
	if strings.Contains(out, "factory SCP03 keys restored") {
		t.Errorf("--confirm-write alone should not trigger destructive reset\n--- output ---\n%s", out)
	}
}

// TestSDReset_DestructivePath_PassesGate confirms that with
// --confirm-reset-sd, the command runs the reset and reports the
// post-reset inventory. The mockcard happens to advertise only the
// factory SCP03 key in its KIT, so post-reset inventory matches
// the pre-reset one — that's fine; the test is about the gate
// flow, not the card-side simulation.
func TestSDReset_DestructivePath_PassesGate(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDReset(context.Background(), env, []string{
		"--reader", "fake",
		"--confirm-reset-sd",
	}); err != nil {
		t.Fatalf("cmdSDReset (destructive): %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"read pre-reset inventory",
		"SD reset",
		"PASS",
		"factory SCP03 keys restored",
		"read post-reset inventory",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("destructive output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Must not contain SKIP for the SD reset step itself.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SD reset") && strings.Contains(line, "SKIP") {
			t.Errorf("SD reset should not be skipped when --confirm-reset-sd is set; line: %q", line)
		}
	}
}
