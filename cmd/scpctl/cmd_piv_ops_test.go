package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestPIVGroupReset_HappyPath_BlocksThenResets is a regression test
// for the bug rmhrisk hit on retail YubiKey 5.7.4: 'scpctl piv reset'
// was sending RESET without first blocking PIN and PUK, which on real
// hardware returned SW=6985. The fix has cmdPIVGroupReset call
// sess.BlockPIN + sess.BlockPUK before sess.Reset.
//
// The test pins the step structure exactly. If a future change drops
// one of the block steps or stops emitting the PASS line for it,
// this test fails loudly with a clear pointer to the regression class.
//
// Uses --raw-local-ok with a TrustBoundary-overriding wrapper so the
// mock transport satisfies the production raw-mode gate without
// spinning up a full SCP11b vs PIV session against the mock (which
// would require extensive SCP key fixture wiring outside the scope
// of this regression).
func TestPIVGroupReset_HappyPath_BlocksThenResets(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Make the probe identify this card as YubiKey 5.7.2. Without
	// this, probe falls through to StandardPIVProfile, which
	// doesn't advertise Reset → BlockPIN refuses on the first
	// attempt with ErrUnsupportedByProfile.
	mockCard.MockYubiKeyVersion = []byte{0x05, 0x07, 0x02}
	wrapped := &rawLocalAcknowledgedTransport{inner: mockCard.Transport()}

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return wrapped, nil
		},
	}

	err = cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
		"--confirm-reset-piv",
	})
	if err != nil {
		t.Fatalf("cmdPIVGroupReset: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"channel mode",
		"block PIN",
		"blocked after 3 wrong attempts",
		"block PUK",
		"PIV reset",
		"applet returned to factory state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("group reset output missing %q (regression on the SW=6985 fix)\n--- output ---\n%s",
				want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("group reset output contains FAIL\n--- output ---\n%s", out)
	}

	// Assert step ORDERING: block PIN → block PUK → PIV reset.
	// If a refactor reorders these, the YubiKey precondition is
	// violated even if every PASS line is still emitted.
	pinIdx := strings.Index(out, "block PIN")
	pukIdx := strings.Index(out, "block PUK")
	rstIdx := strings.Index(out, "PIV reset")
	if !(pinIdx >= 0 && pukIdx > pinIdx && rstIdx > pukIdx) {
		t.Errorf("group reset steps must be in order block PIN → block PUK → PIV reset; "+
			"got positions PIN=%d PUK=%d RESET=%d\n--- output ---\n%s",
			pinIdx, pukIdx, rstIdx, out)
	}
}

// TestPIVGroupReset_DryRunSkipsBlocks pins that the dry-run path
// (no --confirm-reset-piv) does NOT exhaust retry counters. The
// group command should announce what it would do and exit
// cleanly without any wire activity that decrements PIN/PUK
// counters; a stale-flag accident must never silently brick a
// card.
func TestPIVGroupReset_DryRunSkipsBlocks(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	if err := cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
		// no --confirm-reset-piv → dry-run
	}); err != nil {
		t.Fatalf("dry-run group reset should not error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "blocked after") {
		t.Errorf("dry-run must not have blocked PIN/PUK on the mock\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "applet returned to factory state") {
		t.Errorf("dry-run must not announce destructive completion\n--- output ---\n%s", out)
	}
}
