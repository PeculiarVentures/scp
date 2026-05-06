package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDLock_DryRunByDefault confirms 'sd lock' without --confirm-write
// reads the pre-state but does NOT open SCP03 or transmit SET STATUS.
// The output must mention dry-run and reference the gate flag so an
// operator can immediately see how to actually lock.
func TestSDLock_DryRunByDefault(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, Lifecycle: 0x0F},
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDLock(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDLock dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"read pre-lock state",
		"SECURED",
		"dry-run",
		"--confirm-write",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Lock-completion language must NOT appear in dry-run output.
	if strings.Contains(out, "transitioned to CARD_LOCKED") {
		t.Errorf("dry-run output should not announce destructive completion\n--- output ---\n%s", out)
	}
}

// TestSDLock_AlreadyLocked_SkipsTransition: the pre-flight check
// must short-circuit when the card is already CARD_LOCKED. The
// transition would be a no-op on a real card, but the SCP layer
// would see SW=6985 and surface a confusing error. Skipping with a
// clear "already locked" message is the right operator UX.
func TestSDLock_AlreadyLocked_SkipsTransition(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, Lifecycle: 0x7F},
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDLock(context.Background(), env, []string{
		"--reader", "fake", "--confirm-write",
	}); err != nil {
		t.Fatalf("cmdSDLock: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "already CARD_LOCKED") {
		t.Errorf("output should announce idempotent skip; got:\n%s", out)
	}
	if strings.Contains(out, "transitioned to CARD_LOCKED") {
		t.Errorf("idempotent path should not report a transition; got:\n%s", out)
	}
}

// TestSDLock_TerminatedCard_RefusesOutright: a TERMINATED card is
// irrecoverable. Pretending lock could do anything would mislead
// operators chasing recovery options that don't exist.
func TestSDLock_TerminatedCard_RefusesOutright(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, Lifecycle: 0xFF},
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	err = cmdSDLock(context.Background(), env, []string{
		"--reader", "fake", "--confirm-write",
	})
	if err == nil {
		t.Fatalf("cmdSDLock against TERMINATED card should fail; got nil error")
	}
	if !strings.Contains(err.Error(), "TERMINATED") {
		t.Errorf("error should mention TERMINATED; got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "irrecoverable") {
		t.Errorf("output should explain irrecoverability; got:\n%s", out)
	}
}

// TestSDLock_DoesNotConnectInDryRun would test that --confirm-write
// alone doesn't trigger a connect when the destructive path is gated
// behind dry-run. We DO connect to read pre-state, so the connect
// happens regardless. But the SCP03 open and SET STATUS must be
// skipped.
//
// Rather than try to inspect what didn't happen, we verify the
// observable: dry-run output must not contain any "SET STATUS"
// confirmation language and must contain dry-run language. That's
// covered above. This test instead checks that a connect failure
// before the pre-check propagates as an error rather than
// silently skipping.
func TestSDLock_ConnectFailure_Propagates(t *testing.T) {
	want := errors.New("simulated PC/SC failure")
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return nil, want
		},
	}
	err := cmdSDLock(context.Background(), env, []string{"--reader", "fake"})
	if !errors.Is(err, want) {
		t.Errorf("expected connect error to propagate; got: %v", err)
	}
}
