package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDTerminate_DryRunByDefault confirms 'sd terminate' without
// --confirm-terminate-card reads the pre-state but does NOT
// transmit SET STATUS. The dry-run output must surface the
// IRREVERSIBLE language so an operator scanning history doesn't
// confuse this with a reversible operation.
func TestSDTerminate_DryRunByDefault(t *testing.T) {
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
	if err := cmdSDTerminate(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDTerminate dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"read pre-terminate state",
		"SECURED",
		"dry-run",
		"--confirm-terminate-card",
		"IRREVERSIBLE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "transitioned to TERMINATED") {
		t.Errorf("dry-run output should not announce destructive completion\n--- output ---\n%s", out)
	}
}

// TestSDTerminate_RequiresSpecificFlag: --confirm-write alone (the
// flag used by lock/unlock) must NOT trigger the destructive path.
// Overloading a single confirm flag across reversible and
// irreversible operations is the foot-gun this test pins against.
func TestSDTerminate_RequiresSpecificFlag(t *testing.T) {
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

	// --confirm-write should not be recognized as a terminate
	// confirmation. Pass it alone and assert dry-run still wins.
	err = cmdSDTerminate(context.Background(), env, []string{
		"--reader", "fake", "--confirm-write",
	})
	if err != nil {
		// flag.Parse will reject unknown flags; this is the expected
		// failure mode and is itself a useful safety property.
		if !strings.Contains(err.Error(), "flag provided but not defined: -confirm-write") {
			t.Errorf("unexpected error from --confirm-write to terminate: %v", err)
		}
		return
	}
	// If the flag parser accepted it (it shouldn't), at minimum the
	// destructive path must not have been taken.
	out := buf.String()
	if strings.Contains(out, "transitioned to TERMINATED") {
		t.Errorf("--confirm-write triggered destructive terminate path; "+
			"only --confirm-terminate-card should: \n%s", out)
	}
}

// TestSDTerminate_AlreadyTerminated_SkipsIdempotently: pre-state
// TERMINATED means there is nothing left to do. Idempotent skip
// rather than failure — the command's invariant "card is not
// authenticating after this" is already satisfied.
func TestSDTerminate_AlreadyTerminated_SkipsIdempotently(t *testing.T) {
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
	if err := cmdSDTerminate(context.Background(), env, []string{
		"--reader", "fake", "--confirm-terminate-card",
	}); err != nil {
		t.Fatalf("cmdSDTerminate against already-TERMINATED card "+
			"should idempotently succeed; got: %v\n--- output ---\n%s",
			err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "already TERMINATED") {
		t.Errorf("output should announce idempotent skip; got:\n%s", out)
	}
	if strings.Contains(out, "SET STATUS") &&
		strings.Contains(out, "P2=0xFF") {
		t.Errorf("idempotent path should not report a SET STATUS transition; got:\n%s", out)
	}
}
