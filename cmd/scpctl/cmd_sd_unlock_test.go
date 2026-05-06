package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDUnlock_DryRunByDefault confirms 'sd unlock' without
// --confirm-write reads the pre-state but does NOT transmit a
// transition. Pre-state is CARD_LOCKED so the dry-run path actually
// reaches the dry-run skip (rather than being short-circuited as
// "no transition needed").
func TestSDUnlock_DryRunByDefault(t *testing.T) {
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
	if err := cmdSDUnlock(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDUnlock dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"read pre-unlock state",
		"CARD_LOCKED",
		"dry-run",
		"--confirm-write",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "transitioned to SECURED") {
		t.Errorf("dry-run output should not announce destructive completion\n--- output ---\n%s", out)
	}
}

// TestSDUnlock_AlreadySecured_SkipsTransition: pre-state SECURED
// means "nothing to unlock"; same idempotent-skip pattern as 'sd
// lock against an already-locked card'. The skip must announce the
// current state so an operator who ran the wrong command (e.g.
// expected to find a lock) can spot the mismatch.
func TestSDUnlock_AlreadySecured_SkipsTransition(t *testing.T) {
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
	if err := cmdSDUnlock(context.Background(), env, []string{
		"--reader", "fake", "--confirm-write",
	}); err != nil {
		t.Fatalf("cmdSDUnlock: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "SECURED") {
		t.Errorf("output should mention SECURED; got:\n%s", out)
	}
	if !strings.Contains(out, "no transition needed") {
		t.Errorf("output should announce idempotent skip; got:\n%s", out)
	}
}

// TestSDUnlock_TerminatedCard_RefusesOutright: TERMINATED is
// irrecoverable; unlock must refuse explicitly rather than try and
// fail at the SET STATUS layer.
func TestSDUnlock_TerminatedCard_RefusesOutright(t *testing.T) {
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
	err = cmdSDUnlock(context.Background(), env, []string{
		"--reader", "fake", "--confirm-write",
	})
	if err == nil {
		t.Fatal("cmdSDUnlock against TERMINATED card should fail")
	}
	if !strings.Contains(err.Error(), "TERMINATED") {
		t.Errorf("error should mention TERMINATED; got: %v", err)
	}
}
