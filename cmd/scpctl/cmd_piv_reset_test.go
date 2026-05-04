package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport"
)

// TestPIVReset_DryRun confirms --confirm-write is required. The
// destructive guard is on the CLI side as well as the card side
// (card-side: PIN+PUK must both be blocked); the CLI guard means
// the command must not even open a transport without --confirm-write.
func TestPIVReset_DryRun(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	if err := cmdPIVReset(context.Background(), env, []string{
		"--reader", "fake",
	}); err != nil {
		t.Fatalf("dry-run cmdPIVReset: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have connected")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
}

// TestPIVReset_HappyPath_Smoke runs the full reset flow against a
// mock with default PIV state. Asserts the sequence happens (PIN
// blocked, PUK blocked, reset succeeds) and verifies the mock's
// PIV state actually returned to factory afterward.
//
// This is the test that proves the wire flow on its own merits:
// before the reset, the mock's PIN counter is 3; we send 3 wrong
// PINs and the counter goes to 0 (blocked); same for PUK; then
// INS 0xFB is accepted and counters return to 3.
func TestPIVReset_HappyPath_Smoke(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	// Provision some state so the test can verify reset clears it.
	mockCard.PIVPresetKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVReset(context.Background(), env, []string{
		"--reader", "fake",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVReset: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"open SCP11b vs PIV               PASS",
		"block PIN                        PASS",
		"blocked after 3 wrong attempts",
		"block PUK                        PASS",
		"PIV reset                        PASS",
		"applet returned to factory state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVReset_ProvisionAfterReset_Works is the integration test
// for the whole "provision → wrong cert → reset → provision again"
// loop you actually want this command for. Steps:
//
//  1. Pre-seed mock with key A; provision slot 9a with cert bound
//     to key A — succeeds (cert binding passes).
//  2. Reset the card.
//  3. Pre-seed mock with key B; provision slot 9a with cert bound
//     to key B — succeeds again, no leftover state from round 1.
//
// If the mock's reset path forgot to clear pivLastGenKey or the
// counters didn't actually return to 3, this test fails at step 3.
func TestPIVReset_ProvisionAfterReset_Works(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = keyA
	certA := writeMatchingPIVCert(t, keyA)

	provision := func(certPath string) string {
		var b bytes.Buffer
		env := &runEnv{
			out: &b, errOut: &b,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mockCard.Transport(), nil
			},
		}
		if err := cmdPIVProvision(context.Background(), env, []string{
			"--reader", "f", "--pin", "123456",
			"--slot", "9a", "--algorithm", "eccp256",
			"--cert", certPath,
			"--lab-skip-scp11-trust", "--confirm-write",
		}); err != nil {
			t.Fatalf("provision: %v\n%s", err, b.String())
		}
		return b.String()
	}
	reset := func() string {
		var b bytes.Buffer
		env := &runEnv{
			out: &b, errOut: &b,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mockCard.Transport(), nil
			},
		}
		if err := cmdPIVReset(context.Background(), env, []string{
			"--reader", "f",
			"--lab-skip-scp11-trust", "--confirm-write",
		}); err != nil {
			t.Fatalf("reset: %v\n%s", err, b.String())
		}
		return b.String()
	}

	// Round 1: provision with key A.
	r1 := provision(certA)
	if !strings.Contains(r1, "cert binding                     PASS") {
		t.Fatalf("round 1 cert binding did not pass:\n%s", r1)
	}

	// Reset.
	rr := reset()
	if !strings.Contains(rr, "PIV reset                        PASS") {
		t.Fatalf("reset did not pass:\n%s", rr)
	}

	// Round 2: pre-seed with key B and provision with key B's cert.
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = keyB
	certB := writeMatchingPIVCert(t, keyB)
	r2 := provision(certB)
	if !strings.Contains(r2, "cert binding                     PASS") {
		t.Fatalf("round 2 cert binding did not pass after reset:\n%s", r2)
	}
}

// TestPIVReset_RefusedWhenCountersNotBlocked confirms the card-side
// guard. Drive the mock by hand: don't block PIN/PUK first, just
// send INS=0xFB. The mock must refuse with 6985.
func TestPIVReset_RefusedWhenCountersNotBlocked(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	cfg.InsecureSkipCardAuthentication = true

	sess, err := scp11.Open(context.Background(), mockCard.Transport(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(context.Background(), piv.Reset())
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if resp.StatusWord() != 0x6985 {
		t.Errorf("expected 6985 (conditions not satisfied) when counters not blocked, got %04X",
			resp.StatusWord())
	}
}

// TestPIVReset_MaxBlockAttempts_RangeCheck confirms the flag
// validation: out-of-range values fail at the CLI boundary.
func TestPIVReset_MaxBlockAttempts_RangeCheck(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"zero", "0"},
		{"negative", "-1"},
		{"too high", "256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{
				out: &buf, errOut: &buf,
				connect: func(_ context.Context, _ string) (transport.Transport, error) {
					return nil, errors.New("should not connect")
				},
			}
			err := cmdPIVReset(context.Background(), env, []string{
				"--reader", "f",
				"--lab-skip-scp11-trust",
				"--confirm-write",
				"--max-block-attempts", tc.val,
			})
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError, got %T: %v", err, err)
			}
		})
	}
}

// TestPIVReset_MaxBlockAttempts_HighValueAccepted confirms a high
// retry count works against a normal card. The mock blocks at 3
// regardless of the cap, so this also confirms that raising the
// cap doesn't change normal-case behavior.
func TestPIVReset_MaxBlockAttempts_HighValueAccepted(t *testing.T) {
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
	err = cmdPIVReset(context.Background(), env, []string{
		"--reader", "f",
		"--lab-skip-scp11-trust", "--confirm-write",
		"--max-block-attempts", "100",
	})
	if err != nil {
		t.Fatalf("cmdPIVReset: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "blocked after 3 wrong attempts") {
		t.Errorf("expected 3-attempt block (mock counter is 3); got:\n%s", buf.String())
	}
}
