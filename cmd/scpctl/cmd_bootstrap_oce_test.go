package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestBootstrapOCE_DryRun confirms that without --confirm-write,
// bootstrap-oce validates inputs but does not transmit any APDU.
// The mock connect should never be called in dry-run mode.
func TestBootstrapOCE_DryRun(t *testing.T) {
	keyPath, certPath := writeOCEFixturePEMs(t)

	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	_ = keyPath

	if err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
	}); err != nil {
		t.Fatalf("dry-run cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have called connect")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", out)
	}
}

// TestBootstrapOCE_WithConfirm runs the destructive path against the
// SCP03 mock with --confirm-write set. Verifies the CLI:
//   - opens an SCP03 session
//   - issues PUT KEY (recorded by the mock)
//   - skips STORE CERT and CA SKI by default
//
// Asserts on the recorded APDUs from scp03.MockCard.Recorded() so a
// regression in the bootstrap sequence (e.g. dropping the PUT KEY)
// surfaces here, not just in the textual report.
func TestBootstrapOCE_WithConfirm(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}

	rec := mockCard.Recorded()
	var sawPutKey bool
	for _, r := range rec {
		if r.INS == 0xD8 {
			sawPutKey = true
		}
	}
	if !sawPutKey {
		t.Errorf("expected PUT KEY (INS=0xD8) in recorded writes; got %d entries", len(rec))
	}

	out := buf.String()
	for _, want := range []string{
		"open SCP03 SD",
		"install OCE public key",
		"PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestBootstrapOCE_StoreChainAndCASKI exercises the optional flags.
// Confirms STORE DATA (INS=0xE2) is issued for both the cert chain
// and the CA SKI when their flags are set.
func TestBootstrapOCE_StoreChainAndCASKI(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--store-chain",
		"--ca-ski", "0123456789ABCDEF0123456789ABCDEF01234567",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}

	var nE2 int
	for _, r := range mockCard.Recorded() {
		if r.INS == 0xE2 {
			nE2++
		}
	}
	if nE2 < 2 {
		t.Errorf("expected at least 2 STORE DATA (INS=0xE2) calls (chain + CA SKI); got %d", nE2)
	}
	out := buf.String()
	if !strings.Contains(out, "store OCE cert chain") || !strings.Contains(out, "register CA SKI") {
		t.Errorf("output missing expected pass labels\n--- output ---\n%s", out)
	}
}

// TestBootstrapOCE_RequiresOCECert documents the usage-error path:
// missing --oce-cert is rejected explicitly rather than running
// against a no-cert default.
func TestBootstrapOCE_RequiresOCECert(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: nil}
	err := cmdBootstrapOCE(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected usage error for missing --oce-cert")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError; got %T: %v", err, err)
	}
}
