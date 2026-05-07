package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

func runGPDelete(t *testing.T, makeTransport func() transport.Transport, args []string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return makeTransport(), nil
		},
	}
	err := cmdGPDelete(context.Background(), env, args)
	return buf.String(), err
}

// --- input validation ---------------------------------------------------

func TestGPDelete_RequiresAID(t *testing.T) {
	_, err := runGPDelete(t, nil, []string{"--scp03-keys-default"})
	if err == nil {
		t.Fatal("expected error when --aid missing")
	}
	if !strings.Contains(err.Error(), "--aid") {
		t.Errorf("error should mention --aid: %v", err)
	}
}

func TestGPDelete_RequiresExplicitSCP03KeyChoice(t *testing.T) {
	_, err := runGPDelete(t, nil, []string{"--aid", "D2760001240101"})
	if err == nil {
		t.Fatal("expected error when no SCP03 key choice")
	}
	if !strings.Contains(err.Error(), "explicit SCP03 key choice") {
		t.Errorf("error should mention key choice: %v", err)
	}
}

func TestGPDelete_RejectsMalformedAID(t *testing.T) {
	out, err := runGPDelete(t,
		func() transport.Transport { return mockcard.NewSCP03Card(scp03.DefaultKeys).Transport() },
		[]string{
			"--aid", "AB", // 1 byte
			"--scp03-keys-default",
		})
	if err == nil {
		t.Fatal("expected error for AID too short")
	}
	if !strings.Contains(out, "aid") {
		t.Errorf("output should mention aid validation:\n%s", out)
	}
}

// --- dry-run ------------------------------------------------------------

func TestGPDelete_DryRun_DoesNotMutateCard(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}, Lifecycle: 0x07},
	}

	out, err := runGPDelete(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--aid", "D27600012401 01",
			"--scp03-keys-default",
			"--reader", "fake",
		})
	if err != nil {
		t.Fatalf("dry-run delete: %v\n--- output ---\n%s", err, out)
	}
	if !strings.Contains(out, "SKIP") {
		t.Errorf("dry-run output should contain SKIP:\n%s", out)
	}
	if len(mc.RegistryApps) != 1 {
		t.Errorf("dry-run mutated card: %v", mc.RegistryApps)
	}
}

// --- end-to-end ---------------------------------------------------------

func TestGPDelete_ConfirmWrite_RemovesApplet(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}, Lifecycle: 0x07},
	}

	out, err := runGPDelete(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--confirm-write",
		})
	if err != nil {
		t.Fatalf("delete failed: %v\n--- output ---\n%s", err, out)
	}
	if !strings.Contains(out, "DELETE") {
		t.Errorf("output should mention DELETE:\n%s", out)
	}
	if len(mc.RegistryApps) != 0 {
		t.Errorf("applet should be removed: %v", mc.RegistryApps)
	}
}

func TestGPDelete_ConfirmWrite_MissingAID_ReportsSW6A88(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	// Empty registries: any DELETE will hit 6A88.

	out, err := runGPDelete(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--aid", "FFFFFFFFFFFF",
			"--scp03-keys-default",
			"--reader", "fake",
			"--confirm-write",
		})
	if err == nil {
		t.Fatalf("expected delete to fail with 6A88; output:\n%s", out)
	}
	if !strings.Contains(out, "6A88") {
		t.Errorf("output should report SW=6A88:\n%s", out)
	}
}

func TestGPDelete_ConfirmWrite_RelatedCascades(t *testing.T) {
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}

	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{{AID: loadAID, Lifecycle: 0x01}}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: appletAID, Lifecycle: 0x07, AssociatedSDAID: loadAID},
	}

	out, err := runGPDelete(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--aid", "D27600012401",
			"--related",
			"--scp03-keys-default",
			"--reader", "fake",
			"--confirm-write",
		})
	if err != nil {
		t.Fatalf("delete with cascade: %v\n--- output ---\n%s", err, out)
	}
	if !strings.Contains(out, "cascade") {
		t.Errorf("output should mention cascade:\n%s", out)
	}
	if len(mc.RegistryLoadFiles) != 0 || len(mc.RegistryApps) != 0 {
		t.Errorf("cascade should empty both registries; load=%v apps=%v",
			mc.RegistryLoadFiles, mc.RegistryApps)
	}
}
