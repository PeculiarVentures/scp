package main

import (
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestGPInstall_ExpectedCardID_Match: the card's CIN matches the
// pin; install proceeds normally.
func TestGPInstall_ExpectedCardID_Match(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.CIN = []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF}

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--expected-card-id", "CAFEBABEDEADBEEF",
			"--confirm-write",
		})
	if err != nil {
		t.Fatalf("install with matching CIN failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "expected-card-id") {
		t.Errorf("output should record the CIN check:\n%s", out)
	}
	if !strings.Contains(out, "matched CIN") {
		t.Errorf("output should mention CIN match:\n%s", out)
	}
	if len(mc.RegistryApps) != 1 {
		t.Errorf("expected applet registered after matching CIN check")
	}
}

// TestGPInstall_ExpectedCardID_Mismatch: the CIN does NOT match
// the pin; install aborts before any destructive APDU.
func TestGPInstall_ExpectedCardID_Mismatch(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.CIN = []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--expected-card-id", "CAFEBABEDEADBEEF",
			"--confirm-write",
		})
	if err == nil {
		t.Fatalf("install should have aborted on CIN mismatch; output:\n%s", out)
	}
	if !strings.Contains(out, "CIN mismatch") {
		t.Errorf("output should report CIN mismatch:\n%s", out)
	}
	// Card must be unchanged.
	if len(mc.RegistryLoadFiles) != 0 || len(mc.RegistryApps) != 0 {
		t.Errorf("CIN mismatch should have prevented all card mutation: load=%v apps=%v",
			mc.RegistryLoadFiles, mc.RegistryApps)
	}
}

// TestGPInstall_ExpectedCardID_AbsentCIN: card does not expose
// CIN. The install aborts because the operator's pin cannot be
// satisfied.
func TestGPInstall_ExpectedCardID_AbsentCIN(t *testing.T) {
	path := writeFixtureCAP(t)
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	// No CIN set.

	out, err := runGPInstall(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--cap", path,
			"--applet-aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--expected-card-id", "CAFEBABE",
			"--confirm-write",
		})
	if err == nil {
		t.Fatalf("install should have aborted when CIN absent; output:\n%s", out)
	}
	if !strings.Contains(out, "does not expose CIN") {
		t.Errorf("output should explain CIN absence:\n%s", out)
	}
	if len(mc.RegistryLoadFiles) != 0 || len(mc.RegistryApps) != 0 {
		t.Errorf("absent CIN should have prevented mutation: load=%v apps=%v",
			mc.RegistryLoadFiles, mc.RegistryApps)
	}
}

// TestGPDelete_ExpectedCardID_Mismatch: same protective behavior
// on the delete path.
func TestGPDelete_ExpectedCardID_Mismatch(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.CIN = []byte{0xFF}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}, Lifecycle: 0x07},
	}

	out, err := runGPDelete(t,
		func() transport.Transport { return mc.Transport() },
		[]string{
			"--aid", "D2760001240101",
			"--scp03-keys-default",
			"--reader", "fake",
			"--expected-card-id", "AABBCC",
			"--confirm-write",
		})
	if err == nil {
		t.Fatalf("delete should have aborted on CIN mismatch; output:\n%s", out)
	}
	if !strings.Contains(out, "CIN mismatch") {
		t.Errorf("output should report CIN mismatch:\n%s", out)
	}
	if len(mc.RegistryApps) != 1 {
		t.Errorf("CIN mismatch should have prevented delete: %v", mc.RegistryApps)
	}
}
