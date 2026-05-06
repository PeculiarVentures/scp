package securitydomain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

func openLoadFilesSession(t *testing.T) (*securitydomain.Session, *mockcard.SCP03Card) {
	t.Helper()
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{
		{
			AID:       []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01},
			Lifecycle: 0x01,
		},
	}
	sess, err := securitydomain.OpenSCP03(context.Background(), mc.Transport(), &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: 0xFF,
	})
	if err != nil {
		t.Fatalf("OpenSCP03: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess, mc
}

// failGetStatusScope returns a one-shot fault that rejects GET
// STATUS (INS=0xF2) with the given scope byte (P1) and supplies
// the configured SW. Match is on INS+P1; P2 is unconstrained.
func failGetStatusScope(p1 byte, sw uint16) *mockcard.Fault {
	return &mockcard.Fault{
		Match: func(cmd *apdu.Command) bool {
			return cmd.INS == 0xF2 && cmd.P1 == p1
		},
		Response: &apdu.Response{SW1: byte(sw >> 8), SW2: byte(sw)},
		Once:     true,
	}
}

// TestGetStatusLoadFiles_PrefersLoadFilesAndModules: when the
// card accepts both scopes, the helper returns the
// LoadFilesAndModules path and reports that scope in the result.
func TestGetStatusLoadFiles_PrefersLoadFilesAndModules(t *testing.T) {
	sess, _ := openLoadFilesSession(t)

	res, err := sess.GetStatusLoadFiles(context.Background())
	if err != nil {
		t.Fatalf("GetStatusLoadFiles: %v", err)
	}
	if res.Scope != securitydomain.StatusScopeLoadFilesAndModules {
		t.Errorf("scope = %v, want StatusScopeLoadFilesAndModules", res.Scope)
	}
	if len(res.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(res.Entries))
	}
}

// TestGetStatusLoadFiles_FallsBackOn6A86: card rejects
// LoadFilesAndModules with 6A86 (incorrect P1/P2); helper retries
// with LoadFiles-only.
func TestGetStatusLoadFiles_FallsBackOn6A86(t *testing.T) {
	sess, mc := openLoadFilesSession(t)
	mc.AddFault(failGetStatusScope(0x10, 0x6A86))

	res, err := sess.GetStatusLoadFiles(context.Background())
	if err != nil {
		t.Fatalf("GetStatusLoadFiles (with fallback): %v", err)
	}
	if res.Scope != securitydomain.StatusScopeLoadFiles {
		t.Errorf("scope = %v, want fallback to StatusScopeLoadFiles", res.Scope)
	}
	if len(res.Entries) != 1 {
		t.Errorf("entries = %d, want 1 (load file from registry)", len(res.Entries))
	}
}

// TestGetStatusLoadFiles_FallsBackOn6D00: SW=6D00 (INS not
// supported on this CLA) also triggers fallback.
func TestGetStatusLoadFiles_FallsBackOn6D00(t *testing.T) {
	sess, mc := openLoadFilesSession(t)
	mc.AddFault(failGetStatusScope(0x10, 0x6D00))

	res, err := sess.GetStatusLoadFiles(context.Background())
	if err != nil {
		t.Fatalf("GetStatusLoadFiles: %v", err)
	}
	if res.Scope != securitydomain.StatusScopeLoadFiles {
		t.Errorf("scope = %v, want fallback", res.Scope)
	}
}

// TestGetStatusLoadFiles_NonRetryableSWPropagates: SW=6982
// (security status not satisfied) is auth missing, not
// unsupported scope. The helper must NOT retry; the caller
// needs to know authentication is the issue.
func TestGetStatusLoadFiles_NonRetryableSWPropagates(t *testing.T) {
	sess, mc := openLoadFilesSession(t)
	mc.AddFault(failGetStatusScope(0x10, 0x6982))

	_, err := sess.GetStatusLoadFiles(context.Background())
	if err == nil {
		t.Fatal("expected 6982 to propagate, not silently fall back")
	}
	var ae *securitydomain.APDUError
	if !errors.As(err, &ae) || ae.SW != 0x6982 {
		t.Errorf("err should wrap APDUError SW=6982: %v", err)
	}
}
