package securitydomain

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp11"
)

// --- ParsePrivileges -----------------------------------------------------

// TestParsePrivileges_AllBits flips every defined bit and checks each
// flag round-trips through Raw(). RFU bits in byte 3 (bits 4-1) are
// not exposed and are not expected to round-trip.
func TestParsePrivileges_AllBits(t *testing.T) {
	allOn := []byte{0xFF, 0xFF, 0xF0} // bits 4-1 of byte 3 are RFU
	p, err := ParsePrivileges(allOn)
	if err != nil {
		t.Fatalf("ParsePrivileges: %v", err)
	}
	want := Privileges{
		SecurityDomain: true, DAPVerification: true, DelegatedManagement: true,
		CardLock: true, CardTerminate: true, CardReset: true,
		CVMManagement: true, MandatedDAPVerification: true,
		TrustedPath: true, AuthorizedManagement: true, TokenVerification: true,
		GlobalDelete: true, GlobalLock: true, GlobalRegistry: true,
		FinalApplication: true, GlobalService: true,
		ReceiptGeneration: true, CipheredLoadFileDataBlock: true,
		ContactlessActivation: true, ContactlessSelfActivation: true,
	}
	if p != want {
		t.Errorf("decode of all-ones mismatch:\n got  %+v\n want %+v", p, want)
	}
	round := p.Raw()
	if !bytes.Equal(round[:], allOn) {
		t.Errorf("Raw() round-trip mismatch: got %X, want %X", round[:], allOn)
	}
}

// TestParsePrivileges_RoundTrip confirms an arbitrary privilege set
// round-trips through ParsePrivileges and Raw without bit drift.
func TestParsePrivileges_RoundTrip(t *testing.T) {
	original := Privileges{
		SecurityDomain:       true,
		AuthorizedManagement: true,
		CardReset:            true,
		ReceiptGeneration:    true,
	}
	raw := original.Raw()
	parsed, err := ParsePrivileges(raw[:])
	if err != nil {
		t.Fatalf("ParsePrivileges: %v", err)
	}
	if parsed != original {
		t.Errorf("round-trip mismatch:\n got  %+v\n want %+v", parsed, original)
	}
}

// TestParsePrivileges_WrongLength verifies the 3-byte length check
// rejects malformed input via ErrInvalidResponse.
func TestParsePrivileges_WrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 2, 4, 5} {
		_, err := ParsePrivileges(make([]byte, n))
		if err == nil {
			t.Errorf("len=%d: expected error, got nil", n)
			continue
		}
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("len=%d: errors.Is(err, ErrInvalidResponse) = false; got %v", n, err)
		}
	}
}

// TestPrivileges_String covers the human-readable rendering, including
// the (none) case.
func TestPrivileges_String(t *testing.T) {
	if got := (Privileges{}).String(); got != "(none)" {
		t.Errorf("empty Privileges.String() = %q, want %q", got, "(none)")
	}
	p := Privileges{SecurityDomain: true, AuthorizedManagement: true}
	got := p.String()
	if !contains(got, "SecurityDomain") || !contains(got, "AuthorizedManagement") {
		t.Errorf("String() missing names; got %q", got)
	}
}

func contains(s, substr string) bool { return bytes.Contains([]byte(s), []byte(substr)) }

// --- LifecycleString -----------------------------------------------------

func TestRegistryEntry_LifecycleString(t *testing.T) {
	cases := []struct {
		scope StatusScope
		life  byte
		want  string
	}{
		{StatusScopeISD, 0x0F, "SECURED"},
		{StatusScopeISD, 0x07, "INITIALIZED"},
		{StatusScopeISD, 0xFF, "TERMINATED"},
		{StatusScopeApplications, 0x07, "SELECTABLE"},
		{StatusScopeApplications, 0x83, "LOCKED"}, // high bit set
		{StatusScopeApplications, 0x0F, "PERSONALIZED"},
		{StatusScopeLoadFiles, 0x01, "LOADED"},
		{StatusScopeLoadFiles, 0x99, "unknown(0x99)"},
	}
	for _, tc := range cases {
		e := RegistryEntry{Scope: tc.scope, Lifecycle: tc.life}
		got := e.LifecycleString()
		if got != tc.want {
			t.Errorf("scope=%v life=0x%02X: got %q, want %q", tc.scope, tc.life, got, tc.want)
		}
	}
}

// --- GetStatus end-to-end via mockcard ----------------------------------

// openSCP11bAgainstMock opens an SCP11b session against the mock
// card with trust validation skipped. The test focus is GET STATUS
// semantics, not the SCP11 trust path.
func openSCP11bAgainstMock(t *testing.T, mc *mockcard.Card) *Session {
	t.Helper()
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	sess, err := OpenSCP11(context.Background(), mc.Transport(), cfg)
	if err != nil {
		t.Fatalf("OpenSCP11: %v", err)
	}
	return sess
}

// TestGetStatus_ISD_Populated populates RegistryISD and verifies the
// returned entries match.
func TestGetStatus_ISD_Populated(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle:  0x0F, // SECURED
			Privileges: [3]byte{0xC0, 0x00, 0x00},
		},
	}
	sess := openSCP11bAgainstMock(t, mc)
	defer sess.Close()

	entries, err := sess.GetStatus(context.Background(), StatusScopeISD)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	got := entries[0]
	if !bytes.Equal(got.AID, mc.RegistryISD[0].AID) {
		t.Errorf("AID = %X, want %X", got.AID, mc.RegistryISD[0].AID)
	}
	if got.Lifecycle != 0x0F {
		t.Errorf("Lifecycle = 0x%02X, want 0x0F", got.Lifecycle)
	}
	if got.LifecycleString() != "SECURED" {
		t.Errorf("LifecycleString = %q, want SECURED", got.LifecycleString())
	}
	if !got.Privileges.SecurityDomain {
		t.Errorf("expected SecurityDomain privilege; got %s", got.Privileges)
	}
	if got.Privileges.AuthorizedManagement {
		t.Errorf("did not expect AuthorizedManagement; got %s", got.Privileges)
	}
	if got.Scope != StatusScopeISD {
		t.Errorf("Scope = %v, want StatusScopeISD", got.Scope)
	}
}

// TestGetStatus_LoadFiles_WithModules covers the ISD's executable
// load files including module AIDs, exercising the
// LoadFilesAndModules scope.
func TestGetStatus_LoadFiles_WithModules(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{
		{
			AID:       []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01},
			Lifecycle: 0x01,
			Version:   []byte{0x01, 0x02},
			Modules: [][]byte{
				{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x01},
				{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x02},
			},
		},
	}
	sess := openSCP11bAgainstMock(t, mc)
	defer sess.Close()

	// Without modules: same load file, no module AIDs.
	entries, err := sess.GetStatus(context.Background(), StatusScopeLoadFiles)
	if err != nil {
		t.Fatalf("GetStatus(LoadFiles): %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].Modules) != 0 {
		t.Errorf("LoadFiles scope returned modules: %v", entries[0].Modules)
	}
	if !bytes.Equal(entries[0].Version, []byte{0x01, 0x02}) {
		t.Errorf("Version = %X, want 01 02", entries[0].Version)
	}
	if entries[0].LifecycleString() != "LOADED" {
		t.Errorf("LifecycleString = %q, want LOADED", entries[0].LifecycleString())
	}

	// With modules: same entry, modules now populated.
	entries, err = sess.GetStatus(context.Background(), StatusScopeLoadFilesAndModules)
	if err != nil {
		t.Fatalf("GetStatus(LoadFilesAndModules): %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].Modules) != 2 {
		t.Errorf("got %d modules, want 2", len(entries[0].Modules))
	}
}

// TestGetStatus_EmptyScopeReturnsNil confirms SW=6A88 (referenced
// data not found) is treated as an empty registry rather than an
// error — common when a card has nothing installed beyond the ISD.
func TestGetStatus_EmptyScopeReturnsNil(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Leave RegistryApps empty.
	sess := openSCP11bAgainstMock(t, mc)
	defer sess.Close()

	entries, err := sess.GetStatus(context.Background(), StatusScopeApplications)
	if err != nil {
		t.Fatalf("GetStatus on empty registry should succeed; got: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries on empty registry; got %v", entries)
	}
}

// TestGetStatus_MultipleApplications validates that several entries
// in one response decode in order.
func TestGetStatus_MultipleApplications(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x03, 0x08}, Lifecycle: 0x07},
		{AID: []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x21}, Lifecycle: 0x07,
			Privileges:      [3]byte{0x80, 0x00, 0x00},
			AssociatedSDAID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}},
	}
	sess := openSCP11bAgainstMock(t, mc)
	defer sess.Close()

	entries, err := sess.GetStatus(context.Background(), StatusScopeApplications)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if !bytes.Equal(entries[0].AID, mc.RegistryApps[0].AID) {
		t.Errorf("entry 0 AID mismatch")
	}
	if !entries[1].Privileges.SecurityDomain {
		t.Errorf("entry 1 should have SecurityDomain privilege")
	}
	if !bytes.Equal(entries[1].AssociatedSDAID, mc.RegistryApps[1].AssociatedSDAID) {
		t.Errorf("entry 1 AssociatedSDAID = %X, want %X",
			entries[1].AssociatedSDAID, mc.RegistryApps[1].AssociatedSDAID)
	}
}
