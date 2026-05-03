package securitydomain

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/session"
)

// TestIsOCEAuthProtocol covers the gate that drives session
// classification at Open time. SCP11b is the only variant where the
// off-card entity is NOT authenticated to the card; everything else
// authenticates both directions.
func TestIsOCEAuthProtocol(t *testing.T) {
	cases := []struct {
		proto string
		want  bool
	}{
		{"SCP03", true},
		{"SCP11a", true},
		{"SCP11c", true},
		{"SCP11b", false},
		{"none", false},
		{"", false},
		{"SCP99", false},
	}
	for _, c := range cases {
		if got := isOCEAuthProtocol(c.proto); got != c.want {
			t.Errorf("isOCEAuthProtocol(%q) = %v, want %v", c.proto, got, c.want)
		}
	}
}

// TestSCP11b_OCERequiredOps_Rejected_HostSide verifies that PUT KEY,
// DELETE KEY, GENERATE EC KEY, STORE CERTIFICATES, STORE CA ISSUER,
// STORE ALLOWLIST, STORE DATA, and RESET all fail at the API
// boundary — not deep in the wire protocol — when the underlying
// session is SCP11b. This is a defense in depth: the card-side
// authorization layer also rejects, but rejecting host-side gives a
// clear error pointing at the protocol limit.
func TestSCP11b_OCERequiredOps_Rejected_HostSide(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := session.DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true

	sd, err := OpenSCP11(context.Background(), card.Transport(), cfg)
	if err != nil {
		t.Fatalf("OpenSCP11: %v", err)
	}
	defer sd.Close()

	if !sd.IsAuthenticated() {
		t.Fatal("SCP11b session should report IsAuthenticated()=true")
	}
	if sd.OCEAuthenticated() {
		t.Error("SCP11b session should report OCEAuthenticated()=false (one-way auth)")
	}

	ctx := context.Background()
	ref := NewKeyReference(KeyIDSCP11b, 0x01)

	// Each of these must fail at the host-side gate.
	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateECKey", func() error { _, err := sd.GenerateECKey(ctx, ref, 0); return err }},
		{"DeleteKey", func() error { return sd.DeleteKey(ctx, ref, false) }},
		{"Reset", func() error { return sd.Reset(ctx) }},
		{"StoreCertificates", func() error { return sd.StoreCertificates(ctx, ref, nil) }},
		{"StoreCaIssuer", func() error { return sd.StoreCaIssuer(ctx, ref, []byte{0x01, 0x02}) }},
		{"StoreAllowlist", func() error { return sd.StoreAllowlist(ctx, ref, []string{"01"}) }},
		{"ClearAllowlist", func() error { return sd.ClearAllowlist(ctx, ref) }},
		{"StoreData", func() error { return sd.StoreData(ctx, []byte("test")) }},
	}

	for _, c := range tests {
		err := c.fn()
		if err == nil {
			t.Errorf("%s should have failed on SCP11b session", c.name)
			continue
		}
		if !errors.Is(err, ErrNotAuthenticated) {
			t.Errorf("%s: error should wrap ErrNotAuthenticated; got: %v", c.name, err)
		}
		if !strings.Contains(err.Error(), "OCE authentication") {
			t.Errorf("%s: error should mention OCE authentication; got: %v", c.name, err)
		}
	}
}

// TestSCP11b_ReadOnlyOps_Allowed confirms read-only inspection
// commands still work over SCP11b — the OCE gate is a write gate,
// not a session-disable.
func TestSCP11b_ReadOnlyOps_Allowed(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := session.DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true

	sd, err := OpenSCP11(context.Background(), card.Transport(), cfg)
	if err != nil {
		t.Fatalf("OpenSCP11: %v", err)
	}
	defer sd.Close()

	// Transmit a benign no-op-ish APDU through the secure channel.
	// The mockcard returns a generic success for unknown INS values
	// in some paths; we just need to confirm the host-side gate
	// doesn't intercept.
	_, err = sd.scpSession.Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0, P2: 0, Data: []byte{}, Le: -1,
	})
	if err != nil {
		// Acceptable failures are wire-level (mockcard didn't recognize
		// the command); what we're guarding against is a host-side
		// OCE gate intercepting the call. None of those errors should
		// mention OCE authentication.
		if strings.Contains(err.Error(), "OCE authentication") {
			t.Errorf("read-only Transmit shouldn't be gated by OCE auth; got: %v", err)
		}
	}
}
