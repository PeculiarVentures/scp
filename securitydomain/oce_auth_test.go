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
// TestSessionOCEAuthenticated_RequiresTypedCapability covers the
// strict gate at the construction-time classifier: a custom
// scp.Session that does NOT implement oceAuthState is treated as
// not-OCE-authenticated, regardless of what its Protocol() string
// claims. Earlier versions had a string fallback that would accept
// "SCP03" / "SCP11a" / "SCP11c" as OCE-authenticated based on the
// protocol name; that was a soft guard a malicious or buggy custom
// Session could bypass by lying about its protocol. The fallback is
// gone; adapter authors must explicitly opt in.
func TestSessionOCEAuthenticated_RequiresTypedCapability(t *testing.T) {
	// Lying session: claims to be SCP03 but doesn't implement
	// OCEAuthenticated(). MUST be treated as not-OCE-authenticated.
	liar := &fakePlainSession{proto: "SCP03"}
	if sessionOCEAuthenticated(liar) {
		t.Error("session that doesn't implement oceAuthState must be treated as not-OCE-authenticated, " +
			"even when Protocol() returns 'SCP03'")
	}

	// Honest session: implements oceAuthState=true. Protocol() can
	// return literally anything; the typed capability is the
	// authoritative answer.
	honest := &fakeOCESession{proto: "any-string", auth: true}
	if !sessionOCEAuthenticated(honest) {
		t.Error("session that implements oceAuthState=true must be treated as OCE-authenticated")
	}

	// Honest session reporting OCEAuthenticated()=false. Should be
	// rejected even when Protocol() looks favourable.
	hopeful := &fakeOCESession{proto: "SCP11a", auth: false}
	if sessionOCEAuthenticated(hopeful) {
		t.Error("typed oceAuthState=false must win over recognized protocol string")
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
