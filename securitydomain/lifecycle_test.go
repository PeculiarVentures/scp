package securitydomain_test

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// TestSetISDLifecycle_Wire is the regression pin for the SET STATUS
// APDU shape. SetISDLifecycle must emit:
//
//	CLA=0x80 INS=0xF0 P1=0x80 (ISD scope) P2=<target> Data=ISD AID
//
// All four header bytes plus the AID payload are what GP §11.1.10
// Table 11-25 specifies for the ISD-scoped variant. Mis-encoding any
// of them gets rejected by real cards as 6A86 (incorrect P1/P2) or
// 6985 (conditions not satisfied), which surfaces as opaque errors
// in the field; this test catches drift at the unit-test layer.
func TestSetISDLifecycle_Wire(t *testing.T) {
	cases := []struct {
		name   string
		target securitydomain.LifecycleState
		wantP2 byte
	}{
		{"lock", securitydomain.LifecycleCardLocked, 0x7F},
		{"unlock_to_secured", securitydomain.LifecycleSecured, 0x0F},
		{"terminate", securitydomain.LifecycleTerminated, 0xFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			card := scp03.NewMockCard(scp03.DefaultKeys)
			sess, err := securitydomain.OpenSCP03(ctx, card.Transport(), &scp03.Config{
				Keys:       scp03.DefaultKeys,
				KeyVersion: 0xFF,
			})
			if err != nil {
				t.Fatalf("OpenSCP03: %v", err)
			}
			defer sess.Close()

			if err := sess.SetISDLifecycle(ctx, tc.target); err != nil {
				t.Fatalf("SetISDLifecycle(%s): %v", tc.target, err)
			}

			recorded := card.Recorded()
			var setStatus *scp03.RecordedAPDU
			for i := range recorded {
				if recorded[i].INS == 0xF0 {
					setStatus = &recorded[i]
					break
				}
			}
			if setStatus == nil {
				t.Fatalf("no SET STATUS APDU recorded; got %d APDUs", len(recorded))
			}
			if setStatus.P1 != 0x80 {
				t.Errorf("P1 = 0x%02X, want 0x80 (ISD scope)", setStatus.P1)
			}
			if setStatus.P2 != tc.wantP2 {
				t.Errorf("P2 = 0x%02X, want 0x%02X (%s)", setStatus.P2, tc.wantP2, tc.target)
			}
			if len(setStatus.Data) != len(securitydomain.AIDSecurityDomain) {
				t.Errorf("Data length = %d, want %d (ISD AID)",
					len(setStatus.Data), len(securitydomain.AIDSecurityDomain))
			}
			for i := range securitydomain.AIDSecurityDomain {
				if i >= len(setStatus.Data) {
					break
				}
				if setStatus.Data[i] != securitydomain.AIDSecurityDomain[i] {
					t.Errorf("Data[%d] = 0x%02X, want 0x%02X (ISD AID byte)",
						i, setStatus.Data[i], securitydomain.AIDSecurityDomain[i])
					break
				}
			}
		})
	}
}

// TestSetISDLifecycle_RequiresOCEAuth confirms SetISDLifecycle is
// gated on requireOCEAuth — an unauthenticated session is rejected
// before any APDU is sent. This pins the security boundary: a caller
// that forgets to authenticate doesn't get a stub 6982 from the card,
// they get a clear ErrNotAuthenticated from the library so they can
// fix their setup.
func TestSetISDLifecycle_RequiresOCEAuth(t *testing.T) {
	ctx := context.Background()
	card := scp03.NewMockCard(scp03.DefaultKeys)
	sess, err := securitydomain.OpenUnauthenticated(ctx, card.Transport(), nil)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sess.Close()

	err = sess.SetISDLifecycle(ctx, securitydomain.LifecycleCardLocked)
	if err == nil {
		t.Fatal("SetISDLifecycle on unauthenticated session unexpectedly succeeded")
	}
	for _, rec := range card.Recorded() {
		if rec.INS == 0xF0 {
			t.Errorf("SET STATUS APDU emitted despite auth gate; got recorded INS=0x%02X", rec.INS)
		}
	}
}

// TestLifecycleState_String covers the human-readable rendering of
// every named state plus the unknown-byte fallback.
func TestLifecycleState_String(t *testing.T) {
	cases := []struct {
		state securitydomain.LifecycleState
		want  string
	}{
		{securitydomain.LifecycleOPReady, "OP_READY"},
		{securitydomain.LifecycleInitialized, "INITIALIZED"},
		{securitydomain.LifecycleSecured, "SECURED"},
		{securitydomain.LifecycleCardLocked, "CARD_LOCKED"},
		{securitydomain.LifecycleTerminated, "TERMINATED"},
		{securitydomain.LifecycleState(0x42), "LifecycleState(0x42)"},
	}
	for _, tc := range cases {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("LifecycleState(0x%02X).String() = %q, want %q",
				byte(tc.state), got, tc.want)
		}
	}
}
