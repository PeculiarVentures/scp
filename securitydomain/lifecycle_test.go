package securitydomain_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	sess, err := securitydomain.OpenUnauthenticated(ctx, card.Transport())
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

// TestLifecycleError_PreservesSW pins the structured-error contract
// added for Finding 10 of the external review on feat/sd-keys-cli:
// 'lifecycle behavior varies across cards [...] the CLI should
// preserve raw lifecycle byte and raw SW in JSON for every failed
// transition.'
//
// The contract:
//   - SetISDLifecycle returns *LifecycleError on a non-9000 SW
//   - LifecycleError exposes the raw SW for callers that need it
//   - errors.Is(err, ErrCardStatus) still works (Unwrap)
//   - errors.As lets callers extract the typed error
//
// This test exercises the type directly because doSetStatus in
// mockcard unconditionally returns 9000; adding fault injection
// to the mock just for this test would be more code than the
// type's surface area. Tests that drive the full CLI command JSON
// path live alongside the lifecycle commands themselves
// (cmd_sd_lock_test.go, etc.) and exercise the populated
// data.LastSW field once mockcard fault-injection lands.
func TestLifecycleError_PreservesSW(t *testing.T) {
	cases := []struct {
		name   string
		target securitydomain.LifecycleState
		sw     uint16
		hex    string
	}{
		{"conditions of use", securitydomain.LifecycleCardLocked, 0x6985, "6985"},
		{"security status", securitydomain.LifecycleSecured, 0x6982, "6982"},
		{"referenced data not found", securitydomain.LifecycleTerminated, 0x6A88, "6A88"},
		{"unexpected SW", securitydomain.LifecycleSecured, 0x6F00, "6F00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &securitydomain.LifecycleError{Target: tc.target, SW: tc.sw}

			// SW field is directly accessible for telemetry.
			if err.SW != tc.sw {
				t.Errorf("SW = %04X, want %04X", err.SW, tc.sw)
			}

			// Error() format includes the SW as 4-digit hex.
			msg := err.Error()
			if !strings.Contains(msg, tc.hex) {
				t.Errorf("Error() %q should contain SW %s", msg, tc.hex)
			}
			// And the target lifecycle name.
			if !strings.Contains(msg, tc.target.String()) {
				t.Errorf("Error() %q should contain target %s", msg, tc.target)
			}

			// errors.Is unwraps to ErrCardStatus so existing
			// callers that branch on the sentinel keep working.
			if !errors.Is(err, securitydomain.ErrCardStatus) {
				t.Errorf("errors.Is(err, ErrCardStatus) = false; should be true via Unwrap")
			}

			// errors.As recovers the typed error after wrapping.
			wrapped := fmt.Errorf("sd lock: SET STATUS: %w", err)
			var lerr *securitydomain.LifecycleError
			if !errors.As(wrapped, &lerr) {
				t.Errorf("errors.As after wrap should succeed; got false")
			}
			if lerr != nil && lerr.SW != tc.sw {
				t.Errorf("after errors.As: SW = %04X, want %04X", lerr.SW, tc.sw)
			}
		})
	}
}
