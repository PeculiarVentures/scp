package securitydomain

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestOpenUnauthenticated_LockedCard6283_OpensWithWarning is the
// library-level pin for Section 9 of the third external review
// (locked-card SELECT behavior).
//
// GP §11.1.2 documents 6283 as "selected file invalidated" — the
// applet is in CARD_LOCKED lifecycle (GP §5.3.1) and the SELECT
// structurally returned FCI but with the warning status word.
// GlobalPlatformPro and OpenSC tolerate this and continue with
// read-only operations; failing closed on 6283 would refuse to
// describe a CARD_LOCKED card at all, which is exactly the case
// where an operator most needs information about the card.
//
// Three subtests pin the contract:
//
//  1. With SW=6283 from SELECT, Open succeeds and CardLocked()
//     returns true. Pins the new tolerance.
//
//  2. With SW=9000 (the historical case), Open succeeds and
//     CardLocked() returns false. Pins that the new field stays
//     false on the typical-case path so programmatic consumers
//     keying on it don't see false positives.
//
//  3. With SW=6A82 (file not found, NOT a locked-card SW),
//     Open fails. Pins that the tolerance is narrowly scoped to
//     6283; arbitrary non-9000 SWs still surface as errors.
func TestOpenUnauthenticated_LockedCard6283_OpensWithWarning(t *testing.T) {
	ctx := context.Background()

	t.Run("SELECT SW=6283 opens with CardLocked()=true", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockSelectSW = 0x6283

		sd, err := OpenUnauthenticated(ctx, mc.Transport())
		if err != nil {
			t.Fatalf("OpenUnauthenticated: %v (want nil)", err)
		}
		defer sd.Close()
		if !sd.CardLocked() {
			t.Errorf("CardLocked() = false; want true after SELECT SW=6283")
		}
	})

	t.Run("SELECT SW=9000 opens with CardLocked()=false", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		// MockSelectSW unset => default 9000.

		sd, err := OpenUnauthenticated(ctx, mc.Transport())
		if err != nil {
			t.Fatalf("OpenUnauthenticated: %v", err)
		}
		defer sd.Close()
		if sd.CardLocked() {
			t.Errorf("CardLocked() = true on 9000 SELECT; want false")
		}
	})

	t.Run("SELECT SW=6A82 still fails (tolerance is 6283-specific)", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockSelectSW = 0x6A82

		_, err = OpenUnauthenticated(ctx, mc.Transport())
		if err == nil {
			t.Fatal("OpenUnauthenticated: nil error on SW=6A82; want failure")
		}
		// Pin the SW makes it into the error message so an
		// operator diagnosing a real failure can see exactly
		// what the card returned.
		if !errors.Is(err, ErrCardStatus) && !contains(err.Error(), "6A82") {
			t.Errorf("error should reference 6A82 or wrap ErrCardStatus; got: %v", err)
		}
	})
}

// TestOpenUnauthenticatedWithAID_LockedCard6283 mirrors the above
// against the explicit-AID variant. The two functions share the
// same SELECT-handling path (OpenUnauthenticated wraps
// OpenUnauthenticatedWithAID with nil) but pinning both shapes
// catches a regression that splits the implementations and updates
// only one.
func TestOpenUnauthenticatedWithAID_LockedCard6283(t *testing.T) {
	ctx := context.Background()
	customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.MockSDAID = customAID
	mc.MockSelectSW = 0x6283

	sd, err := OpenUnauthenticatedWithAID(ctx, mc.Transport(), customAID)
	if err != nil {
		t.Fatalf("OpenUnauthenticatedWithAID: %v", err)
	}
	defer sd.Close()
	if !sd.CardLocked() {
		t.Errorf("CardLocked() = false; want true after SELECT SW=6283")
	}
	// Belt-and-braces: SDAID() should still return the custom
	// AID — the locked-card path doesn't break the AID pinning.
	got := sd.SDAID()
	if !equalBytes(got, customAID) {
		t.Errorf("SDAID() = %X, want %X", got, customAID)
	}
}

// equalBytes is a local helper so the test doesn't pull in
// bytes.Equal indirectly via the larger bytes package import.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
