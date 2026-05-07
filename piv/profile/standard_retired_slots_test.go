package profile

// Section 10 verification test for the third external review:
// 'OpenSC PIV compatibility boundary'.
//
// OpenSC piv-tool exposes the standard PIV slots 9A/9C/9D/9E plus
// retired slots 82..95 for cert/object operations. Per the review:
//
//	'Standard PIV profile should include: 9A, 9C, 9D, 9E,
//	 retired slots 82..95.
//	 Standard PIV profile should not include: F9 attestation slot,
//	 YubiKey extension instructions.'
//
// TestStandardPIVProfile_Capabilities already pins the negative
// cases (no F9, no YubiKey-only capabilities). This test pins the
// positive: every retired slot 0x82..0x95 must be present in
// caps.Slots so OpenSC-style flows that target retired slots work.
//
// Pinning the full range catches a regression that, say,
// shortened the loop in standard.go or swapped boundary constants.

import (
	"testing"

	"github.com/PeculiarVentures/scp/piv"
)

// TestStandardPIVProfile_IncludesAllRetiredSlots asserts that the
// 20-slot retired range 0x82..0x95 inclusive is fully present in
// the Standard PIV profile's slot inventory. The retired slots
// are a flat numeric block per PIV-IS NIST SP 800-73-4 Part 1
// §2.2.5; OpenSC piv-tool maps them directly via piv_slot_to_obj.
func TestStandardPIVProfile_IncludesAllRetiredSlots(t *testing.T) {
	caps := NewStandardPIVProfile().Capabilities()

	// Build a set of declared slots for O(1) membership tests.
	declared := make(map[piv.Slot]bool, len(caps.Slots))
	for _, s := range caps.Slots {
		declared[s] = true
	}

	// Standard PIV-IS slots (4): pin them too so the negative
	// case (missing 9A/9C/9D/9E) doesn't sneak past.
	for _, want := range []piv.Slot{
		piv.SlotPIVAuthentication,
		piv.SlotDigitalSignature,
		piv.SlotKeyMgmt,
		piv.SlotCardAuthentication,
	} {
		if !declared[want] {
			t.Errorf("Standard PIV missing core slot 0x%02X (%s)", byte(want), want)
		}
	}

	// Retired key management 1..20, slots 0x82..0x95 inclusive
	// per SP 800-73-4 Part 1 §2.2.5. Pin every byte in the
	// closed range so a regression that ends the loop one
	// short, or swaps the boundary constants, surfaces here
	// against the specific missing slot.
	for slot := byte(0x82); slot <= 0x95; slot++ {
		if !declared[piv.Slot(slot)] {
			t.Errorf("Standard PIV missing retired key-mgmt slot 0x%02X "+
				"(per SP 800-73-4 §2.2.5; 20-slot range 82..95)", slot)
		}
	}

	// Negative pin: F9 attestation slot is YubiKey-only and
	// must NOT appear. Already covered by
	// TestStandardPIVProfile_Capabilities in profile_test.go,
	// duplicated here to keep this test self-contained — a
	// developer chasing 'why does my retired-slot test pass
	// but attestation also passes' should see both bounds in
	// one place.
	if declared[piv.SlotYubiKeyAttestation] {
		t.Errorf("Standard PIV must not include YubiKey attestation slot 0xF9")
	}

	// Total count: 4 standard + 20 retired = 24. Pin to catch
	// a regression that adds an extra slot from somewhere.
	wantCount := 4 + 20
	if len(caps.Slots) != wantCount {
		t.Errorf("StandardPIV slot count = %d, want %d (4 standard + 20 retired)",
			len(caps.Slots), wantCount)
	}
}

// TestStandardPIVProfile_RetiredRangeBoundaries pins the boundary
// constants in piv/types.go that the standard.go loop relies on.
// If SlotRetiredKeyMgmt1 or SlotRetiredKeyMgmt20 ever shifted, the
// loop in NewStandardPIVProfile would silently produce a different
// slot inventory while constants-parity would still be green —
// because constants_parity_test.go pins the values, but only
// against yubikit, not against the loop using them. This test
// pins the values via the loop's bounds.
func TestStandardPIVProfile_RetiredRangeBoundaries(t *testing.T) {
	if got, want := byte(piv.SlotRetiredKeyMgmt1), byte(0x82); got != want {
		t.Errorf("SlotRetiredKeyMgmt1 = 0x%02X, want 0x%02X (range start)", got, want)
	}
	if got, want := byte(piv.SlotRetiredKeyMgmt20), byte(0x95); got != want {
		t.Errorf("SlotRetiredKeyMgmt20 = 0x%02X, want 0x%02X (range end)", got, want)
	}
	// The range is inclusive and continuous. 0x95 - 0x82 + 1 = 20.
	span := byte(piv.SlotRetiredKeyMgmt20) - byte(piv.SlotRetiredKeyMgmt1) + 1
	if span != 20 {
		t.Errorf("retired range span = %d, want 20 slots inclusive", span)
	}
}
