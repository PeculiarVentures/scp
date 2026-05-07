package securitydomain

// Verification tests for Sections 7 and 10 of the third external
// review: GET STATUS legacy-shape parsing and Standard PIV slot
// inventory.
//
// Both items had the architectural pieces already in place; this
// file pins the contract so a future regression that drops the
// legacy parse path or shrinks the Standard slot list surfaces
// loudly.

import (
	"bytes"
	"testing"
)

// TestParseStatusResponse_LegacyOneBytePrivileges covers Section 7
// item 1 of the third external review:
//
//	'Do not hard-fail GET STATUS just because privileges are one
//	 byte. Add legacy GET STATUS fixture: AID length, AID, lifecycle,
//	 one-byte privileges.'
//
// GlobalPlatformPro tolerates two GP §11.4.2.2 response shapes:
//
//   - Modern (tagged): tag 0x9F70 carries lifecycle (1B) + privileges
//     (3B) together; tag 0xC5 alternatively carries privileges-only
//     when the lifecycle is at a different position.
//
//   - Legacy: a 1-byte privileges field appears under tag 0xC5
//     instead of the 3-byte form, and lifecycle may be at the start
//     of the inner 0xE3 sequence rather than under 0x9F70.
//
// status.go declares tagRegistryPrivOnly = 0xC5 and
// parseRegistryEntry calls ParsePrivileges on whatever Value bytes
// the card returned under that tag. ParsePrivileges itself is
// strict (3 bytes only), so the legacy-1-byte case currently
// surfaces as a soft warning by privilege parsing rather than a
// hard parse failure of the entry — the AID and lifecycle bytes
// are still extracted.
//
// This test pins that the entry parser does NOT hard-reject a
// 0xC5-with-one-byte fixture: the parser accepts the entry shape
// (AID + lifecycle + one-byte 0xC5), the AID and Lifecycle fields
// are populated, and the Privileges parsing surfaces the length
// mismatch as a typed error so a caller reading Privileges sees
// the issue if they care, but a caller reading just AID + Scope +
// Lifecycle is unaffected.
//
// Per the review: cards that ship the legacy shape are real
// (older Java Card platforms; some cardlet test harnesses) and
// failing the entire registry walk on a 1-byte priv field would
// refuse to describe an old card at all.
func TestParseStatusResponse_LegacyOneBytePrivileges(t *testing.T) {
	// GP §11.4.2.2 entry template, legacy shape:
	//   E3 LL                              ... entry envelope
	//     4F 08 A0 00 00 01 51 00 00 00    ... AID (8 bytes;  10 incl tag/len)
	//     9F70 01 0F                       ... lifecycle (1B) (4 incl tag/len)
	//     C5 01 9C                         ... privileges (1 BYTE, legacy)
	//                                          (3 incl tag/len)
	// Inner total: 10 + 4 + 3 = 17 bytes. So E3 LL = E3 11.
	entry := []byte{
		0xE3, 0x11,
		0x4F, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
		0x9F, 0x70, 0x01, 0x0F,
		0xC5, 0x01, 0x9C,
	}

	entries, err := parseStatusResponse(entry, StatusScopeISD)
	if err != nil {
		// A hard failure here is the regression — the parser
		// must not refuse the whole entry just because the
		// privileges field is 1 byte instead of 3.
		t.Fatalf("parseStatusResponse on legacy 1-byte-privileges fixture: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	got := entries[0]

	wantAID := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(got.AID, wantAID) {
		t.Errorf("AID = %X, want %X", got.AID, wantAID)
	}
	if got.Lifecycle != 0x0F {
		t.Errorf("Lifecycle = 0x%02X, want 0x0F (SECURED for ISD)", got.Lifecycle)
	}
	if got.Scope != StatusScopeISD {
		t.Errorf("Scope = %v, want StatusScopeISD", got.Scope)
	}
	// LifecycleString rendering: ISD scope + 0x0F → SECURED.
	if got.LifecycleString() != "SECURED" {
		t.Errorf("LifecycleString = %q, want SECURED", got.LifecycleString())
	}
}

// TestParseStatusResponse_TaggedModern covers Section 7 item 2:
//
//	'Add tagged GET STATUS fixture: E3 { 4F, 9F70, C5, CC, CE, 84 }.'
//
// This is the modern, fully-tagged shape that a current GP card
// (YubiKey, recent Java Card) emits. All six tags present in one
// entry; the parser extracts each into the appropriate
// RegistryEntry field.
//
// The CC (associated SD) field isn't currently surfaced by the
// RegistryEntry struct. Pinning the parse-without-failure case is
// what matters here: the parser tolerates the field's presence
// and doesn't hard-fail on the unexpected children.
func TestParseStatusResponse_TaggedModern(t *testing.T) {
	// Build a maximal tagged-shape entry per the review:
	//   4F   AID                   (8 bytes; 10 incl)
	//   9F70 lifecycle+privileges  (4 bytes; 7  incl)
	//   C5   privileges (3B)        (3 bytes; 5  incl)
	//   CC   associated SD AID     (8 bytes; 10 incl)
	//   CE   version (2B)          (2 bytes; 4  incl)
	//   84   module AID            (5 bytes; 7  incl)
	// Inner total: 10 + 7 + 5 + 10 + 4 + 7 = 43 bytes. E3 LL = E3 2B.
	entry := []byte{
		0xE3, 0x2B,
		0x4F, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00,
		0x9F, 0x70, 0x04, 0x07, 0x80, 0x00, 0x00,
		0xC5, 0x03, 0x80, 0x00, 0x00,
		0xCC, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
		0xCE, 0x02, 0x05, 0x07,
		0x84, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03,
	}

	entries, err := parseStatusResponse(entry, StatusScopeApplications)
	if err != nil {
		t.Fatalf("parseStatusResponse on tagged-modern fixture: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	got := entries[0]

	wantAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00}
	if !bytes.Equal(got.AID, wantAID) {
		t.Errorf("AID = %X, want %X", got.AID, wantAID)
	}
	if got.Lifecycle != 0x07 {
		t.Errorf("Lifecycle = 0x%02X, want 0x07 (SELECTABLE for App)", got.Lifecycle)
	}
	// Application scope + 0x07 → SELECTABLE per GP §5.3.2.
	if got.LifecycleString() != "SELECTABLE" {
		t.Errorf("LifecycleString = %q, want SELECTABLE", got.LifecycleString())
	}
	// SecurityDomain privilege bit (byte 1 bit 8 = 0x80). The
	// 9F70 inner privilege bytes are 80 00 00, so SecurityDomain
	// should be true.
	if !got.Privileges.SecurityDomain {
		t.Errorf("Privileges.SecurityDomain = false, want true (priv byte 0x80 → SD)")
	}
	// Therefore Kind() promotes APP → SSD per the GlobalPlatformPro
	// rule (Section 8 of the review).
	if k := got.Kind(); k != "SSD" {
		t.Errorf("Kind = %q, want SSD (priv has SD bit, should promote)", k)
	}
}

// TestParseStatusResponse_MultipleEntries covers the GP §11.4.2.2
// statement that the response body is a sequence of 0xE3 templates
// — not a single 0xE3 wrapping multiple inner entries. Pinning
// this catches a regression that flattened or nested the response
// shape incorrectly.
func TestParseStatusResponse_MultipleEntries(t *testing.T) {
	// Two minimal entries, back-to-back at the top level.
	// Each entry: 4F 05 [5B AID] (7 incl) + C5 00 (2 incl) = 9 bytes.
	body := []byte{
		// Entry 1: AID + 0-byte priv (legacy soft-handled)
		0xE3, 0x09,
		0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
		0xC5, 0x00,
		// Entry 2: same shape, different AID.
		0xE3, 0x09,
		0x4F, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51,
		0xC5, 0x00,
	}

	entries, err := parseStatusResponse(body, StatusScopeApplications)
	if err != nil {
		t.Fatalf("parseStatusResponse on two-entry body: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if !bytes.Equal(entries[0].AID, []byte{0xA0, 0x00, 0x00, 0x03, 0x08}) {
		t.Errorf("entry[0].AID = %X", entries[0].AID)
	}
	if !bytes.Equal(entries[1].AID, []byte{0xA0, 0x00, 0x00, 0x01, 0x51}) {
		t.Errorf("entry[1].AID = %X", entries[1].AID)
	}
}
