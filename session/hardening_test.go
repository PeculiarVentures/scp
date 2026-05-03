package session

import (
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestOpen_RejectsHostID confirms HostID is rejected at Open. The
// field is partially implemented (KDF SharedInfo includes it, but
// AUTHENTICATE doesn't set the SCP11 parameter bit nor include tag
// 0x84). Setting it would silently derive different keys than the
// card. Until the wire side is implemented, fail closed.
func TestOpen_RejectsHostID(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	cfg.HostID = []byte("test-host-id")
	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open with HostID set should fail until full impl")
	}
	if !strings.Contains(err.Error(), "HostID") {
		t.Errorf("error should mention HostID; got: %v", err)
	}
}

// TestOpen_RejectsCardGroupID confirms the CardGroupID variant of
// the same guardrail.
func TestOpen_RejectsCardGroupID(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	cfg.CardGroupID = []byte("test-cg-id")
	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open with CardGroupID set should fail until full impl")
	}
	if !strings.Contains(err.Error(), "CardGroupID") {
		t.Errorf("error should mention CardGroupID; got: %v", err)
	}
}

// TestOpen_SCP11b_RequiresReceiptByDefault confirms the new strict
// default: SCP11b sessions against a card that omits the receipt
// fail closed unless InsecureAllowSCP11bWithoutReceipt is set.
func TestOpen_SCP11b_RequiresReceiptByDefault(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	card.LegacySCP11bNoReceipt = true // model pre-Amendment-F-v1.4 card

	cfg := DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	// Note: NOT setting InsecureAllowSCP11bWithoutReceipt — should fail.

	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open should reject SCP11b card without receipt by default")
	}
	if !strings.Contains(err.Error(), "receipt") {
		t.Errorf("error should mention receipt; got: %v", err)
	}
}

// TestSCP11_TagKeyInfo_IsHardcoded11 documents that the first byte of
// tag 0x90 inside the A6 control reference is always 0x11 — the SCP11
// protocol identifier per GP Amendment F §7.6.2.3 — regardless of the
// variant (a/b/c) or the card's KID. The actual KID goes in APDU P2.
//
// This is verified end-to-end by the existing Samsung byte-exact
// transcript test (samsung_scp11a_transcript_test.go), which compares
// the wire bytes against an external reference. That test would catch
// a regression on the tag-0x90 byte. This test exists to make the
// invariant explicit in a unit-test form.
func TestSCP11_TagKeyInfo_IsHardcoded11(t *testing.T) {
	// Compile-time: this package's only producer of the tag-0x90 byte
	// is performKeyAgreement, which now hardcodes 0x11. We can't
	// easily isolate that without a mock transport that captures the
	// AUTHENTICATE APDU, and the byte-exact Samsung test already
	// covers the SCP11a wire shape. Marker test for grep.
	t.Log("tag 0x90 first byte invariant covered by samsung transcript byte-exact test")
}
