package scp03_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
)

// TestOpen_InitializeUpdate6982_SafeNetTokenJCRealShape pins the
// post-#142 InitializeUpdateError diagnostic against the exact
// real-card shape captured from a SafeNet Token JC (Athena
// IDProtect platform, GP 2.3, SCP03 i=0x10) in May 2026. The
// captured behavior was confirmed across a 12-attempt burn test
// (every attempt returned identical bytes; pre/post-burn probes
// were byte-identical). See docs/safenet-token-jc.md "May 2026
// follow-up: 12-attempt burn test" for the empirical data.
//
// What this fixture pins:
//
//   - Attempt context KV=0xFF (the KVN scpctl uses for factory
//     keys), AID=A000000018434D00 (the SafeNet Card Manager AID,
//     GemPlus-registered RID per ISO/IEC 7816-5).
//   - SW=6982 returned BEFORE any cryptogram exchange — i.e. the
//     "rejected before key material was tested" path.
//   - InitializeUpdateError.RetryDifferentKeys is false (so the
//     operator-facing diagnostic discourages key cycling).
//   - Rendered error includes the SW, the attempt context, and
//     the specific guidance "retrying with different keys will
//     not help" plus "Investigate SD lifecycle".
//
// Why this is separate from the existing 6982 test in
// errors_test.go: the existing test is parameterized over the
// SW class; this test is named after the specific real-card data
// point, so a future regression of the diagnostic against this
// exact card shape (e.g. a refactor that drops the attempt
// context, or that misclassifies a SafeNet-style 6982 as
// retryable) gets caught with a test name that grep's straight to
// the relevant docs/safenet-token-jc.md section.
func TestOpen_InitializeUpdate6982_SafeNetTokenJCRealShape(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	card.ForceInitUpdateSW = 0x6982

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: 0xFF,
		SelectAID:  []byte{0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00},
	})
	if err == nil {
		t.Fatal("Open: expected error when card returns 6982 on IU; got nil")
	}

	// Sentinel chain matches.
	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}

	// Concrete InitializeUpdateError recovers.
	var iue *scp03.InitializeUpdateError
	if !errors.As(err, &iue) {
		t.Fatalf("errors.As should recover *InitializeUpdateError; err = %v", err)
	}

	if iue.SW() != 0x6982 {
		t.Errorf("SW = 0x%04X, want 0x6982 (the SafeNet Token JC's observed-12x SW)", iue.SW())
	}
	if iue.RetryDifferentKeys {
		t.Error("RetryDifferentKeys must be false: 6982 before cryptogram check is not a key problem")
	}
	if iue.KeyVersion != 0xFF {
		t.Errorf("KeyVersion = 0x%02X, want 0xFF", iue.KeyVersion)
	}

	// Rendered error must surface the attempt context AID. This is
	// what the May 2026 12-attempt observation pinned: every
	// attempt's rendered message included AID=A000000018434D00 so
	// an operator triaging logs sees which AID was being targeted.
	msg := err.Error()
	if !strings.Contains(msg, "A000000018434D00") {
		t.Errorf("Error() should surface AID context; got:\n%s", msg)
	}

	// Rendered error must surface the diagnostic the post-#142
	// classifier produces for SW=6982 — the discouragement of key
	// cycling and the lifecycle hint.
	for _, want := range []string{
		"SW=6982",
		"retrying with different keys will not help",
		"Investigate SD lifecycle",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() should contain %q; got:\n%s", want, msg)
		}
	}
}
