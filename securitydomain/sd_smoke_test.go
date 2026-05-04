package securitydomain_test

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// TestSecurityDomain_SCP03_ReadAfterAuth is the end-to-end path the
// scp-smoke `scp03-sd-read` command exercises: open SCP03 against an
// SD with default keys, then verify GetKeyInformation and
// GetCardRecognitionData succeed under secure messaging.
//
// Before the SCP03 mock learned to handle GET DATA tag 0xE0/0x66 over
// secure messaging, this test was impossible to write — the mock
// returned 6D00 for any GET DATA. Now it works and gives the smoke
// command unit-test coverage equivalent to a real-card run.
func TestSecurityDomain_SCP03_ReadAfterAuth(t *testing.T) {
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

	if !sess.IsAuthenticated() {
		t.Fatal("session should be authenticated after OpenSCP03 success")
	}

	keys, err := sess.GetKeyInformation(ctx)
	if err != nil {
		t.Fatalf("GetKeyInformation: %v", err)
	}
	if len(keys) == 0 {
		t.Error("expected at least one key entry from synthetic mock")
	}

	crd, err := sess.GetCardRecognitionData(ctx)
	if err != nil {
		t.Fatalf("GetCardRecognitionData: %v", err)
	}
	if len(crd) == 0 {
		t.Error("expected non-empty CRD")
	}
}

// TestSecurityDomain_SCP11b_ReadAfterAuth: same end-to-end shape as
// the SCP03 case above, but against the SCP11 mock card. Open SCP11b
// against the SD, verify the read APDUs that the smoke harness's
// scp11b-sd-read command issues — and assert the SCP11b-specific
// invariant that the session is NOT OCE-authenticated (SCP11b is
// one-way auth: card to host only).
//
// The mock has a freshly generated P-256 keypair and a self-signed
// certificate, so we set InsecureSkipCardAuthentication: any trust
// policy would reject a self-signed leaf, and the test isn't about
// trust validation. The smoke harness exposes the same flag to its
// CLI users for the same reason.
func TestSecurityDomain_SCP11b_ReadAfterAuth(t *testing.T) {
	ctx := context.Background()
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true

	sess, err := securitydomain.OpenSCP11(ctx, card.Transport(), cfg)
	if err != nil {
		t.Fatalf("OpenSCP11: %v", err)
	}
	defer sess.Close()

	if !sess.IsAuthenticated() {
		t.Fatal("session should be authenticated after OpenSCP11 success")
	}
	// SCP11b is one-way auth: card authenticates to the host, but the
	// host does not authenticate to the card. Session.OCEAuthenticated()
	// must be false; the smoke harness asserts the same invariant.
	// A regression here would silently grant SCP11b sessions the
	// authority to perform OCE-gated SD writes — a real downgrade.
	if sess.OCEAuthenticated() {
		t.Fatal("SCP11b session should NOT be OCE-authenticated")
	}

	keys, err := sess.GetKeyInformation(ctx)
	if err != nil {
		t.Fatalf("GetKeyInformation over SCP11b: %v", err)
	}
	if len(keys) == 0 {
		t.Error("expected at least one key entry from synthetic mock")
	}

	crd, err := sess.GetCardRecognitionData(ctx)
	if err != nil {
		t.Fatalf("GetCardRecognitionData over SCP11b: %v", err)
	}
	if len(crd) == 0 {
		t.Error("expected non-empty CRD")
	}
}
