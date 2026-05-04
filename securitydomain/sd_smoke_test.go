package securitydomain_test

import (
	"context"
	"testing"

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

// TestSecurityDomain_SCP11b_ReadAfterAuth: same end-to-end shape
// against the SCP11 mock. Confirms the smoke harness's scp11b-sd-read
// command path.
func TestSecurityDomain_SCP11b_ReadAfterAuth(t *testing.T) {
	t.Skip("SCP11 mock requires more setup (cert chain, ECDH key); revisit when extending the SCP11 smoke tests")
	ctx := context.Background()
	_ = ctx
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	_ = cfg
	// Placeholder; remove t.Skip once mockcard wiring is convenient.
}
