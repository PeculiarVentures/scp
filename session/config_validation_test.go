package session

import (
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
)

// TestOpen_RejectsUnknownVariant confirms an out-of-range Variant
// fails closed at Open time. Earlier the switch on Variant defaulted
// silently into SCP11b-like behavior (params=0, INS=0x88), which is
// the wrong failure mode for a mutual-auth library: a stale numeric
// value from JSON/YAML or a config builder bug would silently
// downgrade the auth shape instead of erroring out.
func TestOpen_RejectsUnknownVariant(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := &Config{
		Variant:                        Variant(99),
		SelectAID:                      AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
	}
	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open with Variant=99 should fail; got success")
	}
	if !strings.Contains(err.Error(), "unsupported SCP11 variant") {
		t.Errorf("error should mention unsupported variant; got: %v", err)
	}
}

// TestOpen_SCP11a_ZeroOCEKeyReference_Rejected confirms zero-valued
// OCEKeyReference is rejected for SCP11a/c. Earlier this fell through
// silently and produced PSO APDUs with P1=0x00 P2=0x00 — most real
// cards reject those opaquely, leaving the user to debug why
// "provisioning fails."
func TestOpen_SCP11a_ZeroOCEKeyReference_Rejected(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := DefaultSCP11aConfig()
	cfg.InsecureSkipCardAuthentication = true
	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open with empty SCP11a config should fail; got success")
	}
}

// TestDefaultSCP11Configs_HaveCorrectKIDs confirms each variant
// constructor sets the right GP Amendment F §7.1.1 KID. This is the
// safety net for the documented pitfall where Variant-only mutation
// of DefaultConfig produced an SCP11a config with the SCP11b KID.
func TestDefaultSCP11Configs_HaveCorrectKIDs(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *Config
		wantV  Variant
		wantID byte
	}{
		{"SCP11a", DefaultSCP11aConfig(), SCP11a, 0x11},
		{"SCP11b", DefaultSCP11bConfig(), SCP11b, 0x13},
		{"SCP11c", DefaultSCP11cConfig(), SCP11c, 0x15},
	}
	for _, c := range cases {
		if c.cfg.Variant != c.wantV {
			t.Errorf("%s: Variant = %v, want %v", c.name, c.cfg.Variant, c.wantV)
		}
		if c.cfg.KeyID != c.wantID {
			t.Errorf("%s: KeyID = 0x%02X, want 0x%02X", c.name, c.cfg.KeyID, c.wantID)
		}
	}
}
