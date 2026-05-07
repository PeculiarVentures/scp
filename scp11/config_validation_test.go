package scp11

import (
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/channel"
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
	cfg := testYubiKeySCP11aConfig()
	cfg.InsecureSkipCardAuthentication = true
	_, err = Open(context.Background(), card.Transport(), cfg)
	if err == nil {
		t.Fatal("Open with empty SCP11a config should fail; got success")
	}
}

// TestStrictGPConfigs_HaveCorrectShape verifies the StrictGP variant
// helpers set the GP-spec values (KID per §7.1.1, KVN 0 = "any
// version"), full security level, and the GP-literal empty-data
// policy — which is the actual semantic difference from the
// YubiKey-default helpers.
func TestStrictGPConfigs_HaveCorrectShape(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *Config
		wantV  Variant
		wantID byte
	}{
		{"SCP11a", StrictGPSCP11aConfig(), SCP11a, 0x11},
		{"SCP11b", StrictGPSCP11bConfig(), SCP11b, 0x13},
		{"SCP11c", StrictGPSCP11cConfig(), SCP11c, 0x15},
	}
	for _, c := range cases {
		if c.cfg.Variant != c.wantV {
			t.Errorf("%s: Variant = %v, want %v", c.name, c.cfg.Variant, c.wantV)
		}
		if c.cfg.KeyID != c.wantID {
			t.Errorf("%s: KeyID = 0x%02X, want 0x%02X", c.name, c.cfg.KeyID, c.wantID)
		}
		if c.cfg.KeyVersion != 0x00 {
			t.Errorf("%s: KeyVersion = 0x%02X, want 0x00 (GP \"any version\")",
				c.name, c.cfg.KeyVersion)
		}
		if c.cfg.SecurityLevel == 0 {
			t.Errorf("%s: SecurityLevel = 0; helpers should set full level", c.name)
		}
		// The defining semantic difference from YubiKeyDefault*: empty
		// data is NOT padded-and-encrypted under the strict-GP reading.
		// If this assertion fails, the helper has silently lost its
		// reason to exist.
		if c.cfg.EmptyDataEncryption != channel.EmptyDataNoOp {
			t.Errorf("%s: EmptyDataEncryption = %v, want EmptyDataNoOp",
				c.name, c.cfg.EmptyDataEncryption)
		}
	}
}

// TestOpen_NilConfig_RejectsExplicitly confirms scp11.Open(ctx, t, nil)
// returns an error rather than silently substituting YubiKey defaults.
// Earlier behavior was to fall through to testYubiKeySCP11bConfig()
// when cfg was nil, which silently picked SCP11b plus YubiKey-shaped
// empty-data policy without the caller naming either. Matching
// scp03.Open's contract: Config is required.
func TestOpen_NilConfig_RejectsExplicitly(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	_, err = Open(context.Background(), mc.Transport(), nil)
	if err == nil {
		t.Fatal("Open(nil cfg) should return an error, not silently default")
	}
	if !strings.Contains(err.Error(), "Config is required") {
		t.Errorf("error should mention Config is required; got: %v", err)
	}
}

// TestOpen_NilTransport_RejectsExplicitly confirms that scp11.Open
// with a nil transport fails fast at the API boundary. The guard
// is the very first check so the failure surfaces before config
// validation or any other work.
func TestOpen_NilTransport_RejectsExplicitly(t *testing.T) {
	_, err := Open(context.Background(), nil, testYubiKeySCP11bConfig())
	if err == nil {
		t.Fatal("Open(nil transport) should return an error")
	}
	if !strings.Contains(err.Error(), "transport is required") {
		t.Errorf("error should mention transport is required; got: %v", err)
	}
}

// TestOpen_DoesNotMutateCallerConfig confirms scp11.Open shallow-
// copies its Config argument before applying defaults like the
// implicit SecurityLevel. Earlier versions mutated the caller's
// Config in place, which surprised callers reusing a config across
// sessions or holding a pointer that another goroutine read in
// parallel. Open is allowed to fail (mock card with no trust path
// fails post-validation) — the side-effect check on the caller's
// pointer happens regardless of outcome.
func TestOpen_DoesNotMutateCallerConfig(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := testYubiKeySCP11bConfig()
	cfg.SecurityLevel = 0
	cfg.InsecureSkipCardAuthentication = true
	wantLevel := cfg.SecurityLevel
	_, _ = Open(context.Background(), mc.Transport(), cfg)
	if cfg.SecurityLevel != wantLevel {
		t.Errorf("Open mutated caller's Config.SecurityLevel: got 0x%X, want 0x%X",
			cfg.SecurityLevel, wantLevel)
	}
	// Reference channel.LevelFull so the import stays used regardless
	// of how Open is rewritten in the future.
	_ = channel.LevelFull
}
