package yubikey_test

import (
	"testing"

	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/yubikey"
)

// TestFactoryKeyVersion pins the SCP03 factory KVN that YubiKey 5.x
// ships with from the factory and returns to after
// securitydomain.Reset. A change here is a wire-protocol change.
func TestFactoryKeyVersion(t *testing.T) {
	if yubikey.FactoryKeyVersion != 0xFF {
		t.Errorf("yubikey.FactoryKeyVersion = 0x%02X, want 0xFF", yubikey.FactoryKeyVersion)
	}
}

// TestFactorySCP03Config_HasYubiKeyShape pins the SCP03 factory
// Config: scp03.DefaultKeys (the GP test keys, also the publicly
// known YubiKey factory keys), KVN 0xFF, otherwise zero-value so
// downstream defaults apply (full security level by virtue of the
// scp03.Open default).
func TestFactorySCP03Config_HasYubiKeyShape(t *testing.T) {
	cfg := yubikey.FactorySCP03Config()
	if cfg.KeyVersion != yubikey.FactoryKeyVersion {
		t.Errorf("KeyVersion = 0x%02X, want 0x%02X", cfg.KeyVersion, yubikey.FactoryKeyVersion)
	}
	// scp03.DefaultKeys is the GP test keys (0x40..0x4F repeated).
	if cfg.Keys.ENC == nil || cfg.Keys.ENC[0] != 0x40 {
		t.Errorf("Keys.ENC = %v, want scp03.DefaultKeys (0x40..0x4F)", cfg.Keys.ENC)
	}
	// Ensure the slices are scp03.DefaultKeys, not a fresh array.
	if len(cfg.Keys.ENC) != len(scp03.DefaultKeys.ENC) {
		t.Errorf("Keys.ENC length = %d, want %d (scp03.DefaultKeys)",
			len(cfg.Keys.ENC), len(scp03.DefaultKeys.ENC))
	}
}

// TestSCP11Configs_KIDsMatchSpec pins the GP Amendment F §7.1.1 SD
// slot KIDs YubiKey allocates per SCP11 variant. A copy-paste error
// that gave SCP11aConfig the wrong KID would silently fail at
// EXTERNAL AUTHENTICATE on a real card; this test catches it
// without hardware.
func TestSCP11Configs_KIDsMatchSpec(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *scp11.Config
		wantVar scp11.Variant
		wantKID byte
	}{
		{"SCP11a", yubikey.SCP11aConfig(), scp11.SCP11a, 0x11},
		{"SCP11b", yubikey.SCP11bConfig(), scp11.SCP11b, 0x13},
		{"SCP11c", yubikey.SCP11cConfig(), scp11.SCP11c, 0x15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg.Variant != tt.wantVar {
				t.Errorf("Variant = %v, want %v", tt.cfg.Variant, tt.wantVar)
			}
			if tt.cfg.KeyID != tt.wantKID {
				t.Errorf("KeyID = 0x%02X, want 0x%02X", tt.cfg.KeyID, tt.wantKID)
			}
			if tt.cfg.SecurityLevel != channel.LevelFull {
				t.Errorf("SecurityLevel = 0x%02X, want LevelFull (0x%02X)",
					tt.cfg.SecurityLevel, channel.LevelFull)
			}
		})
	}
}

// TestSCP11bConfig_Defaults pins the SCP11b starting Config:
// SD applet AID, KVN 0x01, full security level. The variant and KID
// are covered by TestSCP11Configs_KIDsMatchSpec.
func TestSCP11bConfig_Defaults(t *testing.T) {
	cfg := yubikey.SCP11bConfig()
	if string(cfg.SelectAID) != string(scp11.AIDSecurityDomain) {
		t.Errorf("SelectAID = %X, want AIDSecurityDomain %X",
			cfg.SelectAID, scp11.AIDSecurityDomain)
	}
	if cfg.KeyVersion != 0x01 {
		t.Errorf("KeyVersion = 0x%02X, want 0x01", cfg.KeyVersion)
	}
}
