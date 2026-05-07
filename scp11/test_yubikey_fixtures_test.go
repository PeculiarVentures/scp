package scp11

import "github.com/PeculiarVentures/scp/channel"

// Test-only convenience constructors with the same shape as
// yubikey.SCP11{a,b,c}Config in the public API. They live here as
// _test.go-only symbols because the scp11 package cannot import
// yubikey (yubikey imports scp11 to construct *Config values, which
// would create a cycle). Production callers use the yubikey
// package; these are for internal test fixtures only.

func testYubiKeySCP11bConfig() *Config {
	return &Config{
		Variant:       SCP11b,
		SelectAID:     AIDSecurityDomain,
		KeyID:         0x13, // GP §7.1.1 SCP11b
		KeyVersion:    0x01,
		SecurityLevel: channel.LevelFull,
	}
}

func testYubiKeySCP11aConfig() *Config {
	cfg := testYubiKeySCP11bConfig()
	cfg.Variant = SCP11a
	cfg.KeyID = 0x11 // GP §7.1.1 SCP11a
	return cfg
}
