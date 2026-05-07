package yubikey

import (
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/scp11"
)

// SCP11bConfig returns a starting Config for SCP11b (one-way
// card-to-host authentication) tuned for YubiKey defaults: SD
// applet, KID 0x13 (the GP Amendment F §7.1.1 SCP11b slot YubiKey
// allocates), KVN 0x01, full security level, and the channel-layer
// pad-and-encrypt empty-data policy that comes from the zero value
// of channel.EmptyDataPolicy. Verified end-to-end against
// YubiKey 5.x.
//
// The caller still has to configure card-trust validation: set
// CardTrustPolicy or CardTrustAnchors, or
// InsecureSkipCardAuthentication for tests and labs.
//
// For spec-literal defaults that do not bake in YubiKey
// assumptions, see scp11.StrictGPSCP11bConfig.
func SCP11bConfig() *scp11.Config {
	return &scp11.Config{
		Variant:       scp11.SCP11b,
		SelectAID:     scp11.AIDSecurityDomain,
		KeyID:         0x13, // GP §7.1.1 SCP11b
		KeyVersion:    0x01,
		SecurityLevel: channel.LevelFull,
	}
}

// SCP11aConfig returns a starting Config for SCP11a (mutual
// authentication via OCE certificate chain) tuned for YubiKey.
// KeyID is set to the GP Amendment F §7.1.1 SCP11a slot (0x11).
// Caller fills in OCEPrivateKey, OCECertificates, OCEKeyReference,
// and CardTrustPolicy / CardTrustAnchors.
//
// For spec-literal defaults, see scp11.StrictGPSCP11aConfig.
func SCP11aConfig() *scp11.Config {
	cfg := SCP11bConfig()
	cfg.Variant = scp11.SCP11a
	cfg.KeyID = 0x11 // GP §7.1.1 SCP11a
	return cfg
}

// SCP11cConfig returns a starting Config for SCP11c (mutual
// authentication with offline scripting) tuned for YubiKey. KeyID
// is set to the GP Amendment F §7.1.1 SCP11c slot (0x15). Same
// OCE / trust caveats as SCP11aConfig.
//
// For spec-literal defaults, see scp11.StrictGPSCP11cConfig.
func SCP11cConfig() *scp11.Config {
	cfg := SCP11bConfig()
	cfg.Variant = scp11.SCP11c
	cfg.KeyID = 0x15 // GP §7.1.1 SCP11c
	return cfg
}
