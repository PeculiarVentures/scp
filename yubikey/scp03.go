package yubikey

import "github.com/PeculiarVentures/scp/scp03"

// FactorySCP03Config returns an SCP03 Config wired up for a
// factory-fresh YubiKey: scp03.DefaultKeys at KVN 0xFF
// (FactoryKeyVersion), default security level. The session this
// produces has NO security because the keys are publicly known;
// the only legitimate use is the first session against a brand-new
// or freshly-reset card so the caller can rotate the key set.
//
// The deliberately verbose name (FactorySCP03Config rather than
// just SCP03Config) is the consent: typing "Factory" is the
// acknowledgement that the resulting session is not protecting
// secrets.
//
// For production SCP03 against a YubiKey, build a scp03.Config
// directly with caller-supplied keys.
func FactorySCP03Config() *scp03.Config {
	return &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: FactoryKeyVersion,
	}
}
