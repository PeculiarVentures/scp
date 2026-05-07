package profile

// YubiKey returns the YubiKeySDProfile describing YubiKey 5.x's
// Security Domain surface as exercised by the .NET Yubico SDK,
// yubikit, and ykman.
//
// Verified against YubiKey hardware end-to-end and byte-exact
// against the Yubico .NET SDK channel + KDF vectors and against
// martinpaljak/GlobalPlatformPro JCOP4 dumps. See README.md's
// "verified profiles" section for the full accountability
// breakdown.
//
// Capabilities returned true:
//
//   - StandardSD: false (this is a vendor-extended profile)
//   - SCP03, SCP11, CertificateStore, Allowlist, KeyDelete: as
//     standard, all implemented
//   - GenerateECKey: yes — INS=0xF1 generates a P-256 keypair
//     on-card at one of the SCP11 SD slots and returns the SPKI;
//     the private key never crosses the wire. This is a Yubico
//     extension not present in GP Card Spec v2.3.1; non-YubiKey
//     cards will respond 6D00 to this INS.
//   - Reset: yes — YubiKey supports factory-reset of SD key
//     material via the SD reset instruction. Other GP cards
//     typically use SET STATUS TERMINATED, which is a different
//     surface (irreversible, brick-on-failure).
//   - SCP11bAuthRequired: true — YubiKey 5.x firmware requires
//     receipt verification per Amendment F v1.4. Pre-5.x firmware
//     omits the receipt and is reachable only via the channel
//     layer's InsecureAllowSCP11bWithoutReceipt option.
func YubiKey() Profile {
	return yubikeySDProfile{}
}

type yubikeySDProfile struct{}

func (yubikeySDProfile) Name() string { return "yubikey-sd" }

func (yubikeySDProfile) Capabilities() Capabilities {
	return Capabilities{
		StandardSD:         false,
		SCP03:              true,
		SCP11:              true,
		CertificateStore:   true,
		Allowlist:          true,
		GenerateECKey:      true, // INS=0xF1
		KeyDelete:          true,
		Reset:              true, // YubiKey factory-reset
		SCP11bAuthRequired: true, // Amendment F v1.4
	}
}
