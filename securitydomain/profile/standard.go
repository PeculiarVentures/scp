package profile

// Standard returns the StandardSDProfile describing the GP Card
// Spec v2.3.1 + Amendment F surface. Spec-implemented and
// protocol-correct against any GP-conformant card; awaiting
// hardware verification before being moved to a verified profile
// in the project README's assurance-levels classification.
//
// Capability bools deliberately exclude vendor extensions. A card
// that this profile is targeted at and that claims to be GP-
// conformant should accept every capability returned true here:
//
//   - SCP03: yes (GP Card Spec §11.1)
//   - SCP11: yes (GP Amendment F §6, §7)
//   - CertificateStore: yes (GP Amendment F §7.1.4)
//   - Allowlist: yes (GP Amendment F §7.1.5)
//   - KeyDelete: yes (GP Card Spec §11.2)
//
// Capabilities deliberately false:
//
//   - GenerateECKey: NO. INS=0xF1 is a Yubico extension; standard
//     GP defines on-card key generation only via PUT KEY with
//     special parameters that vary by card and are not portable.
//     Operators wanting on-card key generation against a non-
//     YubiKey card need to either upgrade the active profile
//     after vendor docs are confirmed or send PUT KEY with
//     host-generated key material.
//
//   - Reset: NO. Factory reset is a YubiKey-specific operation;
//     standard GP recovery uses SET STATUS to TERMINATED, which
//     is irreversible and is not the same surface.
func Standard() Profile {
	return standardSDProfile{}
}

type standardSDProfile struct{}

func (standardSDProfile) Name() string { return "standard-sd" }

func (standardSDProfile) Capabilities() Capabilities {
	return Capabilities{
		StandardSD:         true,
		SCP03:              true,
		SCP11:              true,
		CertificateStore:   true,
		Allowlist:          true,
		GenerateECKey:      false, // INS=0xF1 is Yubico-specific
		KeyDelete:          true,
		Reset:              false, // YubiKey factory-reset is vendor-specific
		SCP11bAuthRequired: true,  // Amendment F v1.4 baseline
	}
}
