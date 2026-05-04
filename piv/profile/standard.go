package profile

import (
	"github.com/PeculiarVentures/scp/piv"
)

// standardPIVProfile is the NIST SP 800-73-4 / SP 800-78-5 instruction
// subset. Spec-implemented and protocol-correct; awaits hardware
// verification against a non-YubiKey card before promotion to a
// "verified profile" tier in the README.
//
// What this profile claims:
//
//   - Algorithms: RSA-2048, ECC P-256, ECC P-384 (SP 800-78-4 §3.1).
//
//   - Slots: 0x9A, 0x9C, 0x9D, 0x9E, plus retired key management slots
//     0x82..0x95 (SP 800-73-4 Part 1, Table 4b).
//
//   - Management key: 3DES (SP 800-78-4 historical default) and the
//     AES family (SP 800-78-5). Default is 3DES; cards that ship with
//     an AES factory key require an out-of-band override.
//
// What this profile does not claim:
//
//   - IMPORT KEY: SP 800-73-4 has no key import instruction. Vendor
//     extensions exist (YubiKey 0xFE), but they are not standard.
//
//   - RESET: there is no applet-level reset in SP 800-73-4. Recovery
//     is handled out of band by the card management infrastructure.
//
//   - ATTEST: not standard. YubiKey-specific (0xF9, slot 0xF9).
//
//   - PIN policy / touch policy bytes on GENERATE KEY: GENERATE
//     KEY's data field in SP 800-73-4 carries only the algorithm
//     reference. Policy bytes are YubiKey extensions.
//
//   - Protected management key, key delete, key move: all
//     vendor-specific.
//
//   - SCP11b at the PIV applet: not specified by SP 800-73-4. Some
//     cards may support it, some may not; ProbedProfile narrows
//     based on what the card actually advertises.
type standardPIVProfile struct{}

// NewStandardPIVProfile returns a profile that emits only the
// SP 800-73-4 instruction subset and refuses vendor extensions.
//
// This is the safe default for an unidentified PIV card. Operations
// that go beyond the standard instruction set are refused host-side
// with piv.ErrUnsupportedByProfile so a caller does not have to
// interpret a card-specific status word.
func NewStandardPIVProfile() Profile {
	return standardPIVProfile{}
}

// Name returns "standard-piv".
func (standardPIVProfile) Name() string { return "standard-piv" }

// Capabilities returns the SP 800-73-4 / SP 800-78-5 baseline.
// Recomputed from fresh slices on each call so a caller that mutates
// the returned slices does not affect later callers.
func (standardPIVProfile) Capabilities() Capabilities {
	slots := []piv.Slot{
		piv.SlotPIVAuthentication,
		piv.SlotDigitalSignature,
		piv.SlotKeyMgmt,
		piv.SlotCardAuthentication,
	}
	for s := piv.SlotRetiredKeyMgmt1; s <= piv.SlotRetiredKeyMgmt20; s++ {
		slots = append(slots, s)
	}

	return Capabilities{
		StandardPIV: true,
		Algorithms: []piv.Algorithm{
			piv.AlgorithmRSA2048,
			piv.AlgorithmECCP256,
			piv.AlgorithmECCP384,
		},
		Slots: slots,
		MgmtKeyAlgs: []piv.ManagementKeyAlgorithm{
			piv.ManagementKeyAlg3DES,
			piv.ManagementKeyAlgAES128,
			piv.ManagementKeyAlgAES192,
			piv.ManagementKeyAlgAES256,
		},
		// SP 800-78-4 well-known default; SP 800-78-5 cards may ship
		// AES but no spec-mandated default for AES exists, so 3DES
		// remains the conservative assumption.
		DefaultMgmtKeyAlg:      piv.ManagementKeyAlg3DES,
		KeyImport:              false,
		KeyDelete:              false,
		KeyMove:                false,
		Reset:                  false,
		Attestation:            false,
		PINPolicy:              false,
		TouchPolicy:            false,
		ProtectedManagementKey: false,
		// SCP11b at the PIV applet is not specified by SP 800-73-4.
		// A specific card may support it; in that case the caller
		// should use ProbedProfile or NewYubiKeyProfile rather than
		// the bare standard profile.
		SCP11bPIV: false,
	}
}
