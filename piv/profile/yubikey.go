package profile

import (
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
)

// YubiKeyVersion is a parsed firmware version from the YubiKey
// version object (tag 0x5FC109 under SELECT AID PIV, returned as a
// 3-byte major.minor.patch).
//
// Used by NewProbedProfile to narrow the YubiKey profile capability
// set when an older firmware is detected. Callers building a profile
// without a probe can pass a known version to NewYubiKeyProfileVersion.
type YubiKeyVersion struct {
	Major byte
	Minor byte
	Patch byte
}

// String renders the version in the conventional "M.m.p" form.
func (v YubiKeyVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast reports whether v is at least the given firmware version.
// Version comparison is lexicographic on (major, minor, patch).
func (v YubiKeyVersion) AtLeast(major, minor, patch byte) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

// IsROCAAffected reports whether v falls in the YubiKey firmware
// range that ships the Infineon RSALib version vulnerable to ROCA
// (CVE-2017-15361). Per Yubico Security Advisory YSA-2017-01, the
// affected range is 4.2.6 inclusive through 4.3.4 inclusive.
//
// Operationally, RSA keys *generated on-card* in this firmware
// range are factorable in practice (Has, Klima, Susil, Matyas,
// Nemec showed practical key-recovery attacks against the affected
// RSALib in 2017; Estonia, Slovakia, and several smartcard PKI
// programs revoked tens of millions of keys in response). ECC
// keys are unaffected. RSA keys *imported* onto the card are
// unaffected. Yubico fixed the issue in firmware 4.3.5+.
//
// This method exists so callers (CLI tools, library users running
// provisioning flows) can surface a clear advisory before any
// RSA-generation operation runs against an affected card.
func (v YubiKeyVersion) IsROCAAffected() bool {
	if v.Major != 4 {
		return false
	}
	switch {
	case v.Minor < 2:
		return false
	case v.Minor == 2:
		return v.Patch >= 6
	case v.Minor == 3:
		return v.Patch <= 4
	default: // 4.4+ (none shipped publicly, but be precise)
		return false
	}
}

// ParseYubiKeyVersion parses the 3-byte version blob YubiKey returns
// for tag 0x5FC109. The blob is exactly three bytes; anything else is
// an error.
func ParseYubiKeyVersion(b []byte) (YubiKeyVersion, error) {
	if len(b) != 3 {
		return YubiKeyVersion{}, fmt.Errorf("yubikey version: expected 3 bytes, got %d", len(b))
	}
	return YubiKeyVersion{Major: b[0], Minor: b[1], Patch: b[2]}, nil
}

// yubiKeyProfile is the YubiKey PIV applet capability description.
// Capabilities are firmware-aware: Ed25519/X25519, the AES-192
// management-key default, key move, and SCP11b-over-PIV all depend on
// firmware version.
type yubiKeyProfile struct {
	version YubiKeyVersion
	caps    Capabilities
}

// NewYubiKeyProfile returns a YubiKey profile assuming a current
// firmware (5.7.2+).
//
// # When to use this
//
// Only when you have an out-of-band guarantee that the target card
// is on YubiKey firmware 5.7.2 or later. Otherwise, prefer Probe()
// against the connected transmitter, which selects the right
// firmware-narrowed profile from a non-destructive SELECT + GET
// VERSION pair. Probe is the default path inside session.New when
// no profile is supplied.
//
// # Why the default targets 5.7+
//
// 5.7+ is the current shipping firmware family. Choosing a narrower
// default would silently disable Ed25519, X25519, and SCP11b-at-PIV
// for callers who genuinely have a current YubiKey. The trade-off
// is that calling NewYubiKeyProfile() on an older card will let
// the session attempt operations the card cannot perform, and the
// card will return 6D00 (or worse, undefined behavior).
//
// # If you do not know the firmware
//
// Use Probe(). The profile returned by Probe carries the actual
// detected firmware version and gates capabilities accordingly.
// NewYubiKeyProfile() should be reserved for callers that have
// already done the version handling themselves.
//
// For an explicit older-firmware target, use NewYubiKeyProfileVersion.
func NewYubiKeyProfile() Profile {
	return NewYubiKeyProfileVersion(YubiKeyVersion{Major: 5, Minor: 7, Patch: 2})
}

// NewYubiKeyProfileVersion returns a YubiKey profile with capabilities
// narrowed to what the given firmware version supports. Use this when
// you have firmware information out of band; otherwise prefer Probe.
func NewYubiKeyProfileVersion(v YubiKeyVersion) Profile {
	return &yubiKeyProfile{version: v, caps: yubiKeyCaps(v)}
}

// Name returns "yubikey" or "yubikey-5.4.0" form. The bare name is
// used when version detection has not happened; Probe-derived
// profiles include the firmware version for diagnostics.
func (p *yubiKeyProfile) Name() string {
	return fmt.Sprintf("yubikey-%s", p.version.String())
}

// Capabilities returns the cached capability set. Computed once at
// profile construction.
func (p *yubiKeyProfile) Capabilities() Capabilities { return p.caps }

// Version returns the firmware version this profile targets.
func (p *yubiKeyProfile) Version() YubiKeyVersion { return p.version }

// yubiKeyCaps computes the capability set for a YubiKey firmware
// version. Single source of truth for "what does YubiKey N.m.p do".
//
// Reference points:
//
//   - YubiKey 5.4.2 introduced AES-192 as the factory management-key
//     algorithm. Earlier firmware ships with the SP 800-78-4 well-known
//     3DES key.
//
//   - YubiKey 5.7.0 added Ed25519 and X25519 PIV slots and SCP11b
//     termination at the PIV applet. Earlier firmware does not support
//     either.
//
//   - YubiKey 5.7.0 also added MOVE KEY between slots.
func yubiKeyCaps(v YubiKeyVersion) Capabilities {
	algs := []piv.Algorithm{
		piv.AlgorithmRSA2048,
		piv.AlgorithmECCP256,
		piv.AlgorithmECCP384,
	}
	if v.AtLeast(5, 7, 0) {
		algs = append(algs, piv.AlgorithmEd25519, piv.AlgorithmX25519)
	}

	slots := []piv.Slot{
		piv.SlotPIVAuthentication,
		piv.SlotDigitalSignature,
		piv.SlotKeyMgmt,
		piv.SlotCardAuthentication,
		piv.SlotYubiKeyAttestation,
	}
	for s := piv.SlotRetiredKeyMgmt1; s <= piv.SlotRetiredKeyMgmt20; s++ {
		slots = append(slots, s)
	}

	defaultMgmt := piv.ManagementKeyAlg3DES
	if v.AtLeast(5, 4, 2) {
		defaultMgmt = piv.ManagementKeyAlgAES192
	}

	return Capabilities{
		StandardPIV: false,
		Algorithms:  algs,
		Slots:       slots,
		MgmtKeyAlgs: []piv.ManagementKeyAlgorithm{
			piv.ManagementKeyAlg3DES,
			piv.ManagementKeyAlgAES128,
			piv.ManagementKeyAlgAES192,
			piv.ManagementKeyAlgAES256,
		},
		DefaultMgmtKeyAlg:      defaultMgmt,
		KeyImport:              true,
		KeyDelete:              true,
		KeyMove:                v.AtLeast(5, 7, 0),
		Reset:                  true,
		Attestation:            true,
		PINPolicy:              true,
		TouchPolicy:            true,
		ProtectedManagementKey: true,
		SCP11bPIV:              v.AtLeast(5, 7, 0),
	}
}
