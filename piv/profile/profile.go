// Package profile describes per-card capability sets and supplies the
// host-side gating the PIV session uses to refuse operations a card
// does not support before any APDU goes on the wire.
//
// # Goal
//
// PIV is partly standardized (NIST SP 800-73-4 / SP 800-78-4 / SP
// 800-78-5) and partly extended by individual vendors. YubiKey's PIV
// applet adds proprietary instructions for IMPORT KEY (0xFE), ATTEST
// (0xF9), RESET (0xFB), and SET MANAGEMENT KEY (0xFF), plus extensions
// to GENERATE KEY (PIN/touch policy bytes) and additional algorithms
// (Ed25519 0xE0, X25519 0xE1) on firmware 5.7+. Sending any of these
// to a card that does not support them is at best a 6D00 status word,
// at worst undefined behavior.
//
// A Profile is a small description of what a particular card class
// will actually accept. The session consults the active profile before
// emitting any APDU and refuses operations the profile does not claim,
// returning piv.ErrUnsupportedByProfile.
//
// # Profiles shipped today
//
//   - YubiKeyProfile: hardware-verified for YubiKey 5.x. Capability set
//     is firmware-aware (Ed25519/X25519 require 5.7+; AES-192 default
//     management key requires 5.4.2+; SCP11b-over-PIV requires 5.7+).
//
//   - StandardPIVProfile: NIST SP 800-73-4 instruction subset only.
//     Spec-implemented and protocol-correct. Identity detection and
//     capability classification are hardware-verified against
//     non-YubiKey PIV cards (GoldKey, Feitian, Treasury Gemalto
//     vintage 2012); cryptographic operations remain awaiting
//     hardware verification. The compatibility matrix in
//     docs/piv-compatibility.md tracks which behaviors have been
//     exercised end to end.
//
//   - ProbedProfile: wraps one of the above based on a non-destructive
//     probe (SELECT AID + GET DATA on YubiKey version object 0x5FC109).
//     Auto-detect never silently selects YubiKey for a card that did
//     not identify as one.
//
// # What this package is not
//
// This package is not a feature-detection oracle. Detection is a
// non-destructive probe (SELECT, GET DATA on a known-safe object) and
// the rest of Capabilities is per-profile static data. Anything that
// would require generating a key, decrementing a retry counter, or
// writing to the card to discover is excluded by design.
package profile

import (
	"context"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
)

// Transmitter is the minimal APDU pipe the profile layer needs.
// It is satisfied by transport.Transport, by an established SCP
// session, and by the in-tree mockcard. Defining it locally rather
// than importing transport keeps this package free of CGo build tags
// from the PC/SC transport.
type Transmitter interface {
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
}

// Profile describes a card class's PIV capability set.
//
// Implementations are expected to be value-typed and immutable: a
// Profile returned from NewYubiKeyProfile() is safe to share across
// goroutines and across sessions. The session captures the active
// profile at construction time; capability checks happen on every
// operation but the profile itself does not change mid-session.
type Profile interface {
	// Name returns a short identifier for diagnostics and machine
	// output ("yubikey", "standard-piv", "probed:yubikey-5.7.2").
	Name() string

	// Capabilities returns the static capability set for this profile.
	// The same value is returned on every call.
	Capabilities() Capabilities
}

// Capabilities enumerates what a profile claims a card will accept.
//
// Booleans gate proprietary extensions. Slices enumerate the standard
// surface (algorithms, slots, management-key algorithms) the profile
// claims support for. Anything not in the slice or not gated true is
// refused host-side with piv.ErrUnsupportedByProfile.
//
// The struct is intentionally per-profile static. Per-card detection
// data lives on ProbeResult.
type Capabilities struct {
	// StandardPIV reports whether this profile is the NIST SP 800-73-4
	// subset (true) or a vendor-extended profile (false).
	StandardPIV bool

	// Algorithms is the set of asymmetric key generation algorithms
	// this profile claims. SP 800-78-4 mandates RSA-2048, ECC P-256,
	// and ECC P-384; YubiKey adds Ed25519 and X25519 on 5.7+.
	Algorithms []piv.Algorithm

	// Slots is the set of PIV slots this profile claims. The four
	// SP 800-73-4 slots (9a, 9c, 9d, 9e) plus the 20 retired slots
	// (82..95) are standard; the attestation slot (f9) is YubiKey-only.
	Slots []piv.Slot

	// MgmtKeyAlgs is the set of algorithms accepted for the PIV
	// management key on this profile. SP 800-78-4 mandates 3DES;
	// SP 800-78-5 adds AES; YubiKey supports all four.
	MgmtKeyAlgs []piv.ManagementKeyAlgorithm

	// DefaultMgmtKeyAlg is the management-key algorithm a fresh card
	// is expected to ship with. Used by the CLI's "default" key
	// literal and by ProbedProfile to pick the right factory key
	// length.
	DefaultMgmtKeyAlg piv.ManagementKeyAlgorithm

	// KeyImport reports support for IMPORT ASYMMETRIC KEY (YubiKey
	// 0xFE). Standard PIV has no key import instruction.
	KeyImport bool

	// KeyDelete reports support for DELETE KEY (YubiKey extension).
	KeyDelete bool

	// KeyMove reports support for MOVE KEY (YubiKey 5.7+).
	KeyMove bool

	// Reset reports support for the YubiKey PIV reset instruction
	// (0xFB). Standard PIV has no applet-level reset; recovery is
	// out of band.
	Reset bool

	// Attestation reports support for the YubiKey ATTEST instruction
	// (0xF9) and the f9 attestation slot.
	Attestation bool

	// PINPolicy reports whether GENERATE KEY accepts a PIN policy
	// byte (YubiKey extension). Standard PIV's GENERATE KEY data
	// field carries only the algorithm reference.
	PINPolicy bool

	// TouchPolicy reports whether GENERATE KEY accepts a touch policy
	// byte (YubiKey extension).
	TouchPolicy bool

	// ProtectedManagementKey reports support for the PIVMAN
	// protected-management-key scheme: the PIV management key is
	// stored on the card under PIN protection so an operator can
	// authenticate with PIN-only and the management key is
	// retrieved transparently. This is a YubiKey-only behavior
	// (PIVMAN, named after Yubico's pivman tooling); it is NOT
	// part of NIST SP 800-73-4 and Standard PIV cards do not
	// implement it.
	//
	// PIVMAN uses two PIV data objects:
	//
	//   0x5FFF00  PIVMAN_DATA           — unprotected configuration
	//                                     flags (PIN policy hints,
	//                                     device-specific state).
	//   0x5FC109  PIVMAN_PROTECTED_DATA — the protected management
	//                                     key blob; lives at the
	//                                     PRINTED data object slot
	//                                     and is PIN-gated.
	//
	// This field is a capability declaration consumed by the
	// host-side profile gating layer: when false, the cmd/scpctl
	// surface refuses operations that would read or write either
	// object before any APDU is sent. The PIVMAN read/write
	// semantics themselves are NOT implemented in this library
	// today — capability declaration without implementation. If
	// a future change adds the read path, both objects above
	// must be addressed and yubikit-python's pivman.py is the
	// reference for the on-card data shape.
	//
	// Per the third external review on feat/sd-keys-cli, Section 4
	// (PIVMAN / protected management key behavior).
	ProtectedManagementKey bool

	// SCP11bPIV reports whether the card terminates an SCP11b secure
	// channel against the PIV applet directly. YubiKey 5.7+ supports
	// this; older firmware does not. Standard PIV does not specify
	// SCP11 termination at the applet level.
	SCP11bPIV bool
}

// SupportsAlgorithm reports whether a is in the profile's algorithm set.
func (c Capabilities) SupportsAlgorithm(a piv.Algorithm) bool {
	for _, x := range c.Algorithms {
		if x == a {
			return true
		}
	}
	return false
}

// SupportsSlot reports whether s is in the profile's slot set.
func (c Capabilities) SupportsSlot(s piv.Slot) bool {
	for _, x := range c.Slots {
		if x == s {
			return true
		}
	}
	return false
}

// SupportsMgmtKeyAlg reports whether m is in the profile's
// management-key algorithm set.
func (c Capabilities) SupportsMgmtKeyAlg(m piv.ManagementKeyAlgorithm) bool {
	for _, x := range c.MgmtKeyAlgs {
		if x == m {
			return true
		}
	}
	return false
}
