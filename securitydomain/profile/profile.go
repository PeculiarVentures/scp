// Package profile describes per-card Security Domain capability sets
// and supplies the host-side gating the SD session uses to refuse
// operations a card does not support before any APDU goes on the
// wire.
//
// # Goal
//
// GlobalPlatform's Security Domain interface is partly standardized
// (GP Card Spec v2.3.1) and partly extended by individual vendors.
// YubiKey's SD adds proprietary instructions for GENERATE EC KEY
// (0xF1) — useful for terminating SCP11 against an on-card-generated
// key without exposing the private bytes — and a few other
// extensions. Sending those to a card that does not support them is
// at best a 6D00 status word, at worst undefined behavior.
//
// A Profile is a small description of what a particular card class
// will actually accept. SD callers consult the active profile before
// emitting any vendor-extension APDU and refuse operations the
// profile does not claim, returning ErrUnsupportedByProfile.
//
// # Profiles shipped today
//
//   - YubiKeySDProfile: hardware-verified for YubiKey 5.x. Supports
//     SCP03 PUT KEY for AES-128 keysets, SCP11 PUT KEY for ECKA
//     P-256 keys at the SCP11 SD slots, STORE CERTIFICATES /
//     STORE DATA / GET DATA / GET KEY INFORMATION, GENERATE EC KEY
//     (Yubico extension), DELETE KEY, RESET.
//
//   - StandardSDProfile: GP Card Spec v2.3.1 + Amendment F surface
//     only. PUT KEY for SCP03/SCP11 keysets, STORE DATA for
//     certificates and allowlists, GET DATA, GET KEY INFORMATION,
//     DELETE KEY. No vendor-extension instructions.
//     Spec-implemented and protocol-correct, awaiting hardware
//     verification against a non-YubiKey GP card.
//
//   - ProbedProfile: wraps one of the above based on a non-
//     destructive probe (SELECT ISD + GET DATA on the YubiKey
//     version object 0x5FC109). Auto-detect never silently selects
//     YubiKey for a card that did not identify as one.
//
// # What this package is not
//
// This package is not a feature-detection oracle. Detection is a
// non-destructive probe (SELECT, GET DATA on a known-safe object)
// and the rest of Capabilities is per-profile static data. Anything
// that would require generating a key, decrementing a retry counter,
// or writing to the card to discover is excluded by design.
//
// # Why the SD layer mirrors piv/profile
//
// The PIV layer already established this pattern (see piv/profile/).
// The SD layer follows the same shape so a reader who's understood
// one understands the other. Capability bools gate vendor extensions;
// slot/algorithm slices enumerate the standardized surface. Operators
// see the active profile name in JSON output and check lines so
// audit logs across YubiKey and non-YubiKey deployments are
// comparable.
package profile

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/scp/apdu"
)

// ErrUnsupportedByProfile is returned when the host refuses an
// operation because the active profile does not claim it. Callers
// can errors.Is against this sentinel to distinguish "this card
// won't do it" (host-side, before any APDU) from "the card said
// no" (after APDU, returns *securitydomain.APDUError).
var ErrUnsupportedByProfile = errors.New("securitydomain/profile: operation not supported by active profile")

// Transmitter is the minimal APDU pipe the profile layer needs to
// run a probe. Satisfied by transport.Transport, by an established
// SCP session, and by mockcard.SCP03Card. Defined locally to keep
// this package free of CGo build tags from the PC/SC transport.
type Transmitter interface {
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
}

// Profile describes a card class's Security Domain capability set.
//
// Implementations are value-typed and immutable: a Profile returned
// from Standard() or YubiKey() is safe to share across goroutines
// and across sessions. The session captures the active profile at
// construction time; capability checks happen on every operation
// but the profile itself does not change mid-session.
type Profile interface {
	// Name returns a short identifier for diagnostics and machine
	// output ("yubikey-sd", "standard-sd", "probed:yubikey-sd").
	Name() string

	// Capabilities returns the static capability set for this
	// profile. The same value is returned on every call.
	Capabilities() Capabilities
}

// Capabilities enumerates what a profile claims a card will accept.
//
// Booleans gate proprietary extensions. Slices enumerate the
// standard surface (key IDs, key versions, certificate slots) the
// profile claims support for. Anything not in the slice or not
// gated true is refused host-side with ErrUnsupportedByProfile.
//
// The struct is per-profile static. Per-card detection data lives
// on ProbeResult.
type Capabilities struct {
	// StandardSD reports whether this profile is the GP Card Spec
	// v2.3.1 + Amendment F subset (true) or a vendor-extended
	// profile (false).
	StandardSD bool

	// SCP03 reports support for PUT KEY of SCP03 keysets at KID
	// 0x01. Universal across GP-conformant cards.
	SCP03 bool

	// SCP11 reports support for PUT KEY of SCP11 ECKA P-256
	// public keys at the SCP11 SD slots (KID 0x11/0x13/0x15).
	// Standard per GP Amendment F.
	SCP11 bool

	// CertificateStore reports support for storing OCE / CA
	// certificates via STORE DATA / STORE CERTIFICATES at the
	// KLOC slots (KID 0x10 / 0x20–0x2F). Standard per GP
	// Amendment F §7.1.
	CertificateStore bool

	// Allowlist reports support for the SCP11 OCE allowlist
	// (STORE DATA tag BF22 in the YubiKey profile, equivalent
	// in standard GP). Standard per GP Amendment F §7.1.5.
	Allowlist bool

	// GenerateECKey reports support for the YubiKey GENERATE EC
	// KEY instruction (INS=0xF1). NOT a GP standard instruction;
	// non-YubiKey cards will respond 6D00 (instruction not
	// supported) when this is sent. Standard PUT KEY (0xD8) with
	// host-supplied key material is the GP-spec equivalent.
	GenerateECKey bool

	// KeyDelete reports support for DELETE KEY at SD-managed key
	// references. Standard per GP Card Spec v2.3.1 §11.2.
	KeyDelete bool

	// Reset reports support for the YubiKey factory-reset
	// instruction. Standard GP cards do not implement this at
	// the SD level; recovery on those cards is out-of-band or
	// via SET STATUS to TERMINATED.
	Reset bool

	// SCP11bAuthRequired reports whether the SD this profile
	// describes requires receipt verification on SCP11b
	// (Amendment F v1.4 default). Older v1.3 cards omit the
	// receipt; the channel layer's InsecureAllowSCP11bWithoutReceipt
	// gates the difference.
	SCP11bAuthRequired bool
}
