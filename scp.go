// Package scp implements GlobalPlatform Secure Channel Protocols for
// establishing authenticated and encrypted communication with smart cards.
//
// Two protocols are supported:
//
//   - SCP03 (Amendment D) — Symmetric key protocol using pre-shared AES
//     keys. Simpler to deploy but requires secure key distribution.
//
//   - SCP11 (Amendment F) — Asymmetric protocol using ECDH key agreement
//     and X.509 certificates. Three variants: SCP11a (mutual auth),
//     SCP11b (card-to-host), SCP11c (mutual auth with offline scripting).
//
// Both protocols share the same secure messaging layer (AES-CBC
// encryption, AES-CMAC authentication) and produce a Session with an
// identical API. The consumer calls Open with protocol-specific config,
// then uses Session.Transmit for all subsequent commands — the wrapping
// is transparent.
//
// # Assurance categories
//
// The library is vendor-neutral by design. Protocol behavior is
// implemented against GP / ISO specs, and verified hardware profiles
// are named explicitly rather than baked into the API surface.
// Configuration helpers for a specific card vendor live in their own
// peer package (see the yubikey package); additional verified
// profiles will land as additional peer packages, not by extending
// vendor-named symbols inside the protocol packages.
//
// Three assurance categories describe what the library promises:
//
//   - Verified profiles: behavior validated against hardware AND an
//     independent reference implementation. YubiKey is the currently
//     verified profile, covering SCP03 AES-128 end-to-end, SCP11
//     P-256 / AES-128 / S8 / full security level end-to-end, the
//     pad-and-encrypt empty-data behavior at the channel layer, and
//     the YubiKey Security Domain management API surface.
//
//   - Implemented GlobalPlatform capabilities: standards-compatible
//     behavior implemented against the GP / ISO specs and exercisable
//     today against any conformant card. Includes SCP03 AES-128 /
//     192 / 256, SCP03 S8 + S16, configurable empty-data behavior,
//     X.509 SCP11 card trust validation, custom validation for
//     GP-proprietary SCP11 certificate stores via
//     trust.Policy.CustomValidator, short and extended APDUs, GET
//     RESPONSE chaining, BER-TLV parsing, and transport-independent
//     APDU construction.
//
//   - Expansion targets: in-scope work waiting on additional cards or
//     reference material. Includes additional non-YubiKey GP cards as
//     verified profiles, Java Card security domains, additional vendor
//     certificate-store formats, SCP03 AES-192 / 256 management
//     profiles, SCP03 S16 hardware validation, SCP11 HostID /
//     CardGroupID wire behavior (AUTHENTICATE parameter bit, tag
//     0x84, KDF shared-info), broader logical-channel behavior
//     end-to-end against real cards, and additional Security Domain
//     management profiles.
//
// See the project README for the detailed assurance breakdown.
//
// # Quick Start
//
//	// SCP11b with mock card (for testing). Mock cards are not
//	// real hardware; the trust posture is opted out explicitly so
//	// the example is runnable. Production code MUST set
//	// CardTrustPolicy or CardTrustAnchors instead.
//	card, _ := mockcard.New()
//	cfg := yubikey.SCP11bConfig()
//	cfg.InsecureSkipCardAuthentication = true
//	sess, _ := scp11.Open(ctx, card.Transport(), cfg)
//	defer sess.Close()
//
//	// SCP03 with static keys:
//	sess, _ := scp03.Open(ctx, transport, &scp03.Config{
//	    Keys: scp03.StaticKeys{ENC: encKey, MAC: macKey, DEK: dekKey},
//	})
//	defer sess.Close()
//
//	// Both return scp.Session — same Transmit API:
//	resp, _ := sess.Transmit(ctx, myCommand)
//
// # Architecture
//
// The library is layered so each component can be used independently:
//
//	┌─────────────────────────────────┐
//	│  scp03.Open() / scp11.Open()  │  Protocol-specific handshake
//	├─────────────────────────────────┤
//	│  scp.Session (common interface) │  Transmit, Close
//	├─────────────────────────────────┤
//	│  channel (secure messaging)     │  Encrypt, MAC, verify;
//	│                                 │  ISO 7816-4 CLA / logical
//	│                                 │  channel encoding
//	├─────────────────────────────────┤
//	│  kdf / cmac / tlv / apdu        │  Shared primitives
//	├─────────────────────────────────┤
//	│  transport.Transport            │  PC/SC, NFC, gRPC relay, mock
//	└─────────────────────────────────┘
package scp

import (
	"context"

	"github.com/PeculiarVentures/scp/apdu"
)

// Session is the common interface for an established secure channel,
// regardless of whether it was created via SCP03 or SCP11.
//
// After Open returns a Session, every command sent through Transmit
// is automatically encrypted and MACed. The consumer does not need
// to know which protocol is in use.
//
// The interface is deliberately narrow. Capabilities like the
// session DEK or OCE-authentication state are exposed by the
// concrete *scp03.Session and *scp11.Session types and accessed
// by the securitydomain package through type assertions on
// unexported capability interfaces. That keeps key material out
// of the broad public abstraction: a caller holding a generic
// scp.Session cannot reach into key bytes.
type Session interface {
	// Transmit sends a command through the secure channel. The command
	// is encrypted and MACed before transmission; the response is
	// verified and decrypted before being returned.
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)

	// Close terminates the session and zeros all key material.
	Close()

	// Protocol returns "SCP03" or "SCP11a" / "SCP11b" / "SCP11c".
	// This is intended for diagnostics and logging, not for
	// authorization decisions — the securitydomain package gates
	// management operations through typed capability checks on the
	// concrete session, not on this string.
	Protocol() string

	// Note: an earlier version of this interface exposed SessionKeys()
	// as a public method, with the rationale "for audit or debugging."
	// That was a footgun: examples become production code, and the
	// reference example logged S-ENC to stdout, which is a permanent
	// session compromise. A subsequent iteration exposed SessionDEK()
	// here for the Security Domain PUT KEY path; that was also a
	// footgun, because the DEK is enough to encrypt key material the
	// card will accept. Both are now reachable only through the
	// concrete *scp03.Session / *scp11.Session types — for tests
	// via InsecureExportSessionKeysForTestOnly(), and for the
	// securitydomain package via unexported capability interfaces.
}
