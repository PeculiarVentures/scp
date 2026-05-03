// Package scp implements GlobalPlatform Secure Channel Protocols for
// establishing authenticated and encrypted communication with smart cards.
//
// Two protocols are supported:
//
//   - SCP03 (Amendment D) — Symmetric key protocol using pre-shared AES keys.
//     Simpler to deploy but requires secure key distribution.
//
//   - SCP11 (Amendment F) — Asymmetric protocol using ECDH key agreement
//     and X.509 certificates. Three variants: SCP11a (mutual auth),
//     SCP11b (card-to-host), SCP11c (mutual auth with offline scripting).
//
// Both protocols share the same secure messaging layer (AES-CBC encryption,
// AES-CMAC authentication) and produce a Session with an identical API.
// The consumer calls Open with protocol-specific config, then uses
// Session.Transmit for all subsequent commands — the wrapping is transparent.
//
// # Quick Start
//
//	// SCP11b with mock card (for testing):
//	card, _ := mockcard.New()
//	sess, _ := scp11.Open(ctx, card.Transport(), scp11.DefaultConfig())
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
//	│  scp03.Open() / scp11.Open()    │  Protocol-specific handshake
//	├─────────────────────────────────┤
//	│  scp.Session (common interface) │  Transmit, Close
//	├─────────────────────────────────┤
//	│  channel (secure messaging)     │  Encrypt, MAC, verify
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
type Session interface {
	// Transmit sends a command through the secure channel. The command
	// is encrypted and MACed before transmission; the response is
	// verified and decrypted before being returned.
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)

	// Close terminates the session and zeros all key material.
	Close()

	// Protocol returns "SCP03" or "SCP11a" / "SCP11b" / "SCP11c".
	Protocol() string

	// SessionDEK returns a defensive copy of the Data Encryption Key
	// derived during the handshake. The DEK is used by the Security
	// Domain layer to wrap key material in PUT KEY commands (per
	// GP §11.1.4).
	//
	// Returns nil if the protocol or session has no separate DEK
	// (e.g. SCP11b without OCE-DEK key, or a closed session).
	//
	// This is intended for the securitydomain package and any custom
	// management code that needs to construct PUT KEY APDUs. It is
	// deliberately narrower than full session-key access: a caller
	// with the DEK can encrypt key material the card will accept, but
	// cannot decrypt past traffic, forge MACs, or compromise the
	// receipt chain.
	//
	// Production callers SHOULD use the securitydomain.Session API,
	// which calls this internally. Direct callers must zero the
	// returned slice when done.
	SessionDEK() []byte

	// Note: an earlier version of this interface exposed SessionKeys()
	// as a public method, with the rationale "for audit or debugging."
	// That was a footgun: examples become production code, and the
	// reference example logged S-ENC to stdout, which is a permanent
	// session compromise. Both implementations still expose the
	// material — but now via InsecureExportSessionKeysForTestOnly()
	// on the concrete type, NOT on this interface, so it can't be
	// reached through a value of interface type Session.
}
