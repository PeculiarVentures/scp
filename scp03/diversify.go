package scp03

import (
	"fmt"

	"github.com/PeculiarVentures/scp/kdf"
)

// Static key diversification derives a per-card SCP03 key set from
// a master key set plus a card-unique value (typically the CSN /
// IIN+CIN read out of GP card-recognition data). The construction
// is NIST SP 800-108 counter-mode KDF with AES-CMAC as the PRF —
// the same primitive GP Amendment D specifies for session-key
// derivation, applied here at the static-key level.
//
// Why this matters: a fleet of cards personalized from a single
// master key set is operationally fragile (compromise of one card
// compromises the whole fleet). Diversification breaks that
// coupling: each card has its own ENC/MAC/DEK derived from the
// master plus its own serial number, so leaking one card's keys
// does not let an attacker forge sessions against any other card.
//
// The Diversify function below implements one publicly-documented
// scheme — NIST SP 800-108 counter-mode KDF with role-specific
// labels chosen to be distinct from session-key derivation
// constants (which are 0x04/0x06/0x07 in GP Amendment D). Vendor
// pre-personalized cards typically use vendor-specific schemes
// (NXP JCOP, G&D, Athena each differ in label byte choice and
// fixed-input layout); compatibility with a vendor-personalized
// card requires using that vendor's scheme. Use Diversify when
// both sides of a deployment agree on this scheme.

// Static key derivation labels per role. Distinct from the
// session-key derivation constants used by GP SCP03 Amendment D
// (0x04 S-ENC, 0x06 S-MAC, 0x07 S-RMAC) so a careless caller who
// mixes session and static derivation cannot accidentally produce
// colliding outputs from the same master key.
const (
	staticDivLabelENC byte = 0x10
	staticDivLabelMAC byte = 0x11
	staticDivLabelDEK byte = 0x12
)

// Diversify derives a per-card SCP03 static key set from master
// keys plus a card-unique value csn (Card Serial Number, typically
// the IIN+CIN bytes from the card's recognition data, but any
// non-empty unique value works).
//
// All three master keys (ENC, MAC, DEK) must have the same length:
// 16, 24, or 32 bytes (AES-128, -192, or -256). Mixed lengths
// return an error rather than silently producing keys that differ
// in length from the master, which would lead to confusing
// downstream failures.
//
// The diversification is deterministic: the same master+csn pair
// always produces the same diversified keys. To rotate keys on a
// card, change either the master key set or the CSN value the
// caller agrees to use.
//
// Returns ErrInvalidConfig if the input lengths don't satisfy
// the invariants above.
func Diversify(master StaticKeys, csn []byte) (StaticKeys, error) {
	if len(master.ENC) == 0 || len(master.MAC) == 0 || len(master.DEK) == 0 {
		return StaticKeys{}, fmt.Errorf("%w: all master keys must be non-empty", ErrInvalidConfig)
	}
	if len(master.ENC) != len(master.MAC) || len(master.MAC) != len(master.DEK) {
		return StaticKeys{}, fmt.Errorf("%w: master keys must all have the same length (got ENC=%d MAC=%d DEK=%d)",
			ErrInvalidConfig, len(master.ENC), len(master.MAC), len(master.DEK))
	}
	switch len(master.ENC) {
	case 16, 24, 32:
	default:
		return StaticKeys{}, fmt.Errorf("%w: master key length must be 16, 24, or 32 bytes (AES-128/192/256), got %d",
			ErrInvalidConfig, len(master.ENC))
	}
	if len(csn) == 0 {
		return StaticKeys{}, fmt.Errorf("%w: csn cannot be empty", ErrInvalidConfig)
	}
	keyLenBits := len(master.ENC) * 8

	enc, err := kdf.DeriveSCP03SessionKey(master.ENC, staticDivLabelENC, csn, keyLenBits)
	if err != nil {
		return StaticKeys{}, fmt.Errorf("ENC key diversification: %w", err)
	}
	mac, err := kdf.DeriveSCP03SessionKey(master.MAC, staticDivLabelMAC, csn, keyLenBits)
	if err != nil {
		return StaticKeys{}, fmt.Errorf("MAC key diversification: %w", err)
	}
	dek, err := kdf.DeriveSCP03SessionKey(master.DEK, staticDivLabelDEK, csn, keyLenBits)
	if err != nil {
		return StaticKeys{}, fmt.Errorf("DEK key diversification: %w", err)
	}
	return StaticKeys{ENC: enc, MAC: mac, DEK: dek}, nil
}
