package session

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
)

// GenerateKeyOptions configures a GENERATE KEY call.
//
// PINPolicy and TouchPolicy are YubiKey extensions. Setting either
// to a non-default value under a profile that does not advertise
// PINPolicy / TouchPolicy is refused with piv.ErrUnsupportedByProfile.
type GenerateKeyOptions struct {
	Algorithm   piv.Algorithm
	PINPolicy   piv.PINPolicy
	TouchPolicy piv.TouchPolicy
}

// GenerateKey generates a fresh asymmetric key pair in the named
// slot and returns the parsed public key.
//
// Preconditions:
//
//   - Slot must be in the profile's slot set.
//   - Algorithm must be in the profile's algorithm set.
//   - PINPolicy and TouchPolicy must be default unless the profile
//     advertises support.
//   - The session must be management-key-authenticated. Cards that
//     do not enforce mgmt auth for generate are still required to go
//     through AuthenticateManagementKey here so the session contract
//     is consistent across cards.
//
// On success, the generated public key is cached on the session for
// the next PutCertificate call to use as the binding target.
func (s *Session) GenerateKey(ctx context.Context, slot piv.Slot, opts GenerateKeyOptions) (crypto.PublicKey, error) {
	caps := s.profile.Capabilities()

	if !caps.SupportsSlot(slot) {
		return nil, fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}
	if !caps.SupportsAlgorithm(opts.Algorithm) {
		return nil, fmt.Errorf("%w: algorithm %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, opts.Algorithm, s.profile.Name())
	}

	// Policy bytes are only legal under profiles that claim them.
	hasPolicy := opts.PINPolicy != 0 || opts.TouchPolicy != 0
	if hasPolicy {
		if opts.PINPolicy != 0 && !caps.PINPolicy {
			return nil, fmt.Errorf("%w: PIN policy not supported by profile %s",
				piv.ErrUnsupportedByProfile, s.profile.Name())
		}
		if opts.TouchPolicy != 0 && !caps.TouchPolicy {
			return nil, fmt.Errorf("%w: touch policy not supported by profile %s",
				piv.ErrUnsupportedByProfile, s.profile.Name())
		}
	}

	if err := s.requireMgmtAuth("GENERATE KEY"); err != nil {
		return nil, err
	}

	var cmd = piv.GenerateKey(slot.Byte(), opts.Algorithm.Byte())
	if hasPolicy {
		cmd = piv.GenerateKeyWithPolicy(
			slot.Byte(),
			opts.Algorithm.Byte(),
			opts.PINPolicy.Byte(),
			opts.TouchPolicy.Byte(),
		)
	}

	resp, err := s.transmit(ctx, "GENERATE KEY", cmd)
	if err != nil {
		return nil, err
	}

	pub, err := piv.ParseGeneratedPublicKey(resp.Data, opts.Algorithm.Byte())
	if err != nil {
		return nil, fmt.Errorf("GENERATE KEY: parse response: %w", err)
	}

	// Cache for the next PutCertificate's binding check.
	s.lastGeneratedSlot = slot
	s.lastGeneratedPubKey = pub
	s.lastGeneratedSet = true

	return pub, nil
}

// LastGeneratedPublicKey returns the public key from the most recent
// successful GenerateKey, plus the slot it was generated in. Returns
// (nil, 0, false) if no key has been generated on this session.
//
// Used by PutCertificate's default binding check and by tests.
func (s *Session) LastGeneratedPublicKey() (crypto.PublicKey, piv.Slot, bool) {
	if !s.lastGeneratedSet {
		return nil, 0, false
	}
	return s.lastGeneratedPubKey, s.lastGeneratedSlot, true
}

// PutCertificateOptions configures a PUT CERTIFICATE call.
//
// RequirePubKeyBinding turns on the cert-to-public-key check: the
// certificate's SubjectPublicKeyInfo must equal the public key for
// the slot. The expected public key comes from ExpectedPublicKey
// (caller-supplied, the usual case) or from LastGeneratedPublicKey
// (when a generate-then-install flow uses the same slot in one
// session).
type PutCertificateOptions struct {
	// RequirePubKeyBinding refuses to install a certificate whose
	// public key does not match the expected key. Highly recommended
	// for production provisioning paths.
	RequirePubKeyBinding bool

	// ExpectedPublicKey is the public key the certificate must bind
	// to. If nil and RequirePubKeyBinding is true, the session uses
	// the public key from the most recent GenerateKey on the same
	// slot (if any); if no such key exists, PutCertificate returns
	// an error rather than silently disabling the binding check.
	ExpectedPublicKey crypto.PublicKey
}

// PutCertificate installs a certificate in a PIV slot.
//
// Preconditions:
//
//   - Slot must be in the profile's slot set.
//   - The session must be management-key-authenticated.
//   - If RequirePubKeyBinding is set, the certificate's public key
//     must equal the expected public key for the slot. The check
//     happens in the library, not at the wire, so a mismatch never
//     touches the card.
func (s *Session) PutCertificate(ctx context.Context, slot piv.Slot, cert *x509.Certificate, opts PutCertificateOptions) error {
	if cert == nil {
		return fmt.Errorf("PUT CERTIFICATE: %w: cert is nil", errInvalidArg)
	}

	caps := s.profile.Capabilities()
	if !caps.SupportsSlot(slot) {
		return fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}

	if opts.RequirePubKeyBinding {
		expected := opts.ExpectedPublicKey
		if expected == nil {
			cached, cachedSlot, ok := s.LastGeneratedPublicKey()
			if !ok || cachedSlot != slot {
				return fmt.Errorf(
					"PUT CERTIFICATE: binding check requested but no expected public key supplied and no recent generate on slot %s",
					slot)
			}
			expected = cached
		}
		if !piv.PublicKeysEqual(cert.PublicKey, expected) {
			return fmt.Errorf("PUT CERTIFICATE: certificate public key does not match expected key for slot %s",
				slot)
		}
	}

	if err := s.requireMgmtAuth("PUT CERTIFICATE"); err != nil {
		return err
	}

	cmd, err := piv.PutCertificate(slot.Byte(), cert)
	if err != nil {
		return fmt.Errorf("PUT CERTIFICATE: build: %w", err)
	}
	if _, err := s.transmit(ctx, "PUT CERTIFICATE", cmd); err != nil {
		return err
	}
	return nil
}

// Attest fetches a YubiKey attestation certificate for a slot.
//
// Refused under any profile that does not advertise Attestation
// (currently anything that is not YubiKey). The attestation slot
// itself (0xF9) does not need to be in the profile slot set;
// attestation is about a different slot's key, not the attestation
// slot.
func (s *Session) Attest(ctx context.Context, slot piv.Slot) (*x509.Certificate, error) {
	caps := s.profile.Capabilities()
	if !caps.Attestation {
		return nil, fmt.Errorf("%w: attestation not supported by profile %s",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	if !caps.SupportsSlot(slot) {
		return nil, fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}

	cmd := piv.Attest(slot.Byte())
	resp, err := s.transmit(ctx, "ATTEST", cmd)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("ATTEST: parse certificate: %w", err)
	}
	return cert, nil
}

// ResetOptions configures a Reset call. Empty today; reserved for
// future flags (e.g. confirm tokens).
type ResetOptions struct{}

// Reset issues the YubiKey PIV reset (INS=0xFB), erasing all slot
// keys, certificates, the management key (back to factory), and
// resetting PIN/PUK to factory values.
//
// Refused under profiles that do not advertise Reset. The card-side
// precondition (PIN and PUK both blocked) is the caller's
// responsibility; the session does not block them automatically
// because doing so requires deliberately exhausting retry counters
// and that should be an explicit caller decision, not a session-
// internal step.
func (s *Session) Reset(ctx context.Context, _ ResetOptions) error {
	caps := s.profile.Capabilities()
	if !caps.Reset {
		return fmt.Errorf("%w: reset not supported by profile %s",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	cmd := piv.Reset()
	if _, err := s.transmit(ctx, "RESET", cmd); err != nil {
		return err
	}
	// Clear authentication state.
	s.pinVerified = false
	s.mgmtAuthed = false
	s.lastGeneratedSet = false
	return nil
}

// Sentinel imports kept reachable.
var _ = errors.New
