package session

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
	pivapdu "github.com/PeculiarVentures/scp/piv/apdu"
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

	var cmd = pivapdu.GenerateKey(slot.Byte(), opts.Algorithm.Byte())
	if hasPolicy {
		cmd = pivapdu.GenerateKeyWithPolicy(
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

	pub, err := pivapdu.ParseGeneratedPublicKey(resp.Data, opts.Algorithm.Byte())
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
		if !pivapdu.PublicKeysEqual(cert.PublicKey, expected) {
			return fmt.Errorf("PUT CERTIFICATE: certificate public key does not match expected key for slot %s",
				slot)
		}
	}

	if err := s.requireMgmtAuth("PUT CERTIFICATE"); err != nil {
		return err
	}

	cmd, err := pivapdu.PutCertificate(slot.Byte(), cert)
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

	cmd := pivapdu.Attest(slot.Byte())
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
//
// Callers who want the full block-then-reset sequence in one call
// can run BlockPIN, BlockPUK, then Reset in sequence. Each step
// is a public method so the caller can interleave reporting
// between them.
func (s *Session) Reset(ctx context.Context, _ ResetOptions) error {
	caps := s.profile.Capabilities()
	if !caps.Reset {
		return fmt.Errorf("%w: reset not supported by profile %s",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	cmd := pivapdu.Reset()
	if _, err := s.transmit(ctx, "RESET", cmd); err != nil {
		return err
	}
	// Clear authentication state.
	s.pinVerified = false
	s.mgmtAuthed = false
	s.lastGeneratedSet = false
	return nil
}

// BlockPIN intentionally exhausts the PIV PIN retry counter by
// sending VERIFY PIN with deliberately-wrong PIN values until the
// card returns SW=6983 ("authentication method blocked"). Returns
// the number of wrong-PIN attempts that were sent.
//
// This is the YubiKey-required precondition for Reset: the card
// only accepts INS=0xFB (PIV reset) once both PIN and PUK are
// blocked. Used by 'scpctl piv reset' and 'scpctl smoke piv-reset'
// so callers don't have to reach into raw transport for the
// blocking loop.
//
// maxAttempts caps the loop so a card returning unexpected status
// doesn't loop forever. YubiKey defaults to 3 PIN tries; cards
// configured with high retry counts should pass a larger value
// (Yubico supports up to 255). maxAttempts must be >= 1.
//
// Refused under profiles that do not advertise Reset, since
// blocking PIN without a follow-up reset path is destructive
// without recovery.
func (s *Session) BlockPIN(ctx context.Context, maxAttempts int) (int, error) {
	if maxAttempts < 1 {
		return 0, fmt.Errorf("BlockPIN: maxAttempts must be >= 1; got %d", maxAttempts)
	}
	caps := s.profile.Capabilities()
	if !caps.Reset {
		return 0, fmt.Errorf("%w: BlockPIN is the precondition for Reset; "+
			"refused under profiles that do not advertise Reset (got %s)",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	wrong := []byte("00000000")
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd, err := pivapdu.VerifyPIN(wrong)
		if err != nil {
			return attempt - 1, fmt.Errorf("build VERIFY PIN: %w", err)
		}
		// Don't go through s.transmit: that turns 63Cx and 6983 into
		// errors, but we EXPECT both. Use the underlying tx directly,
		// which mirrors the smoke piv-reset path. Chaining is irrelevant
		// here because VERIFY PIN never produces 61xx responses.
		resp, err := s.tx.Transmit(ctx, cmd)
		if err != nil {
			return attempt - 1, fmt.Errorf("transmit VERIFY PIN attempt %d: %w", attempt, err)
		}
		sw := resp.StatusWord()
		// 6983 = authentication method blocked. Done.
		if sw == 0x6983 {
			s.pinVerified = false
			return attempt, nil
		}
		// 63XX = wrong PIN; the low byte carries the retry counter.
		// Real YubiKey returns 0x63CX (high nibble C indicates PIN-
		// related counter); mock cards may return 0x630X. Either
		// way SW1=0x63 is the continue signal, matching the
		// existing scp11-side helper in cmd_piv_reset.
		if resp.SW1 == 0x63 {
			continue
		}
		// 9000 = the card accepted "00000000" as the PIN. Operator
		// is in an unexpected state; abort rather than continuing.
		if sw == 0x9000 {
			s.pinVerified = true
			return attempt, fmt.Errorf("BlockPIN: card accepted '%s' as PIN on attempt %d; "+
				"refusing to continue because PIN is now valid, not blocked",
				string(wrong), attempt)
		}
		return attempt, fmt.Errorf("BlockPIN: unexpected SW=%04X on attempt %d", sw, attempt)
	}
	return maxAttempts, fmt.Errorf("BlockPIN: PIN not blocked after %d attempts; "+
		"raise maxAttempts if the card has a higher retry count", maxAttempts)
}

// BlockPUK intentionally exhausts the PIV PUK retry counter by
// sending RESET RETRY COUNTER with a deliberately-wrong PUK until
// the card returns SW=6983. Returns the number of wrong-PUK
// attempts that were sent.
//
// PUK is exercised through INS=0x2C (RESET RETRY COUNTER). Each
// attempt also supplies a "new PIN" value (which the card never
// applies because the PUK check fails first). The new-PIN value
// here is a deliberate placeholder ("11111111") that wouldn't be
// accepted by Yubico's PIN complexity check anyway; it will never
// be applied because the wrong PUK rejects every attempt.
//
// Same maxAttempts and profile-capability semantics as BlockPIN.
func (s *Session) BlockPUK(ctx context.Context, maxAttempts int) (int, error) {
	if maxAttempts < 1 {
		return 0, fmt.Errorf("BlockPUK: maxAttempts must be >= 1; got %d", maxAttempts)
	}
	caps := s.profile.Capabilities()
	if !caps.Reset {
		return 0, fmt.Errorf("%w: BlockPUK is the precondition for Reset; "+
			"refused under profiles that do not advertise Reset (got %s)",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	wrongPUK := []byte("00000000")
	dummyPIN := []byte("11111111")
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd, err := pivapdu.ResetRetryCounter(wrongPUK, dummyPIN)
		if err != nil {
			return attempt - 1, fmt.Errorf("build RESET RETRY COUNTER: %w", err)
		}
		resp, err := s.tx.Transmit(ctx, cmd)
		if err != nil {
			return attempt - 1, fmt.Errorf("transmit RESET RETRY COUNTER attempt %d: %w", attempt, err)
		}
		sw := resp.StatusWord()
		if sw == 0x6983 {
			return attempt, nil
		}
		// 63XX = wrong PUK; the low byte carries the retry counter.
		// Same loose match as BlockPIN: real YubiKey uses 0x63CX,
		// some implementations 0x630X. SW1=0x63 is the continue
		// signal.
		if resp.SW1 == 0x63 {
			continue
		}
		if sw == 0x9000 {
			// Wrong PUK was accepted — should never happen with the
			// fixed wrong value above. If a card lets "00000000"
			// through, the PIN now equals dummyPIN, which will likely
			// fail Yubico's complexity validation later but isn't
			// blocked. Abort rather than masking the surprise.
			return attempt, fmt.Errorf("BlockPUK: card accepted '%s' as PUK on attempt %d; "+
				"PIN may now be %q, not blocked", string(wrongPUK), attempt, string(dummyPIN))
		}
		return attempt, fmt.Errorf("BlockPUK: unexpected SW=%04X on attempt %d", sw, attempt)
	}
	return maxAttempts, fmt.Errorf("BlockPUK: PUK not blocked after %d attempts; "+
		"raise maxAttempts if the card has a higher retry count", maxAttempts)
}

// Sentinel imports kept reachable.
var _ = errors.New
