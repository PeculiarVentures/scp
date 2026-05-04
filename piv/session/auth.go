package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
	pivapdu "github.com/PeculiarVentures/scp/piv/apdu"
)

// VerifyPIN issues VERIFY against the PIV applet (NIST SP 800-73-4
// Part 2 §3.2.1). On success the session marks PIN-verified, which
// allows subsequent PIN-gated operations (GENERATE KEY, sign, etc.)
// to proceed without re-verifying.
//
// The PIN is padded to 8 bytes with 0xFF as required by the spec.
// PINs longer than 8 bytes are rejected here rather than truncated
// silently.
//
// On wrong PIN the card returns 63Cx where x is the remaining retry
// count; callers can recover the count via piv.RetriesRemaining on
// the returned error. On 6983 (PIN blocked), use UnblockPIN with
// the PUK.
func (s *Session) VerifyPIN(ctx context.Context, pin []byte) error {
	cmd, err := pivapdu.VerifyPIN(pin)
	if err != nil {
		return fmt.Errorf("VERIFY PIN: %w", err)
	}
	if _, err := s.transmit(ctx, "VERIFY PIN", cmd); err != nil {
		s.pinVerified = false
		return err
	}
	s.pinVerified = true
	return nil
}

// PINVerified reports whether VerifyPIN has succeeded on this session
// since open. Useful for callers that want to skip a redundant
// VerifyPIN before a PIN-gated batch.
func (s *Session) PINVerified() bool { return s.pinVerified }

// AuthenticateManagementKey runs PIV management-key mutual auth
// against the card, using the existing piv.MgmtKeyMutualAuth* helpers.
//
// The key.Algorithm must be in the active profile's MgmtKeyAlgs set;
// passing an algorithm the profile does not claim is refused with
// piv.ErrUnsupportedByProfile before any APDU is sent.
//
// On success the session marks mgmt-authed, which is the precondition
// for write operations (PUT CERTIFICATE, GENERATE KEY on cards that
// require mgmt auth for generate, IMPORT KEY).
//
// The two-APDU exchange is:
//
//  1. Host sends GENERAL AUTHENTICATE with empty witness slot. Card
//     returns its witness encrypted under the management key.
//  2. Host decrypts the witness, sends back a response (the decrypted
//     witness) plus a fresh challenge encrypted under the same key.
//     Card decrypts and verifies, then returns its response to the
//     host's challenge.
//
// All cryptographic primitives live in the existing piv.MgmtKey* helpers;
// this method orchestrates them.
func (s *Session) AuthenticateManagementKey(ctx context.Context, key piv.ManagementKey) error {
	caps := s.profile.Capabilities()
	if !caps.SupportsMgmtKeyAlg(key.Algorithm) {
		return fmt.Errorf("%w: management-key algorithm %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, key.Algorithm, s.profile.Name())
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("AUTH MGMT KEY: %w", err)
	}

	algoByte := key.Algorithm.Byte()

	// Step 1: request the card's witness.
	chCmd := pivapdu.MgmtKeyMutualAuthChallenge(algoByte)
	chResp, err := s.transmit(ctx, "AUTH MGMT KEY (witness request)", chCmd)
	if err != nil {
		s.mgmtAuthed = false
		return err
	}
	witness, err := pivapdu.ParseMutualAuthWitness(chResp.Data, algoByte)
	if err != nil {
		s.mgmtAuthed = false
		return fmt.Errorf("AUTH MGMT KEY: parse witness: %w", err)
	}

	// Step 2: decrypt the witness, send response + fresh challenge.
	respCmd, hostChallenge, err := pivapdu.MgmtKeyMutualAuthRespond(witness, key.Key, algoByte)
	if err != nil {
		s.mgmtAuthed = false
		return fmt.Errorf("AUTH MGMT KEY: build response: %w", err)
	}
	finalResp, err := s.transmit(ctx, "AUTH MGMT KEY (response)", respCmd)
	if err != nil {
		s.mgmtAuthed = false
		return err
	}

	// Verify the card's response to our challenge.
	if err := pivapdu.VerifyMutualAuthResponse(finalResp.Data, hostChallenge, key.Key, algoByte); err != nil {
		s.mgmtAuthed = false
		return fmt.Errorf("AUTH MGMT KEY: verify card response: %w", err)
	}

	s.mgmtAuthed = true
	return nil
}

// MgmtKeyAuthenticated reports whether AuthenticateManagementKey has
// succeeded on this session.
func (s *Session) MgmtKeyAuthenticated() bool { return s.mgmtAuthed }

// requireMgmtAuth returns piv.ErrNotAuthenticated if the session has
// not authenticated to the management key. Used as a precondition
// check on write operations.
func (s *Session) requireMgmtAuth(op string) error {
	if !s.mgmtAuthed {
		return fmt.Errorf("%s: %w (call AuthenticateManagementKey first)",
			op, piv.ErrNotAuthenticated)
	}
	return nil
}

// requirePINVerified returns piv.ErrNotAuthenticated if the session
// has not verified the PIN. Used as a precondition check on PIN-gated
// operations.
func (s *Session) requirePINVerified(op string) error {
	if !s.pinVerified {
		return fmt.Errorf("%s: %w (call VerifyPIN first)",
			op, piv.ErrNotAuthenticated)
	}
	return nil
}

// errInvalidArg is a sentinel for argument-validation errors that
// should not be wrapped as CardError.
var errInvalidArg = errors.New("invalid argument")

// ChangePIN replaces the application PIN. The card requires the
// current PIN to authorize replacement; wrong oldPIN decrements the
// retry counter the same way VerifyPIN does and returns
// piv.IsWrongPIN with retries remaining via piv.RetriesRemaining.
//
// On success the PIN-verified flag is cleared because the prior
// VERIFY (if any) is consumed; callers that need PIN-gated
// operations after a change must call VerifyPIN with the new PIN.
func (s *Session) ChangePIN(ctx context.Context, oldPIN, newPIN []byte) error {
	cmd, err := pivapdu.ChangePIN(oldPIN, newPIN)
	if err != nil {
		return fmt.Errorf("CHANGE PIN: %w", err)
	}
	if _, err := s.transmit(ctx, "CHANGE PIN", cmd); err != nil {
		return err
	}
	s.pinVerified = false
	return nil
}

// ChangePUK replaces the PUK. The card requires the current PUK to
// authorize replacement; wrong oldPUK decrements the PUK retry
// counter and returns piv.IsWrongPIN (the same SW family covers PUK
// errors at the PIN-blocked-style level).
func (s *Session) ChangePUK(ctx context.Context, oldPUK, newPUK []byte) error {
	cmd, err := pivapdu.ChangePUK(oldPUK, newPUK)
	if err != nil {
		return fmt.Errorf("CHANGE PUK: %w", err)
	}
	if _, err := s.transmit(ctx, "CHANGE PUK", cmd); err != nil {
		return err
	}
	return nil
}

// UnblockPIN uses the PUK to reset a blocked PIN to a new value
// (NIST SP 800-73-4 Part 2 §3.2.3, RESET RETRY COUNTER instruction).
//
// Wrong PUK decrements the PUK retry counter; PUK blocking on a
// YubiKey-flavored card means the only path forward is the YubiKey
// PIV reset, and on a Standard PIV card the recovery is out of band.
//
// On success the PIN retry counter resets to its factory value (3
// on YubiKey) and the PIN is set to newPIN. The session does not
// mark PIN-verified after UnblockPIN; the caller must call VerifyPIN
// with the new PIN to authorize PIN-gated operations.
func (s *Session) UnblockPIN(ctx context.Context, puk, newPIN []byte) error {
	cmd, err := pivapdu.ResetRetryCounter(puk, newPIN)
	if err != nil {
		return fmt.Errorf("UNBLOCK PIN: %w", err)
	}
	if _, err := s.transmit(ctx, "UNBLOCK PIN", cmd); err != nil {
		return err
	}
	s.pinVerified = false
	return nil
}
