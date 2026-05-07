package scp03

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for SCP03 session establishment and operation.
//
// Callers can use errors.Is to discriminate the cause of an Open or
// Transmit failure without pattern-matching on message text:
//
//	sess, err := scp03.Open(ctx, t, cfg)
//	switch {
//	case errors.Is(err, scp03.ErrAuthFailed):
//	    // Wrong keys or compromised handshake; a retry with the
//	    // same keys will not succeed.
//	case errors.Is(err, scp03.ErrInvalidConfig):
//	    // Caller-side bug; fix the Config and retry.
//	case errors.Is(err, scp03.ErrInvalidResponse):
//	    // Card returned a malformed response; check that the
//	    // SELECTed applet actually implements SCP03, and that
//	    // the transport is not corrupting bytes.
//	}
//
// Wrapped errors carry the original descriptive message so logs and
// debug output remain useful. ErrAuthFailed in particular often wraps
// a CryptogramMismatchError that carries expected and actual bytes
// for diagnostic comparison; see CryptogramMismatchError below.
var (
	// ErrAuthFailed indicates handshake authentication failed: the
	// card's cryptogram did not match the host's expected value, or
	// the host's cryptogram was rejected by the card. Almost always
	// means the keys configured on the host do not match the keys
	// on the card; a retry with the same keys will not succeed.
	ErrAuthFailed = errors.New("scp03: authentication failed")

	// ErrInvalidConfig indicates Open was called with a Config that
	// failed validation: missing keys, wrong key length, mismatched
	// key sizes, missing transport, rejected security level, etc.
	// Wraps a more specific message describing which check failed.
	ErrInvalidConfig = errors.New("scp03: invalid configuration")

	// ErrInvalidResponse indicates the card returned a malformed or
	// unexpectedly-shaped response during the handshake. Common
	// causes are wrong applet (SELECT a different AID), a card that
	// does not implement SCP03, or transport-level corruption.
	ErrInvalidResponse = errors.New("scp03: invalid response from card")
)

// CryptogramMismatchError is returned (wrapped behind ErrAuthFailed)
// when the card cryptogram the card sends in its INITIALIZE UPDATE
// response does not match the value the host computed from its
// configured keys. The expected and received cryptogram bytes are
// preserved on the error so an operator can compare them against a
// reference implementation (gppro, the GP Amendment D §6.2.2 vectors,
// a vendor key sheet, etc.) without re-running the handshake.
//
// Re-running the handshake with the same keys would not succeed —
// the cryptogram is a deterministic function of the keys, the host
// challenge, the card challenge, and the SCP03 KDF — so a retry
// just consumes another slot of the card's failed-authentication
// counter. Real cards lock the ISD permanently when the counter
// hits zero. SafeNet eToken family carries an 80-attempt counter
// (per the FIPS 140-2 Security Policy for the platform); other
// cards can have counters as low as 10. Callers should treat this
// error as terminal for the supplied key set and surface the
// expected/received bytes to the operator for triage.
//
// The error's Error() output mirrors gppro's format so logs from
// scpctl and gppro against the same card are visually comparable:
//
//	scp03: card cryptogram mismatch (wrong keys or compromised handshake)
//	  Received: 76532D72CF9DE05F
//	  Expected: B2F392D2CFB9A459
//	  Do not re-try the same keys — the card's failed-auth counter
//	  is finite and a brick is the consequence of exhausting it.
//
// Use errors.As to inspect:
//
//	var cm *scp03.CryptogramMismatchError
//	if errors.As(err, &cm) {
//	    log.Printf("expected=%X received=%X", cm.Expected, cm.Received)
//	}
type CryptogramMismatchError struct {
	// Expected is the cryptogram value the host computed from the
	// configured Keys, the host challenge, the card challenge, and
	// the SCP03 KDF. Length is 8 (S8) or 16 (S16).
	Expected []byte

	// Received is the cryptogram value the card returned in its
	// INITIALIZE UPDATE response. Same length as Expected.
	Received []byte
}

// Error renders the mismatch with the same shape gppro uses, so
// operators correlating logs from both tools see comparable output.
// Includes an explicit brick-risk warning to discourage immediate
// retries with the same keys.
func (e *CryptogramMismatchError) Error() string {
	return fmt.Sprintf(
		"scp03: card cryptogram mismatch (wrong keys or compromised handshake)\n"+
			"  Received: %s\n"+
			"  Expected: %s\n"+
			"  Do not re-try the same keys — the card's failed-auth counter "+
			"is finite and a brick is the consequence of exhausting it.",
		strings.ToUpper(hex.EncodeToString(e.Received)),
		strings.ToUpper(hex.EncodeToString(e.Expected)),
	)
}

// Is reports whether target is ErrAuthFailed, so callers using
// errors.Is(err, scp03.ErrAuthFailed) can detect a cryptogram
// mismatch as a kind of auth failure without naming this concrete
// type. Callers wanting the bytes use errors.As with
// *CryptogramMismatchError.
func (e *CryptogramMismatchError) Is(target error) bool {
	return target == ErrAuthFailed
}
