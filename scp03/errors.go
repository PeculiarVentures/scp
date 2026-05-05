package scp03

import "errors"

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
// debug output remain useful.
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
