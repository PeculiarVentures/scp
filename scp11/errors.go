package scp11

import "errors"

// Sentinel errors for SCP11 session establishment and operation.
//
// Callers can use errors.Is to discriminate the cause of an Open or
// Transmit failure without pattern-matching on message text:
//
//	sess, err := scp11.Open(ctx, t, cfg)
//	switch {
//	case errors.Is(err, scp11.ErrTrustValidation):
//	    // Card cert chain rejected; possible card swap, MITM,
//	    // or misconfigured trust roots.
//	case errors.Is(err, scp11.ErrAuthFailed):
//	    // Handshake completed but receipt or signature did not
//	    // verify; a retry will not succeed.
//	case errors.Is(err, scp11.ErrInvalidConfig):
//	    // Caller-side bug; fix the Config and retry.
//	case errors.Is(err, scp11.ErrInvalidResponse):
//	    // Card returned a malformed response.
//	}
//
// Wrapped errors carry the original descriptive message so logs and
// debug output remain useful.
var (
	// ErrAuthFailed indicates SCP11 mutual authentication failed:
	// the card's receipt did not verify, the card omitted a receipt
	// where one was required, or the card rejected the host's
	// authentication. Indicates wrong keys, wrong cert chain, or
	// that the underlying ECDH agreement was tampered with.
	ErrAuthFailed = errors.New("scp11: authentication failed")

	// ErrInvalidConfig indicates Open was called with a Config that
	// failed validation: no trust posture configured, missing OCE
	// material for SCP11a/c, unsupported variant, or rejected
	// security level. Wraps a more specific message describing which
	// check failed.
	ErrInvalidConfig = errors.New("scp11: invalid configuration")

	// ErrInvalidResponse indicates the card returned a malformed or
	// unexpectedly-shaped response during the handshake.
	ErrInvalidResponse = errors.New("scp11: invalid response from card")

	// ErrTrustValidation indicates the card's certificate chain
	// failed validation against the configured trust policy. The
	// wrapped error carries detail about which check failed (no
	// roots, wrong curve, SKI mismatch, custom validator rejection,
	// etc.).
	//
	// This error always means the card identity could not be
	// established, so the SCP11 session was not opened. Possible
	// causes: a different card was inserted, the trust roots are
	// misconfigured, or the card's certificate has changed since
	// it was provisioned.
	ErrTrustValidation = errors.New("scp11: card trust validation failed")
)
