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
// debug output remain useful. ErrAuthFailed in particular often
// wraps one of two richer error types depending on which phase of
// the handshake failed:
//
//   - InitializeUpdateError when the card rejected INITIALIZE
//     UPDATE itself (before any cryptogram exchange). Carries the
//     SW, a diagnostic interpretation, and a flag for whether
//     retrying with different keys could plausibly help. SW=6982
//     and 6985 indicate state/policy blocks where keys aren't the
//     gate; SW=6A88 and 63CX indicate wrong key material that a
//     different key might satisfy.
//
//   - CryptogramMismatchError when INITIALIZE UPDATE succeeded and
//     returned a card challenge plus card cryptogram, but the
//     host's computed cryptogram didn't match the card's. Carries
//     the expected and received cryptogram bytes for diagnostic
//     comparison against a reference implementation or vendor
//     vector.
//
// errors.As against either concrete type recovers the structured
// fields. errors.Is(err, ErrAuthFailed) matches both.
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

// InitializeUpdateError is returned (wrapped behind ErrAuthFailed)
// when INITIALIZE UPDATE itself is rejected by the card before any
// cryptogram exchange happens. The card returned a non-success
// status word in response to the INITIALIZE UPDATE APDU, which
// means key material was never tested and a retry with different
// keys won't help unless the SW specifically indicates that.
//
// This is a different failure mode from CryptogramMismatchError.
// CryptogramMismatchError fires after INITIALIZE UPDATE succeeded
// and returned a card challenge plus card cryptogram, when the
// host computes its own cryptogram from configured keys and
// finds the values don't match. InitializeUpdateError fires
// strictly earlier than that, when the card refuses the
// INITIALIZE UPDATE APDU outright. Surfacing them as distinct
// types stops an operator from cycling more keys at a card that
// isn't even getting far enough to test them.
//
// # Attempt context
//
// The KeyVersion, KeyIdentifier, AID, and SCP fields preserve the
// context of the failed attempt so a caller iterating over key
// versions or P2 values (as is common when probing a card whose
// installed key references aren't fully known) can log what was
// tried without tracking it externally. AID is populated only
// when scp03.Open did the SELECT itself via Config.SelectAID;
// when the caller did SELECT before calling Open, AID is empty.
//
// # Diagnostic interpretation
//
// The Diagnostic field carries a human-readable interpretation of
// the SW based on common GP responses. SW=0x6982 ("Security status
// not satisfied") and SW=0x6985 ("Conditions of use not satisfied")
// both indicate the card refused SCP03 establishment before any
// cryptographic verification. The cause is consistent with the SD
// being in a locked or vendor-managed state, with a missing vendor
// precondition (e.g. a SAC-mediated handshake before host SCP03 is
// allowed), or with policy-blocked INITIALIZE UPDATE; without a
// lifecycle/status read confirming which, the diagnostic stops at
// "consistent with" rather than naming a single cause as proven.
// SW=0x6A88 ("Referenced data not found") indicates the requested
// key version wasn't installed; that one might benefit from a
// different KeyVersion value.
//
// The RetryDifferentKeys field flags whether trying different key
// material is even potentially useful. It's true only for SWs that
// indicate "this specific key didn't work" (currently SW=0x63CX
// counters and any vendor-extension SWs that map to that semantic).
// Operators who see RetryDifferentKeys=false should investigate
// the SD state, the card's lifecycle, or vendor preconditions
// rather than trying more keys.
//
// Use errors.As to inspect:
//
//	var iue *scp03.InitializeUpdateError
//	if errors.As(err, &iue) {
//	    log.Printf("SW=%04X (%s) attempt KV=%02X P2=%02X retry-keys=%v",
//	        iue.SW(), iue.Diagnostic,
//	        iue.KeyVersion, iue.KeyIdentifier, iue.RetryDifferentKeys)
//	}
type InitializeUpdateError struct {
	// SW1 and SW2 are the two status word bytes the card returned
	// in response to INITIALIZE UPDATE.
	SW1, SW2 byte

	// KeyVersion is the value sent in P1 of the INITIALIZE UPDATE
	// APDU (the SCP03 key version requested). Preserved so callers
	// iterating across versions can log what was tried.
	KeyVersion byte

	// KeyIdentifier is the value sent in P2 of the INITIALIZE
	// UPDATE APDU. For SCP03 the spec defines P2=0x00 normally; in
	// practice some hosts vary P2 across 0x00, 0x01, 0x02 when
	// probing what a card accepts. Preserved for the same reason
	// as KeyVersion.
	KeyIdentifier byte

	// AID is the Application Identifier of the SD that was
	// SELECTed before INITIALIZE UPDATE, when scp03.Open did the
	// SELECT itself via Config.SelectAID. Empty when the caller
	// did SELECT externally and Open just did INITIALIZE UPDATE
	// against the already-selected applet.
	AID []byte

	// SCP names the secure channel protocol that was being
	// established. Always "SCP03" for errors from this package;
	// included for symmetry with caller-side logging that may
	// also handle SCP11 errors.
	SCP string

	// Diagnostic is a human-readable interpretation of the SW. For
	// known SWs (6982, 6985, 6A88, 63Cx) this names the GP-spec
	// meaning and the typical cause; for unknown SWs it just names
	// the SW value.
	Diagnostic string

	// RetryDifferentKeys reports whether trying different key
	// material against the same card might succeed where this call
	// failed. False for policy/state SWs (6982, 6985); true only
	// for SWs that specifically indicate a wrong key was used and
	// the card is willing to be tried again with a different one.
	RetryDifferentKeys bool
}

// SW returns the status word as a single uint16 (SW1<<8 | SW2) for
// convenient comparison and logging.
func (e *InitializeUpdateError) SW() uint16 {
	return uint16(e.SW1)<<8 | uint16(e.SW2)
}

// Error renders the SW, the attempt context (KeyVersion and P2 if
// non-zero, AID if known), and the diagnostic interpretation. The
// shape is designed to be log-readable alongside the cryptogram
// diagnostic shipped by CryptogramMismatchError. SWs where
// retrying with different keys won't help carry an explicit "not a
// key problem" line so the operator's next step is investigating
// state rather than cycling keys.
func (e *InitializeUpdateError) Error() string {
	context := e.formatAttemptContext()
	if e.RetryDifferentKeys {
		return fmt.Sprintf(
			"scp03: INITIALIZE UPDATE rejected (SW=%04X%s, %s)",
			e.SW(), context, e.Diagnostic,
		)
	}
	return fmt.Sprintf(
		"scp03: INITIALIZE UPDATE rejected before key material was tested "+
			"(SW=%04X%s, %s); retrying with different keys will not help. "+
			"Investigate SD lifecycle, card state, or vendor preconditions",
		e.SW(), context, e.Diagnostic,
	)
}

// formatAttemptContext renders the attempt context fields (KV, P2,
// AID) as a comma-separated suffix when any of them is populated.
// Returns empty string when no context is available, so cards that
// pre-select the AID externally and use the default P1/P2 values
// don't get a noisy "KV=00 P2=00 AID=" suffix on every error.
func (e *InitializeUpdateError) formatAttemptContext() string {
	parts := []string{}
	// KeyVersion is informative even when zero (some cards accept
	// KV=0x00 as "any version"); the cleaner heuristic is to
	// always include it when the error was constructed via
	// scp03.Open (which always sets it from cfg.KeyVersion).
	parts = append(parts, fmt.Sprintf("KV=%02X", e.KeyVersion))
	parts = append(parts, fmt.Sprintf("P2=%02X", e.KeyIdentifier))
	if len(e.AID) > 0 {
		parts = append(parts, fmt.Sprintf("AID=%X", e.AID))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, " ")
}

// Is reports whether target is ErrAuthFailed, so callers using
// errors.Is(err, scp03.ErrAuthFailed) can detect this as a kind
// of auth failure without naming this concrete type.
func (e *InitializeUpdateError) Is(target error) bool {
	return target == ErrAuthFailed
}

// classifyInitUpdateSW maps a status word to a human-readable
// diagnostic string and a flag for whether different keys might
// succeed where this call failed. The mapping is conservative:
// SWs that GlobalPlatform Card Spec gives state/policy semantics
// to are flagged retry=false; SWs that name a wrong-key condition
// are flagged retry=true; everything else is unknown and
// retry=false (don't encourage cycling keys at SWs we can't
// interpret).
func classifyInitUpdateSW(sw1, sw2 byte) (diagnostic string, retry bool) {
	sw := uint16(sw1)<<8 | uint16(sw2)
	switch sw {
	case 0x6982:
		return "Security status not satisfied. SCP03 establishment was " +
			"refused before cryptographic verification, so key material " +
			"was not tested. Consistent with locked/vendor-managed SD, " +
			"missing vendor precondition (SAC handshake, middleware-mediated " +
			"session, etc.), lifecycle restriction, or policy-blocked " +
			"INITIALIZE UPDATE; lifecycle/status read needed to confirm " +
			"which", false
	case 0x6985:
		return "Conditions of use not satisfied. SCP03 establishment was " +
			"refused before cryptographic verification, so key material " +
			"was not tested. Similar to 6982; the card based the rejection " +
			"on its own state or policy rather than on the key material", false
	case 0x6A82:
		return "File not found. The SELECTed AID isn't an SCP03 " +
			"endpoint; check that the right SD AID was selected " +
			"before INITIALIZE UPDATE", false
	case 0x6A86:
		return "Incorrect P1 or P2. The KeyVersion supplied in P1 " +
			"isn't accepted by this card; try a different KeyVersion " +
			"or check KIT for installed key versions", true
	case 0x6A88:
		return "Referenced data not found. The requested KeyVersion " +
			"isn't installed on this card; check KIT (GET DATA tag 0xE0) " +
			"for installed SCP03 key references", true
	case 0x6700:
		return "Wrong length. The INITIALIZE UPDATE host challenge " +
			"length is wrong for this card's expected i-parameter " +
			"(8 bytes for S8, 16 bytes for S16)", false
	}
	// SW=63CX: counter-based, with X = remaining attempts.
	if sw1 == 0x63 && (sw2&0xF0) == 0xC0 {
		remaining := int(sw2 & 0x0F)
		return fmt.Sprintf(
			"verification failed, %d attempts remaining. Wrong key material; "+
				"counter is decrementing toward card lock",
			remaining), true
	}
	return fmt.Sprintf("SW=%02X%02X (unknown to scp03 diagnostics)", sw1, sw2), false
}

// CryptogramMismatchError is returned (wrapped behind ErrAuthFailed)
// when the card cryptogram the card sends in its INITIALIZE UPDATE
// response does not match the value the host computed from its
// configured keys. The expected and received cryptogram bytes are
// preserved on the error so an operator can compare them against a
// reference implementation (gppro, the GP Amendment D §6.2.2 vectors,
// a vendor key sheet, etc.) without re-running the handshake.
//
// Re-running the handshake with the same keys would not succeed.
// The cryptogram is a deterministic function of the keys, the host
// challenge, the card challenge, and the SCP03 KDF, so a retry just
// consumes another slot of the card's failed-authentication
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
//	  Do not re-try the same keys the card's failed-auth counter
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
			"  Do not re-try the same keys the card's failed-auth counter "+
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
