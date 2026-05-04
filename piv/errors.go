// Package piv: status-word-aware error model.
//
// Every PIV operation that talks to a card can fail in one of three
// shapes: a transport error (no response), a parse error (malformed
// response), or a non-success status word (the card replied but
// refused or qualified the operation). The third case carries
// information programs need: was the PIN wrong, is it now blocked,
// is the management key required, was the slot empty, did the card
// reject the instruction outright.
//
// CardError is the typed shape callers receive when a card returns a
// non-success SW. Helper predicates (IsWrongPIN, IsPINBlocked, ...)
// let callers branch on the specific failure without inspecting raw
// SWs. The status-word taxonomy below is a working subset; new SWs
// can be added by extending the helpers as PIV behaviors accumulate.
package piv

import (
	"errors"
	"fmt"
)

// Sentinel errors raised by the piv package independent of any card
// status word. Callers can use errors.Is to branch on these.
var (
	// ErrUnsupportedByProfile is returned by the session layer when an
	// operation is requested that the active profile does not claim to
	// support (e.g. ATTEST under StandardPIVProfile, IMPORT KEY under a
	// profile without that capability). The session refuses host-side,
	// before any APDU is transmitted.
	ErrUnsupportedByProfile = errors.New("piv: operation not supported by the active profile")

	// ErrNotAuthenticated is returned when a write or PIN-gated
	// operation is attempted but the required authorization
	// (management-key auth or PIN verify) has not been performed on
	// the session.
	ErrNotAuthenticated = errors.New("piv: required authentication has not been performed")
)

// CardError represents a non-success status word returned by a PIV
// command. Operation names the semantic step that produced it (e.g.
// "VERIFY PIN", "GENERATE KEY") so the message is useful in logs;
// SW carries the raw status word; Message carries any additional
// context (e.g. retries-remaining when SW is 63Cx).
type CardError struct {
	Operation string
	SW        uint16
	Message   string
}

// Error implements error. The format is stable enough for log
// scraping but not part of the API contract; programs should branch
// on the helper predicates rather than the string.
func (e *CardError) Error() string {
	parts := fmt.Sprintf("%s: SW=%04X (%s)", e.Operation, e.SW, swDescription(e.SW))
	if e.Message != "" {
		return parts + ": " + e.Message
	}
	return parts
}

// NewCardError constructs a CardError. msg is optional; pass "" if
// no extra context is available.
func NewCardError(operation string, sw uint16, msg string) *CardError {
	return &CardError{Operation: operation, SW: sw, Message: msg}
}

// StatusWord returns the SW from err if err (or any error wrapped
// inside it) is a *CardError. ok reports whether a status word was
// found.
func StatusWord(err error) (sw uint16, ok bool) {
	var ce *CardError
	if errors.As(err, &ce) {
		return ce.SW, true
	}
	return 0, false
}

// RetriesRemaining returns the retry count encoded in a 63Cx status
// RetriesRemaining returns the number of retries left in the status
// word if err is a *CardError carrying such a SW. ok is false for
// any other error or status word.
//
// Two SW forms are recognized:
//
//   - 0x63Cx: NIST SP 800-73-4 / ISO 7816-4 canonical form ("verify
//     failed, x attempts left"). YubiKey and most current cards.
//
//   - 0x63xx (where SW1 == 0x63 and the high nibble of SW2 is 0):
//     older PIV cards and some implementations omit the Cx high
//     nibble. The retry count is still in the low nibble.
//
// Both forms appear in the field. The predicate accepts both rather
// than forcing callers to branch.
func RetriesRemaining(err error) (retries int, ok bool) {
	sw, found := StatusWord(err)
	if !found {
		return 0, false
	}
	// Canonical 63Cx form.
	if sw&0xFFF0 == 0x63C0 {
		return int(sw & 0x000F), true
	}
	// Bare 63xx form: SW1=0x63, SW2 high nibble zero, low nibble is
	// the retry count.
	if sw&0xFFF0 == 0x6300 {
		return int(sw & 0x000F), true
	}
	return 0, false
}

// IsWrongPIN reports whether err indicates a wrong PIN or PUK with
// retries remaining. Retry count of zero is treated as blocked, not
// wrong, and routes to IsPINBlocked / IsPUKBlocked.
func IsWrongPIN(err error) bool {
	retries, ok := RetriesRemaining(err)
	if !ok {
		return false
	}
	return retries > 0
}

// IsPINBlocked reports whether err indicates the PIN is blocked.
// Maps SW 6983 (authentication method blocked), SW 63C0 (canonical
// "verify failed, 0 attempts" form), and SW 6300 (bare form, zero
// retries).
func IsPINBlocked(err error) bool {
	sw, ok := StatusWord(err)
	if !ok {
		return false
	}
	switch sw {
	case 0x6983, 0x63C0, 0x6300:
		return true
	}
	return false
}

// IsPUKBlocked is an alias for IsPINBlocked at the SW level. The
// distinction between PIN and PUK lockouts is contextual: the same
// SW values are returned for both depending on which command the
// card was processing. Callers that have the operation context can
// branch on the operation field of the underlying CardError if they
// need to distinguish.
func IsPUKBlocked(err error) bool {
	return IsPINBlocked(err)
}

// IsAuthRequired reports whether err indicates the operation
// required prior authentication that has not been performed (the
// piv-package sentinel ErrNotAuthenticated, or a card SW 6982).
func IsAuthRequired(err error) bool {
	if errors.Is(err, ErrNotAuthenticated) {
		return true
	}
	return IsSecurityStatusNotSatisfied(err)
}

// IsSecurityStatusNotSatisfied reports whether err is SW 6982
// (security status not satisfied). On PIV cards this typically means
// PIN verify or management-key auth is required and has not been
// performed for this session.
func IsSecurityStatusNotSatisfied(err error) bool {
	sw, ok := StatusWord(err)
	if !ok {
		return false
	}
	return sw == 0x6982
}

// IsUnsupportedInstruction reports whether err is SW 6D00
// (instruction not supported or invalid). This is the canonical
// response when a card receives an INS byte it does not implement;
// for example, a Standard PIV card receiving a YubiKey-specific INS
// like 0xFB (RESET) or 0xF9 (ATTEST).
func IsUnsupportedInstruction(err error) bool {
	sw, ok := StatusWord(err)
	if !ok {
		return false
	}
	return sw == 0x6D00
}

// IsNotFound reports whether err is SW 6A82 (file or application
// not found). On PIV this is the typical response when a slot or
// data object has not been written yet.
func IsNotFound(err error) bool {
	sw, ok := StatusWord(err)
	if !ok {
		return false
	}
	return sw == 0x6A82
}

// IsIncorrectData reports whether err is SW 6A80 (incorrect
// parameters in the data field).
func IsIncorrectData(err error) bool {
	sw, ok := StatusWord(err)
	if !ok {
		return false
	}
	return sw == 0x6A80
}

// IsUnsupportedByProfile reports whether err is the piv-package
// sentinel for an operation refused by the active profile before
// any APDU is transmitted. Distinguishes host-side refusals from
// card-side refusals (which surface as IsUnsupportedInstruction).
func IsUnsupportedByProfile(err error) bool {
	return errors.Is(err, ErrUnsupportedByProfile)
}

// swDescription renders a short human-readable label for SW. The
// list is a working subset; unknown SWs render as "unknown".
func swDescription(sw uint16) string {
	switch {
	case sw == 0x9000:
		return "success"
	case sw&0xFF00 == 0x6100:
		return "more data available"
	case sw&0xFFF0 == 0x63C0:
		return fmt.Sprintf("wrong PIN/PUK, %d retries remaining", sw&0x000F)
	case sw == 0x6700:
		return "wrong length"
	case sw == 0x6982:
		return "security status not satisfied"
	case sw == 0x6983:
		return "authentication method blocked"
	case sw == 0x6985:
		return "conditions of use not satisfied"
	case sw == 0x6A80:
		return "incorrect parameters in data field"
	case sw == 0x6A81:
		return "function not supported"
	case sw == 0x6A82:
		return "file or application not found"
	case sw == 0x6A86:
		return "incorrect P1 or P2"
	case sw == 0x6A88:
		return "referenced data not found"
	case sw == 0x6D00:
		return "instruction not supported or invalid"
	case sw == 0x6E00:
		return "class not supported"
	case sw == 0x6F00:
		return "no precise diagnosis"
	}
	return "unknown"
}
