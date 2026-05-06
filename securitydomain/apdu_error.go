package securitydomain

import (
	"errors"
	"fmt"
)

// APDUError is the canonical typed error for a card returning a
// non-9000 status word. Callers extract structured info via
// errors.As and match specific SWs without parsing strings:
//
//	var ae *APDUError
//	if errors.As(err, &ae) {
//	    switch ae.SW {
//	    case 0x6A88: // referenced data not found
//	    case 0x6A84: // not enough memory
//	    case 0x6982: // security status not satisfied
//	    }
//	}
//
// errors.Is(err, ErrCardStatus) also returns true for any
// APDUError, preserving the package-wide "card said no"
// sentinel for callers that want the generic check.
//
// Operation is a short human-readable label for the request
// that triggered the rejection (e.g. "INSTALL [for load]",
// "GET DATA tag 0x0042"). It feeds the Error() string so the
// reader knows which APDU was rejected without consulting the
// surrounding wrap chain.
type APDUError struct {
	Operation string
	SW        uint16
}

// Error implements the error interface.
func (e *APDUError) Error() string {
	if e.Operation == "" {
		return fmt.Sprintf("card rejected APDU (SW=%04X)", e.SW)
	}
	return fmt.Sprintf("%s rejected (SW=%04X)", e.Operation, e.SW)
}

// Is implements errors.Is so APDUError matches the package-wide
// ErrCardStatus sentinel. Lets callers write a generic
// errors.Is(err, ErrCardStatus) check without giving up the
// structured access via errors.As.
func (e *APDUError) Is(target error) bool {
	return target == ErrCardStatus
}

// swFromError extracts the SW from an APDUError if err wraps one,
// else returns 0 (transport-level error, no SW available).
func swFromError(err error) uint16 {
	var ae *APDUError
	if errors.As(err, &ae) {
		return ae.SW
	}
	return 0
}
