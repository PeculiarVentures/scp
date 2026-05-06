package securitydomain

import (
	"context"
	"errors"
	"fmt"
)

// Card identity tags per GP Card Spec v2.3.1 §11.3.3 GET DATA.
// IIN identifies the issuer (5 bytes BCD, ISO 7812 format on most
// cards); CIN identifies the specific card (vendor-defined,
// typically 8..16 bytes encoding chip serial + production lot).
//
// These are read-only data objects. Production cards may not
// expose either: GP allows omitting both, in which case GET DATA
// returns SW=6A88. Code that depends on CIN (the diversification
// CSN, the --expected-card-id pin) must handle absence gracefully.
const (
	tagIIN uint16 = 0x0042
	tagCIN uint16 = 0x0045
)

// ErrCardIdentityMissing is returned by GetIIN/GetCIN when the
// card responds SW=6A88 (referenced data not found). Callers
// can errors.Is against this to distinguish "card did not
// expose this identity field" from a transport or auth failure.
//
// The companion APDUError with SW=6A88 is the underlying form;
// errors.Is unwraps to find this sentinel for convenience.
var ErrCardIdentityMissing = errors.New("card identity field not exposed by card")

// GetIIN returns the Issuer Identification Number (GP §B.3,
// GET DATA tag 0x0042). Typical length 5 bytes (BCD-encoded
// ISO 7812 number) but variable. ErrCardIdentityMissing wraps
// the SW=6A88 case.
func (s *Session) GetIIN(ctx context.Context) ([]byte, error) {
	return s.getIdentityTag(ctx, tagIIN, "IIN")
}

// GetCIN returns the Card Image Number (GP §B.4, GET DATA tag
// 0x0045). Length is vendor-defined; common forms include 8-byte
// chip-serial-plus-mask values and longer 16-byte production
// lot identifiers. ErrCardIdentityMissing wraps the SW=6A88
// case for cards that omit CIN.
//
// The returned bytes are the value the --expected-card-id flag
// pins for destructive operator commands (gp install, gp delete).
// They are also a reasonable diversification CSN for
// scp03.Diversify on cards that personalize per-card keys.
func (s *Session) GetCIN(ctx context.Context) ([]byte, error) {
	return s.getIdentityTag(ctx, tagCIN, "CIN")
}

func (s *Session) getIdentityTag(ctx context.Context, tag uint16, fieldName string) ([]byte, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}
	data, err := s.GetData(ctx, tag, nil)
	if err != nil {
		// GetData wraps SW=6A88 as a non-success APDUError that
		// surfaces in err. Detect that case and return the
		// sentinel so callers can distinguish "card said no"
		// from "transport broke."
		var ae *APDUError
		if errors.As(err, &ae) && ae.SW == 0x6A88 {
			return nil, fmt.Errorf("%s: %w", fieldName, ErrCardIdentityMissing)
		}
		// GetData currently formats the error string itself; the
		// underlying SW for non-6A88 cases is already in err.
		// Wrap with the field name so the caller knows which
		// identity tag failed.
		if isSW6A88(err) {
			return nil, fmt.Errorf("%s: %w", fieldName, ErrCardIdentityMissing)
		}
		return nil, fmt.Errorf("%s: %w", fieldName, err)
	}
	return data, nil
}

// isSW6A88 detects the SW=6A88 case from a GetData-style error
// string. The existing GetData wraps non-9000 SWs into a
// formatted error string (e.g. "securitydomain: get data: SW=6A88")
// rather than a typed error; this helper matches the SW byte
// pattern. When GetData is upgraded to return a typed APDUError
// this fallback can be removed.
func isSW6A88(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for i := 0; i+4 <= len(s); i++ {
		if s[i] == '6' && s[i+1] == 'A' && s[i+2] == '8' && s[i+3] == '8' {
			return true
		}
	}
	return false
}
