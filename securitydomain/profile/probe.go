package profile

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
)

// AIDSecurityDomain is the GP Issuer Security Domain default AID
// per GP Card Spec v2.3.1 §F.6. Duplicated here from
// securitydomain.AIDSecurityDomain so this package does not have
// to import securitydomain (which would create a circular import:
// securitydomain depends on profile for capability gating).
var AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

// yubikeyVersionObject is the GP-spec data object tag YubiKey 5.x
// uses to expose its firmware version (5FC109 in BER-TLV form).
// The tag is YubiKey-specific; standard GP cards return SW=6A88
// (referenced data not found) when GET DATA targets it, which is
// the discriminator the probe uses to distinguish YubiKey from
// other GP cards without sending any vendor-extension instruction.
//
// GET DATA encodes the tag in the P1/P2 bytes for two-byte tags:
//
//	00 CA 5F C1 00  -- GET DATA tag 5FC1, sub-tag 09 in Le envelope
//
// The exact tag bytes are operator-visible in the trace so audit
// log diffs across detection runs are unambiguous.
var yubikeyVersionTag = []byte{0x5F, 0xC1, 0x09}

// ProbeResult is the output of a non-destructive SD probe.
//
// Profile is the recommended profile for the detected card. The
// raw SELECT response data and any vendor version blob are exposed
// for callers (CLI, JSON reports) that want to surface what the
// probe actually saw rather than just the chosen profile name.
type ProbeResult struct {
	// Profile is the profile selected for this card. Either
	// YubiKeySDProfile (when the YubiKey version object answered
	// 9000), StandardSDProfile (SD reachable, no YubiKey signal),
	// or nil if no SD was reachable.
	Profile Profile

	// SelectResponse is the raw response data the card returned
	// for SELECT AID. May be nil if SELECT failed.
	SelectResponse []byte

	// YubiKeyVersion is the 3-byte major.minor.patch firmware
	// version parsed from the YubiKey version object, populated
	// only when the GET DATA on tag 5FC109 succeeded with a
	// well-shaped response. Nil for non-YubiKey cards or when
	// the object was absent.
	YubiKeyVersion []byte
}

// ErrNoSecurityDomain is returned by Probe when SELECT AID against
// the SD AID fails. The card may not implement GP, the AID may be
// non-default (use the --sd-aid override on the gp commands), or
// the reader may not be connected.
var ErrNoSecurityDomain = errors.New("securitydomain/profile: no Security Domain reachable at requested AID")

// Probe runs a non-destructive identification sequence against a
// card and returns the recommended SD profile.
//
// Sequence:
//
//  1. SELECT AID (00 A4 04 00 [sdAID]). Required. Failure here
//     yields ErrNoSecurityDomain because nothing else is
//     meaningful.
//
//  2. GET DATA tag 5FC109 (YubiKey firmware version object).
//     YubiKey 5.x answers 9000 with a 3-byte major.minor.patch
//     payload. Standard GP cards answer SW=6A88. A 6A88 drops
//     through to StandardSDProfile silently; any other failure
//     also drops through (we don't fail the whole probe over an
//     unexpected SW because the SD itself is reachable — the
//     operator can still proceed, just under the standard profile).
//
// Auto-detect never silently selects YubiKey for a card that did
// not identify as one. A card that returns 9000 to GET DATA on
// 5FC109 with a non-conformant response (zero bytes, malformed)
// also drops through to standard rather than guessing.
//
// Pass nil for sdAID to use the GP-default ISD AID. Pass a
// vendor- or deployment-specific AID for cards with a non-default
// ISD (the same shape as the gp commands' --sd-aid flag).
func Probe(ctx context.Context, t Transmitter, sdAID []byte) (*ProbeResult, error) {
	if t == nil {
		return nil, errors.New("securitydomain/profile: nil transmitter")
	}
	if len(sdAID) == 0 {
		sdAID = AIDSecurityDomain
	}

	// Step 1: SELECT.
	sel := &apdu.Command{
		CLA:  0x00,
		INS:  0xA4,
		P1:   0x04,
		P2:   0x00,
		Data: sdAID,
		Le:   -1,
	}
	resp, err := t.Transmit(ctx, sel)
	if err != nil {
		return nil, fmt.Errorf("securitydomain/profile: SELECT SD: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("%w (SW=%04X)", ErrNoSecurityDomain, resp.StatusWord())
	}

	out := &ProbeResult{SelectResponse: resp.Data}

	// Step 2: probe the YubiKey version object via GET DATA.
	getVer := &apdu.Command{
		CLA:  0x00,
		INS:  0xCA,
		P1:   yubikeyVersionTag[0],
		P2:   yubikeyVersionTag[1],
		Data: nil,
		Le:   -1,
	}
	verResp, err := t.Transmit(ctx, getVer)
	if err != nil {
		// Transport error. The SD is reachable (SELECT succeeded)
		// but version probing failed mid-way. Treat as inconclusive
		// and fall through to standard rather than failing — the
		// CLI surfaces the probe outcome and the operator can
		// override.
		out.Profile = Standard()
		return out, nil
	}
	if verResp.IsSuccess() && len(verResp.Data) >= 3 {
		// YubiKey 5.x emits the version as raw 3-byte
		// major.minor.patch. Older firmware that wraps it in BER-TLV
		// is not in scope for this probe; the data shape can be
		// extended later if needed.
		out.YubiKeyVersion = append([]byte(nil), verResp.Data[:3]...)
		out.Profile = YubiKey()
		return out, nil
	}

	// Any other outcome (6A88 / non-conformant payload / SW=9000
	// with shorter data than expected) drops through to standard.
	out.Profile = Standard()
	return out, nil
}
