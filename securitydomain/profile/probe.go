package profile

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cardrecognition"
)

// AIDSecurityDomain is the GP Issuer Security Domain default AID
// per GP Card Spec v2.3.1 §F.6. Duplicated here from
// securitydomain.AIDSecurityDomain so this package does not have
// to import securitydomain (which would create a circular import:
// securitydomain depends on profile for capability gating).
var AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

// yubikeyCardIdentificationOID is the value YubiKey 5.7+ emits in
// the Card Recognition Data tag 0x63 (Card Identification Scheme).
// It's the bare GP RID + arc 3 with no further qualifier — Yubico
// occupies the GP card-identification slot but doesn't advertise
// a vendor-specific sub-OID, which makes the unqualified value
// itself the discriminator.
//
// Captured 2026-05-04 from a retail YubiKey 5.7.4. Pinned in
// cardrecognition/cardrecognition_test.go's
// TestParse_RetailYubiKey5_BothSCPs fixture.
var yubikeyCardIdentificationOID = asn1.ObjectIdentifier{1, 2, 840, 114283, 3}

// crdGetDataTagP2 is the GP-spec tag for fetching Card Recognition
// Data via GET DATA. Most cards return CRD inline in the SELECT
// FCI; some return a minimal SELECT response and require a
// follow-up GET DATA tag 0x66.
const crdGetDataTagP2 = 0x66

// ProbeResult is the output of a non-destructive SD probe.
//
// Profile is the recommended profile for the detected card. The
// raw SELECT response data and parsed CRD are exposed for callers
// (CLI, JSON reports) that want to surface what the probe actually
// saw rather than just the chosen profile name.
type ProbeResult struct {
	// Profile is the profile selected for this card. YubiKey()
	// when the CRD's Card Identification Scheme OID matches
	// Yubico's, Standard() when SD is reachable but the OID
	// either is absent or names a non-YubiKey vendor, or nil if
	// no SD was reachable (Probe returns an error in that case).
	Profile Profile

	// SelectResponse is the raw response data the card returned
	// for SELECT AID. May be nil if SELECT failed.
	SelectResponse []byte

	// CardInfo is the parsed Card Recognition Data, if Probe
	// could fetch and parse it. Nil if the card returned no CRD
	// or the CRD was unparseable. CardInfo carries the structural
	// signal (Card Identification Scheme OID, GP version, SCPs
	// advertised) the probe uses for profile selection — exposed
	// here so consumers can render or audit what the probe saw.
	CardInfo *cardrecognition.CardInfo

	// YubiKeyVersion is reserved for compatibility with earlier
	// callers that read this field. Always nil under the CRD-based
	// probe — the previous implementation tried to read a YubiKey
	// firmware version object directly off the SD applet, but
	// that data lives in the PIV applet and switching applets
	// during a probe was intrusive. Operators wanting the firmware
	// version should call ykman or run scpctl piv info.
	//
	// Deprecated: always nil. Will be removed in a future release.
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
// The probe sequence:
//
//  1. SELECT the SD by AID. If SELECT fails, return
//     ErrNoSecurityDomain — the operator either has no card,
//     no GP card, or the wrong AID.
//  2. Try to parse the SELECT FCI as Card Recognition Data
//     (GP §H.2). YubiKey returns CRD inline in the SELECT
//     response; standard GP cards may not.
//  3. If SELECT didn't produce parseable CRD, issue GET DATA
//     tag 0x66 to fetch CRD explicitly.
//  4. If parsed CRD has Card Identification Scheme OID
//     1.2.840.114283.3 (Yubico's signature — see fixture in
//     cardrecognition's RetailYubiKey5 test), return YubiKey().
//  5. Otherwise return Standard().
//
// Auto-detect never silently selects YubiKey for a card that did
// not identify as one. A card that returns 9000 to SELECT but
// emits no CRD, or emits CRD without a Card Identification Scheme
// arc, drops through to Standard rather than guessing.
//
// The previous probe implementation queried GET DATA tag 0x5FC109
// against the SD applet expecting the YubiKey firmware version
// object — but that data lives in the PIV applet, not the SD.
// Probe always returned Standard regardless of card. Hardware
// verification against a YubiKey 5.7.4 surfaced the bug; this
// implementation uses the CRD which is reliably available off
// the SD applet.
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

	// Step 1: SELECT the SD.
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

	// Step 2: try parsing SELECT response as inline CRD.
	if info, err := cardrecognition.Parse(resp.Data); err == nil {
		out.CardInfo = info
	}

	// Step 3: fall back to GET DATA tag 0x66 if SELECT didn't
	// give us CRD. Some cards return a minimal SELECT response
	// and expect the host to fetch CRD explicitly.
	if out.CardInfo == nil {
		getCRD := &apdu.Command{
			CLA:  0x00,
			INS:  0xCA,
			P1:   0x00,
			P2:   crdGetDataTagP2,
			Data: nil,
			Le:   -1,
		}
		if crdResp, err := t.Transmit(ctx, getCRD); err == nil && crdResp.IsSuccess() {
			if info, err := cardrecognition.Parse(crdResp.Data); err == nil {
				out.CardInfo = info
			}
		}
	}

	// Step 4: classify on Card Identification Scheme OID. The
	// signature is the bare GP RID + arc 3 (1.2.840.114283.3)
	// with no further qualifier — that exact OID is what every
	// captured YubiKey 5.7+ has emitted to date.
	if out.CardInfo != nil &&
		out.CardInfo.CardIdentificationOID.Equal(yubikeyCardIdentificationOID) {
		out.Profile = YubiKey()
		return out, nil
	}

	// Step 5: anything else — no CRD, CRD without Card ID OID,
	// or CRD naming a different vendor — drops to Standard.
	out.Profile = Standard()
	return out, nil
}
