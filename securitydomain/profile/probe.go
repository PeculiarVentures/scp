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

// gpStandardCardIdentificationOID is the GP Card Spec Card_IDS OID
// (1.2.840.114283.3) — the bare GP RID + arc 3 with no further
// qualifier. Every GP-conformant card emits this value in tag 0x63
// (Card Identification Scheme) of its Card Recognition Data; it
// does NOT identify a specific vendor.
//
// The historical detection treated this OID as the YubiKey
// signature, on the assumption that "Yubico occupies the GP
// card-identification slot but doesn't advertise a vendor-specific
// sub-OID." That assumption was wrong. A SafeNet eToken Fusion
// (Thales-built, GP 2.2.1, JavaCard v3, OS release 2017-11-30)
// emits the same OID, so do other GP-conformant non-YubiKey cards.
// classifyByCRD now uses the OID's presence as a sanity check
// (the card must at least claim GP card-identification) but adds
// further narrowing via CardChipDetailsOID and the SCPs list.
var gpStandardCardIdentificationOID = asn1.ObjectIdentifier{1, 2, 840, 114283, 3}

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
//  4. Classify the CRD via classifyByCRD. yubikey-sd requires
//     the GP-standard Card_IDS OID, absence of CardChipDetailsOID,
//     and SCP11 in the advertised SCPs list. Anything else
//     classifies as standard-sd. Detection signals and rationale
//     are documented on classifyByCRD.
//
// Auto-detect never silently selects YubiKey for a card that did
// not match every signal. A card that returns 9000 to SELECT but
// emits no CRD, emits CRD without the GP-standard Card_IDS OID,
// emits CRD that explicitly tags a non-YubiKey chip platform, or
// emits CRD without SCP11 advertised, drops through to Standard
// rather than guessing.
//
// The first probe implementation queried GET DATA tag 0x5FC109
// against the SD applet expecting the YubiKey firmware version
// object — but that data lives in the PIV applet, not the SD.
// Probe always returned Standard regardless of card. Hardware
// verification against a YubiKey 5.7.4 surfaced the bug; the
// CRD-based detection replaced it. The CRD detection itself was
// then tightened after a SafeNet eToken Fusion was observed
// emitting the same Card_IDS OID as YubiKey, which the original
// CRD detection treated as the YubiKey signature.
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

	// Step 1: SELECT the SD. apdu.NewSelect sets Le=0 (request
	// FCI body) on the wire — Le=-1 would encode case-1 (no
	// expected response) and the YubiKey returns a successful
	// 9000 with no FCI body, leaving CardInfo unpopulated.
	//
	// Routed through apdu.TransmitWithChaining rather than the
	// bare t.Transmit so that cards which respond to SELECT with
	// SW=61xx ("FCI is xx bytes, fetch with GET RESPONSE") get
	// their FCI assembled transparently. Real-world example: a
	// Thales-built GP 2.1.1 card with ATR
	// 3B7F96000080318065B0850300EF120FFE829000 returns SW=6167
	// to SELECT A000000018434D00 when the host doesn't supply Le=00
	// or doesn't auto-follow the chain. The corresponding fix in
	// the discover-SD path landed in PR #144; this path needed the
	// same treatment.
	sel := apdu.NewSelect(sdAID)
	resp, err := apdu.TransmitWithChaining(ctx, t, sel)
	if err != nil {
		return nil, fmt.Errorf("securitydomain/profile: SELECT SD: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("%w (SW=%04X)", ErrNoSecurityDomain, resp.StatusWord())
	}

	out := &ProbeResult{SelectResponse: resp.Data}

	// Step 2: try parsing SELECT response as inline CRD. Some
	// cards return CRD in the SELECT FCI; if cardrecognition
	// can decode it directly, we skip the GET DATA round trip.
	// Only accept the result if it carries the discriminator
	// (CardIdentificationOID) — a parse-success without OID
	// usually means the SELECT FCI was something else entirely
	// (FCP, an AID-only response, etc.) and we should fall
	// through to the explicit GET DATA path.
	if info, err := cardrecognition.Parse(resp.Data); err == nil && len(info.CardIdentificationOID) > 0 {
		out.CardInfo = info
	}

	// Step 3: fall back to GET DATA tag 0x66 if SELECT didn't
	// give us CRD with a Card Identification OID. Some cards
	// (YubiKey 5.7+) return CRD only via this explicit GET DATA;
	// the SELECT FCI carries different data.
	//
	// Le must be 0 (not -1) so the encoded APDU includes the Le
	// byte that tells the card "send up to 256 bytes of
	// response." Le=-1 encodes as a case-1 APDU with no Le byte
	// — the YubiKey interprets that as "no response data
	// expected" and returns 9000 with an empty body, leaving
	// CardInfo unpopulated and Probe falling through to
	// Standard. This is a wire-shape match with the library's
	// own GetCardRecognitionData path which uses Le=0.
	if out.CardInfo == nil {
		getCRD := &apdu.Command{
			CLA:  0x00,
			INS:  0xCA,
			P1:   0x00,
			P2:   crdGetDataTagP2,
			Data: nil,
			Le:   0,
		}
		if crdResp, err := apdu.TransmitWithChaining(ctx, t, getCRD); err == nil && crdResp.IsSuccess() {
			if info, err := cardrecognition.Parse(crdResp.Data); err == nil {
				out.CardInfo = info
			}
		}
	}

	// Step 4: classify on Card Recognition Data signals.
	// classifyByCRD encapsulates the YubiKey detection logic so
	// it can be shared with cmd/scpctl/cmd_probe (which already
	// has CRD in hand from its own SELECT + GET DATA work and
	// would otherwise duplicate the round trips of calling Probe
	// here).
	out.Profile = classifyByCRD(out.CardInfo)
	return out, nil
}

// classifyByCRD returns the profile that best matches the given
// Card Recognition Data. Used by Probe (which fetches CRD via
// SELECT + GET DATA) and by cmd/scpctl/cmd_probe via the exported
// ClassifyByCRD wrapper (which already has CRD in hand and avoids
// the redundant round trip).
//
// Detection signals — all must hold for yubikey-sd:
//
//   - CardIdentificationOID is the GP-standard Card_IDS OID
//     1.2.840.114283.3. Every GP-conformant card emits this; its
//     absence indicates the card emitted no parseable CRD or
//     malformed CRD, and the detection cannot proceed.
//
//   - CardChipDetailsOID is absent. Cards that explicitly tag
//     their chip platform (SafeNet eToken Fusion emits the
//     JavaCard v3 OID 1.3.6.1.4.1.42.2.110.1.3 here; other
//     vendors emit other arcs) are not YubiKey. YubiKey 5.7
//     CRD does not include a CardChipDetailsOID, and absent-vs-
//     present is the cleanest signal for distinguishing
//     YubiKey from explicit-chip-tagging cards observed to date.
//
//   - SCPs advertises SCP11. YubiKey 5.7+ advertises both SCP03
//     (i=0x60) and SCP11 (i=0x0D86); SafeNet eToken Fusion
//     advertises SCP03 (i=0x10) only, and other observed non-
//     YubiKey cards advertise either SCP03 alone or SCP02. SCP11
//     being advertised is necessary but not sufficient for
//     yubikey-sd; combined with the absence of CardChipDetailsOID
//     it's a strong narrow.
//
// All other CardInfo states classify as standard-sd. Auto-detect
// never returns YubiKey for a card that did not match every
// signal — false-positive on classification is worse than false-
// negative because it gates vendor-extension instructions
// (GENERATE EC KEY 0xF1 etc.) the standard surface lacks.
//
// History: the previous implementation matched only on
// CardIdentificationOID == 1.2.840.114283.3 and misclassified any
// GP-conformant card as YubiKey. The signal set was tightened
// after a SafeNet eToken Fusion emitted the same identification
// OID and surfaced the bug.
func classifyByCRD(info *cardrecognition.CardInfo) Profile {
	if info == nil {
		return Standard()
	}
	if !info.CardIdentificationOID.Equal(gpStandardCardIdentificationOID) {
		return Standard()
	}
	if len(info.CardChipDetailsOID) > 0 {
		// Explicit chip-platform tag — observed on JavaCard v3
		// cards (SafeNet eToken Fusion). YubiKey 5.7 doesn't
		// emit this tag.
		return Standard()
	}
	if !advertisesSCP11(info.SCPs) {
		// YubiKey 5.7+ advertises both SCP03 and SCP11.
		// SafeNet, SCP02-only cards, and SCP03-only non-
		// YubiKey cards lack the SCP11 advertisement.
		return Standard()
	}
	return YubiKey()
}

// advertisesSCP11 returns true when any SCPInfo in the slice
// declares SCP11 (version byte 0x11). The check is on the version
// arc, not a specific i parameter, because YubiKey firmware
// versions and future verified profiles may differ in i and we
// want the narrowing signal stable across YubiKey hardware
// revisions without having to enumerate every shipping i.
func advertisesSCP11(scps []cardrecognition.SCPInfo) bool {
	for _, s := range scps {
		if s.Version == 0x11 {
			return true
		}
	}
	return false
}

// ClassifyByCRD is the exported wrapper around classifyByCRD for
// callers that already have parsed CRD (notably cmd/scpctl/cmd_probe)
// and want to avoid Probe's redundant SELECT + GET DATA. The
// classification rules are documented on classifyByCRD; this
// wrapper exists only so the unexported helper can stay as the
// single source of truth.
func ClassifyByCRD(info *cardrecognition.CardInfo) Profile {
	return classifyByCRD(info)
}
