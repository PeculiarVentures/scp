package profile

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/tlv"
)

// AIDPIV is the truncated PIV applet AID (NIST SP 800-73-4 Part 1,
// §2.2). Cards perform AID matching by prefix, so the 5-byte form
// is what every PIV applet observed in the wild accepts. This value
// is also what scp11.AIDPIV uses; it is duplicated here so the
// profile package does not have to import scp11 (which would pull
// the SCP11 protocol stack into a probe path).
//
// The full AID (AIDPIVFull below) is what SP 800-73-4 specifies on
// the wire; some strict implementations may require it. Probe tries
// the full AID first and falls back to AIDPIV on 6A82 (file not
// found), so callers do not need to reason about which form the
// card prefers.
var AIDPIV = []byte{0xA0, 0x00, 0x00, 0x03, 0x08}

// AIDPIVFull is the full PIV applet AID per NIST SP 800-73-4 Part
// 1, §2.2. The trailing bytes after the 5-byte RID identify the
// PIX (proprietary application identifier extension): 00 00 10 00
// 01 00. Probe sends this form first because it is what the spec
// mandates; the truncated AIDPIV is used as a fallback for cards
// that reject the full form.
var AIDPIVFull = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}

// ProbeResult is the output of a non-destructive PIV probe.
//
// Profile is the recommended profile for the detected card. The raw
// SELECT response data and any vendor version blob are exposed for
// callers (CLI, JSON reports) that want to surface what the probe
// actually saw rather than just the chosen profile name.
type ProbeResult struct {
	// Profile is the profile selected for this card. Either
	// YubiKeyProfile (firmware-narrowed if version was readable),
	// StandardPIVProfile (PIV applet present, no YubiKey signal),
	// or nil if no PIV applet was found.
	Profile Profile

	// SelectResponse is the raw application property template the
	// card returned for SELECT AID PIV. May be nil if SELECT failed.
	SelectResponse []byte

	// PIVVersion is the contents of tag 5FC107 (PIV Application
	// Version Number) parsed from SelectResponse, if present.
	PIVVersion []byte

	// YubiKeyFW is the YubiKey firmware version, populated only when
	// the GET VERSION instruction (YubiKey-specific INS=0xFD)
	// succeeded. nil for non-YubiKey cards or when GET VERSION
	// returned 6D00.
	YubiKeyFW *YubiKeyVersion
}

// ErrNoPIVApplet is returned by Probe when SELECT AID PIV fails. The
// card may not have a PIV applet, or the PC/SC reader may not be
// connected to a card.
var ErrNoPIVApplet = errors.New("piv/profile: no PIV applet found on card")

// Probe runs a non-destructive identification sequence against a
// card and returns the recommended profile.
//
// Sequence:
//
//  1. SELECT AID PIV (00 A4 04 00 [aid]). Required. Failure here
//     yields ErrNoPIVApplet because nothing else is meaningful.
//
//  2. GET VERSION (00 FD 00 00 00). YubiKey-specific. Returns 3
//     bytes major.minor.patch on YubiKey, 6D00 on standard PIV.
//     The response narrows the YubiKey profile to the detected
//     firmware version. A 6D00 (or any other non-success) drops
//     through to StandardPIVProfile silently; this is the design.
//
// Probe never generates keys, decrements retry counters, writes
// objects, or issues any instruction that changes card state. The
// two APDUs above are the entire probe surface, plus an optional
// fallback SELECT if the card rejects the full AID.
func Probe(ctx context.Context, tx Transmitter) (*ProbeResult, error) {
	res := &ProbeResult{}

	// 1. SELECT AID PIV. Try the full AID first because that is what
	// SP 800-73-4 specifies on the wire; fall back to the truncated
	// form on 6A82 (file not found) for cards that match by exact
	// AID rather than prefix. Both forms reach the same PIV applet
	// on every implementation observed in the field; the difference
	// matters only at the AID-matching layer, so the SelectResponse
	// returned to the caller is whichever form the card accepted.
	selectResp, err := selectPIVApplet(ctx, tx, AIDPIVFull)
	if err != nil {
		return nil, err
	}
	if !selectResp.IsSuccess() && selectResp.StatusWord() == 0x6A82 {
		// Card rejected the full AID; retry with the truncated form.
		// Some embedded PIV implementations match the AID exactly
		// rather than by prefix.
		selectResp, err = selectPIVApplet(ctx, tx, AIDPIV)
		if err != nil {
			return nil, err
		}
	}
	if !selectResp.IsSuccess() {
		return nil, fmt.Errorf("%w (SW=%04X)", ErrNoPIVApplet, selectResp.StatusWord())
	}
	res.SelectResponse = selectResp.Data

	// Parse the application property template for tag 5FC107.
	if v, ok := findAppPropertyVersion(selectResp.Data); ok {
		res.PIVVersion = v
	}

	// 2. GET VERSION (YubiKey-only).
	versionCmd := &apdu.Command{
		CLA: 0x00,
		INS: 0xFD,
		P1:  0x00,
		P2:  0x00,
		Le:  0,
	}
	versionResp, err := tx.Transmit(ctx, versionCmd)
	if err == nil && versionResp.IsSuccess() && len(versionResp.Data) == 3 {
		v, parseErr := ParseYubiKeyVersion(versionResp.Data)
		if parseErr == nil {
			res.YubiKeyFW = &v
			res.Profile = NewYubiKeyProfileVersion(v)
			return res, nil
		}
	}

	// No YubiKey signal: fall through to Standard PIV.
	res.Profile = NewStandardPIVProfile()
	return res, nil
}

// selectPIVApplet sends a SELECT AID PIV with the given AID bytes
// and returns the response. Transport errors are wrapped; status-
// word interpretation is the caller's job because Probe wants to
// branch on 6A82 specifically before treating it as terminal.
func selectPIVApplet(ctx context.Context, tx Transmitter, aid []byte) (*apdu.Response, error) {
	cmd := &apdu.Command{
		CLA:  0x00,
		INS:  0xA4,
		P1:   0x04,
		P2:   0x00,
		Data: aid,
		Le:   0,
	}
	resp, err := tx.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("piv/profile: SELECT AID PIV transport failed: %w", err)
	}
	return resp, nil
}

// findAppPropertyVersion extracts the PIV Application Version Number
// (tag 5FC107) from the application property template returned by
// SELECT AID PIV. SP 800-73-4 Part 2 §3.1.1 defines the template as
// a constructed TLV (tag 0x61) containing the version among other
// fields; older responses sometimes return the inner TLVs flat.
//
// Returns the raw value bytes and true on success; (nil, false) if
// the tag is absent. Errors in TLV decoding are not propagated because
// SELECT response shape varies by card and a probe should not fail
// on a well-formed SELECT just because version detection missed.
func findAppPropertyVersion(data []byte) ([]byte, bool) {
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, false
	}

	// Try the constructed application property template first.
	if t := tlv.Find(nodes, 0x61); t != nil {
		// Decode the template's contents and look for 5FC107 inside.
		inner, err := tlv.Decode(t.Value)
		if err == nil {
			if v := tlv.Find(inner, 0x5FC107); v != nil {
				return v.Value, true
			}
		}
	}

	// Fall back to a flat search at the top level.
	if v := tlv.Find(nodes, 0x5FC107); v != nil {
		return v.Value, true
	}
	return nil, false
}

// probedProfile wraps an underlying profile so its Name reflects that
// the choice came from a probe rather than from explicit construction.
// Capabilities pass through to the underlying profile unchanged.
type probedProfile struct {
	inner Profile
}

// NewProbedProfile wraps a probe-selected profile with a name prefix
// of "probed:". Callers can introspect the underlying profile via
// Underlying.
//
// This is a thin wrapper because the spec calls for the probe path
// to be visible in diagnostics ("probed:yubikey-5.7.2") without
// changing capability semantics.
func NewProbedProfile(p *ProbeResult) Profile {
	if p == nil || p.Profile == nil {
		return NewStandardPIVProfile()
	}
	return &probedProfile{inner: p.Profile}
}

// Name returns "probed:<inner-name>".
func (p *probedProfile) Name() string {
	return "probed:" + p.inner.Name()
}

// Capabilities passes through to the underlying profile unchanged.
func (p *probedProfile) Capabilities() Capabilities {
	return p.inner.Capabilities()
}

// Underlying exposes the wrapped profile for callers that need to
// type-assert to a concrete profile or inspect a YubiKey firmware
// version.
func (p *probedProfile) Underlying() Profile {
	return p.inner
}

// Compile-time assertion that piv is referenced (keeps the import
// from being elided on builds that strip unused imports).
var _ = piv.SlotPIVAuthentication
