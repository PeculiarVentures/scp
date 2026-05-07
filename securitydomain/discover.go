package securitydomain

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/transport"
)

// ErrNoISDFound is returned by DiscoverISD when none of the
// supplied candidate AIDs SELECTed successfully on the card.
// errors.Is matches against this sentinel so callers can
// distinguish "exhausted candidate list" from a transport error
// or an unexpected non-6A82 SW that aborted discovery early.
var ErrNoISDFound = errors.New("securitydomain: no candidate AID found an ISD")

// ErrLockedISD is returned by DiscoverISD when a candidate AID
// SELECTed with SW=6283 ("selected file/application invalidated"
// per ISO 7816-4 Table 11). The SD exists at this AID but is in
// TERMINATED or LOCKED state and cannot serve commands. Distinct
// from ErrNoISDFound: the operator's discovery list is correct
// but the card needs out-of-band recovery (factory reset on
// YubiKey, Issuer Security Domain unlock on JCOP, etc.) before
// the SD will respond. errors.Is matches this so automation can
// branch on lock vs absent.
var ErrLockedISD = errors.New("securitydomain: ISD found but locked (SW=6283)")

// DiscoveryAttempt records a single SELECT probe during ISD
// discovery: which candidate was tried, what SW the card
// returned (or 0 if the transport never produced one), and
// whether this attempt was the one that the discovery loop
// settled on. Used by the trace callback to expose every
// attempted SELECT to operators debugging a discovery failure.
type DiscoveryAttempt struct {
	Candidate gp.ISDCandidate
	SW        uint16 // 0 if transport error before SW was returned
	Err       error  // non-nil for any non-9000 outcome
	Selected  bool   // true when this attempt was returned as the chosen ISD
}

// DiscoveryTrace receives one DiscoveryAttempt per candidate
// SELECT during DiscoverISD. Lets a CLI print "tried <AID>: SW=
// <hex>" lines so an operator who hits a discovery failure can
// see what was attempted instead of a single aggregate error.
// May be nil; DiscoverISD checks before invoking.
type DiscoveryTrace func(DiscoveryAttempt)

// DiscoverISD probes a transport for a Security Domain by
// SELECTing each candidate AID in order. Returns the open
// unauthenticated session against the first candidate that
// answered 9000, plus the candidate that matched.
//
// Failure handling:
//   - SW=6A82 (file not found): try the next candidate. The
//     standard "this AID isn't here" signal.
//   - SW=6A87 (Lc inconsistent / unexpected length): try the
//     next candidate. Per the feat/sd-keys-cli coordination
//     brief, some SmartJac and SafeNet GP card variants
//     answer 6A87 rather than 6A82 when the AID is unknown
//     because their dispatcher rejects the SELECT before
//     AID matching. Treating it as "not found" gives interop
//     against those cards without masking other 6A87 cases
//     (the trace callback shows what happened). The
//     attribution is from field reports relayed via that
//     brief, not from a hardware-verified trace replay; the
//     test fixture pins the host-side behavior against a
//     scripted transport.
//   - SW=6283 (selected file/application invalidated): the SD
//     exists but is in TERMINATED/LOCKED state. Returns
//     ErrLockedISD with the locked candidate; abort rather
//     than continue probing because the operator's discovery
//     list is correct, the card needs recovery.
//   - Any other non-9000 SW: abort with that error. Real-card
//     errors (security state, card mute) should not be
//     silently retried against every other AID; that risks
//     masking the real problem.
//   - Transport errors: abort.
//   - All candidates exhausted with 6A82/6A87: return
//     ErrNoISDFound. The error message lists each tried AID
//     and the SW the card returned for it, plus an
//     actionable hint pointing to --sd-aid (the CLI flag for
//     supplying a vendor- or deployment-specific ISD AID
//     that isn't on the curated default list).
//
// Pass gp.ISDDiscoveryAIDs for the curated default list, or a
// custom slice when scripted automation has its own probe order.
//
// Pass a non-nil trace to receive a DiscoveryAttempt per probe.
// nil disables tracing. The trace runs synchronously on the
// caller's goroutine; an expensive callback throttles discovery.
//
// Caller owns the returned *Session; close it via Session.Close.
// discoveryAttempt records what each SELECT probe returned, used
// only to build the exhaustion-path error message. Distinct from
// the public DiscoveryAttempt type, which is what the trace
// callback receives — that type also includes the candidate's
// Source citation and a Selected flag, neither of which the
// final error message needs.
type discoveryAttempt struct {
	aid []byte
	sw  uint16
}

func DiscoverISD(ctx context.Context, t transport.Transport, candidates []gp.ISDCandidate, trace DiscoveryTrace) (*Session, gp.ISDCandidate, error) {
	if t == nil {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: transport is required")
	}
	if len(candidates) == 0 {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: no candidates supplied")
	}

	// Track every attempt so the exhaustion-path error message
	// can name each AID and SW. The trace callback already sees
	// these per-attempt; this slice exists so the final error
	// is self-contained for operators who don't capture the
	// trace stream.
	var attempts []discoveryAttempt
	var lastErr error

	for _, c := range candidates {
		sd, err := OpenUnauthenticated(ctx, t, c.AID)
		if err == nil {
			if trace != nil {
				trace(DiscoveryAttempt{Candidate: c, SW: 0x9000, Selected: true})
			}
			return sd, c, nil
		}

		// Extract SW from the typed APDUError when present so
		// the trace and dispatch logic both see the same value.
		var ae *APDUError
		var sw uint16
		if errors.As(err, &ae) {
			sw = ae.SW
		}
		if trace != nil {
			trace(DiscoveryAttempt{Candidate: c, SW: sw, Err: err})
		}
		attempts = append(attempts, discoveryAttempt{aid: c.AID, sw: sw})

		switch sw {
		case 0x6A82, 0x6A87:
			// "Not found" signals (6A82 standard, 6A87 SmartJac /
			// some SafeNet dispatchers). Try next candidate.
			lastErr = err
			continue
		case 0x6283:
			// "Selected but locked." The SD exists at this AID
			// but is in TERMINATED/LOCKED state. Don't keep
			// probing — surface the locked-AID distinctly.
			return nil, gp.ISDCandidate{},
				fmt.Errorf("%w at candidate %q: %w",
					ErrLockedISD, candidateLabel(c), err)
		}

		// Any other failure aborts discovery.
		return nil, gp.ISDCandidate{}, fmt.Errorf("DiscoverISD aborted at candidate %q: %w",
			candidateLabel(c), err)
	}
	return nil, gp.ISDCandidate{}, fmt.Errorf("%w; %s; supply the AID for this card with --sd-aid (vendor documentation, card datasheet, or output of GET STATUS on a card with a known-working ISD): last error: %v",
		ErrNoISDFound, formatExhaustedAttempts(attempts), lastErr)
}

// formatExhaustedAttempts builds the per-attempt diagnostic the
// exhaustion-path error embeds. Each attempt renders as
// "<AID-hex> SW=<hex>"; nil AID renders as "(empty SELECT)".
// Anchored by the introductory phrase "tried N AIDs:" so a
// single-line error remains parseable by automation.
func formatExhaustedAttempts(attempts []discoveryAttempt) string {
	if len(attempts) == 0 {
		return "tried 0 AIDs"
	}
	parts := make([]string, 0, len(attempts))
	for _, a := range attempts {
		var aidStr string
		if len(a.aid) == 0 {
			aidStr = "(empty SELECT)"
		} else {
			aidStr = fmt.Sprintf("%X", a.aid)
		}
		parts = append(parts, fmt.Sprintf("%s SW=%04X", aidStr, a.sw))
	}
	out := fmt.Sprintf("tried %d AIDs: ", len(attempts))
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// candidateLabel formats a candidate for log/error messages.
// Empty AID becomes "(default)" rather than empty hex, since the
// nil-AID case is meaningful (default SELECT per ISO 7816-4).
func candidateLabel(c gp.ISDCandidate) string {
	if len(c.AID) == 0 {
		return "(default)"
	}
	return fmt.Sprintf("%X", c.AID)
}
