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
//     next candidate. SmartJac and some SafeNet variants
//     answer 6A87 instead of 6A82 when the AID is unknown
//     because their dispatcher rejects the SELECT before AID
//     matching. Treating it as "not found" gives interop
//     against those cards without masking other 6A87 cases
//     (the trace callback shows what happened).
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
//     ErrNoISDFound with the count and last SW.
//
// Pass gp.ISDDiscoveryAIDs for the curated default list, or a
// custom slice when scripted automation has its own probe order.
//
// Pass a non-nil trace to receive a DiscoveryAttempt per probe.
// nil disables tracing. The trace runs synchronously on the
// caller's goroutine; an expensive callback throttles discovery.
//
// Caller owns the returned *Session; close it via Session.Close.
func DiscoverISD(ctx context.Context, t transport.Transport, candidates []gp.ISDCandidate, trace DiscoveryTrace) (*Session, gp.ISDCandidate, error) {
	if t == nil {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: transport is required")
	}
	if len(candidates) == 0 {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: no candidates supplied")
	}

	var lastErr error
	var lastSW uint16
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

		switch sw {
		case 0x6A82, 0x6A87:
			// "Not found" signals (6A82 standard, 6A87 SmartJac /
			// some SafeNet dispatchers). Try next candidate.
			lastErr = err
			lastSW = sw
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
	return nil, gp.ISDCandidate{}, fmt.Errorf("%w (tried %d AIDs, last SW=%04X, err=%v)",
		ErrNoISDFound, len(candidates), lastSW, lastErr)
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
