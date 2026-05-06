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

// DiscoverISD probes a transport for a Security Domain by
// SELECTing each candidate AID in order. Returns the open
// unauthenticated session against the first candidate that
// answered 9000, plus the candidate that matched.
//
// Failure handling:
//   - SW=6A82 (file not found): try the next candidate.
//   - Any other non-9000 SW: abort with that error. Real-card
//     errors (security state, card mute) should not be silently
//     retried against every other AID; that risks masking the
//     real problem.
//   - Transport errors: abort.
//   - All candidates exhausted with 6A82: return ErrNoISDFound.
//
// Pass gp.ISDDiscoveryAIDs for the curated default list, or a
// custom slice when scripted automation has its own probe order.
//
// Caller owns the returned *Session; close it via Session.Close.
func DiscoverISD(ctx context.Context, t transport.Transport, candidates []gp.ISDCandidate) (*Session, gp.ISDCandidate, error) {
	if t == nil {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: transport is required")
	}
	if len(candidates) == 0 {
		return nil, gp.ISDCandidate{}, errors.New("securitydomain: no candidates supplied")
	}

	var lastErr error
	for _, c := range candidates {
		sd, err := OpenUnauthenticated(ctx, t, c.AID)
		if err == nil {
			return sd, c, nil
		}

		// SW=6A82 means "this AID isn't here" — try the next.
		var ae *APDUError
		if errors.As(err, &ae) && ae.SW == 0x6A82 {
			lastErr = err
			continue
		}

		// Any other failure is unexpected and aborts discovery so
		// we don't mask the real problem.
		return nil, gp.ISDCandidate{}, fmt.Errorf("DiscoverISD aborted at candidate %q: %w",
			candidateLabel(c), err)
	}
	return nil, gp.ISDCandidate{}, fmt.Errorf("%w (tried %d AIDs, last SW=%v)",
		ErrNoISDFound, len(candidates), lastErr)
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
