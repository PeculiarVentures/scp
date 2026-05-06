package securitydomain

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
)

// LifecycleState identifies an Issuer Security Domain lifecycle state
// per GP Card Specification §5.1.1 Table 5-1. The state machine is:
//
//	OP_READY → INITIALIZED → SECURED ⇄ CARD_LOCKED → TERMINATED
//
// Transitions are controlled by SET STATUS (GP §11.1.10). OP_READY
// and INITIALIZED are pre-issuance personalization states; production
// cards live in SECURED until they're locked or terminated. CARD_LOCKED
// is recoverable; TERMINATED is permanent.
type LifecycleState byte

const (
	// LifecycleOPReady is the post-fab state. Most personalization
	// operations are allowed but the card has no production keys yet.
	LifecycleOPReady LifecycleState = 0x01

	// LifecycleInitialized has cardholder/applet data installed but
	// is not yet locked against further structural changes.
	LifecycleInitialized LifecycleState = 0x07

	// LifecycleSecured is the production state. Most installations
	// stay here for the life of the card.
	LifecycleSecured LifecycleState = 0x0F

	// LifecycleCardLocked disables most card-level operations; SCP
	// authentication still works so the card can be unlocked back to
	// SECURED. Recoverable.
	LifecycleCardLocked LifecycleState = 0x7F

	// LifecycleTerminated permanently disables the card. The
	// transition is irreversible — the card cannot be returned to
	// any other lifecycle state by any operation. GP-conformant
	// cards reject every non-SELECT command after TERMINATED.
	LifecycleTerminated LifecycleState = 0xFF
)

// String returns the GP-spec name of the lifecycle state, or
// "LifecycleState(0xXX)" for unrecognized values.
func (l LifecycleState) String() string {
	switch l {
	case LifecycleOPReady:
		return "OP_READY"
	case LifecycleInitialized:
		return "INITIALIZED"
	case LifecycleSecured:
		return "SECURED"
	case LifecycleCardLocked:
		return "CARD_LOCKED"
	case LifecycleTerminated:
		return "TERMINATED"
	default:
		return fmt.Sprintf("LifecycleState(0x%02X)", byte(l))
	}
}

// GP §11.1.10 SET STATUS.
const insSetStatus byte = 0xF0

// LifecycleError carries the structured failure detail when a
// SET STATUS APDU returns a non-9000 status word. Callers that
// need the raw SW byte for telemetry or operator-facing error
// reporting (e.g. lifecycle JSON output that has to distinguish
// 'card policy rejected the transition' — 6985, 6982, 6A88 —
// from 'host encoded wrong APDU') extract it via errors.As:
//
//	var lerr *LifecycleError
//	if errors.As(err, &lerr) {
//	    fmt.Printf("card rejected transition with SW=%04X\n", lerr.SW)
//	}
//
// errors.Is(err, ErrCardStatus) still works — LifecycleError
// wraps ErrCardStatus via Unwrap so existing callers that
// branch on the sentinel keep working unchanged.
//
// Per the external review on feat/sd-keys-cli, Finding 10:
// 'lifecycle behavior varies across cards, and the library
// deliberately does not enforce a transition table, leaving
// invalid transitions to card responses [...] the CLI should
// preserve raw lifecycle byte and raw SW in JSON for every
// failed transition.' This typed error is the structured
// extraction point that makes the JSON preservation possible.
type LifecycleError struct {
	// Target is the lifecycle state the caller asked for
	// (CARD_LOCKED, SECURED, TERMINATED).
	Target LifecycleState

	// SW is the raw status word the card returned. The
	// common rejections per GP §11.1.10 + ISO 7816-4 Table 11:
	//   - 0x6985: conditions of use not satisfied (card
	//             policy rejected this transition for the
	//             current lifecycle state)
	//   - 0x6982: security status not satisfied (the
	//             authenticated session lacks the privilege
	//             needed for this transition)
	//   - 0x6A88: referenced data not found (the targeted
	//             SD AID isn't recognized; recovery is
	//             out-of-scope)
	// Cards can return other SWs; LifecycleError preserves
	// whatever the card actually said without interpretation.
	SW uint16
}

func (e *LifecycleError) Error() string {
	return fmt.Sprintf("%s: SET STATUS to %s: SW=%04X",
		ErrCardStatus.Error(), e.Target, e.SW)
}

func (e *LifecycleError) Unwrap() error { return ErrCardStatus }

// SetISDLifecycle issues GP §11.1.10 SET STATUS to transition the
// Issuer Security Domain to the requested lifecycle state.
//
// Wire format (P1 = 0x80 ISD scope):
//
//	CLA = 0x80
//	INS = 0xF0 (SET STATUS)
//	P1  = 0x80 (ISD scope)
//	P2  = target lifecycle byte
//	Lc  = len(ISD AID)
//	Data = ISD AID (per GP §11.1.10 Table 11-25, required when
//	       P1 indicates ISD)
//
// SetISDLifecycle does NOT enforce legal transitions in software.
// The card is the source of truth on what's allowed; illegal
// transitions return SW=6985 (conditions of use not satisfied) or
// SW=6982 (security status not satisfied). Callers that want a
// pre-check should read the current state via Session.GetStatus
// with StatusScopeISD before calling.
//
// Error returns. Card-side failures (non-9000 SW) come back as
// *LifecycleError carrying the raw SW; transport-level failures
// come back as a wrapped fmt.Errorf. Callers needing structured
// SW handling should use errors.As(&LifecycleError{}); callers
// that just want to know it failed can still errors.Is against
// ErrCardStatus.
//
// Authentication required.
//
// SET STATUS modifies card-level state, so it requires an
// authenticated SCP session that authenticates the off-card entity
// (SCP03, SCP11a, or SCP11c). SCP11b authenticates the card to the
// host but not the host to the card; the OCE-auth check below
// rejects SCP11b sessions before the APDU goes out so the failure
// is clear rather than surfacing as an opaque card-side 6982.
//
// Reversibility.
//
// Transitioning to LifecycleTerminated is permanent. The card
// CANNOT be brought back from TERMINATED by any operation — no
// reset, no re-personalization, no manufacturer recovery (short of
// chip replacement). Callers exposing this through a CLI surface
// should require an explicit, distinct confirmation flag for the
// terminate path; --confirm-write is not enough.
func (s *Session) SetISDLifecycle(ctx context.Context, target LifecycleState) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  insSetStatus,
		P1:   byte(StatusScopeISD), // 0x80
		P2:   byte(target),
		Data: append([]byte(nil), AIDSecurityDomain...),
		Le:   -1,
	}
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: SET STATUS to %s: %w", target, err)
	}
	if !resp.IsSuccess() {
		return &LifecycleError{Target: target, SW: resp.StatusWord()}
	}
	return nil
}
