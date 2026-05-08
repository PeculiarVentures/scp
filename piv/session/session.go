// Package session is a stateful PIV API over an APDU transmitter.
//
// # Why this exists
//
// The cmd/scp-smoke binary today carries roughly 500 lines of PIV
// orchestration (management-key mutual auth, generate-then-bind-then-
// install, PIN gating, attestation fetch) inline in CLI files. None
// of that orchestration is reachable from a non-CLI caller. This
// package lifts it into a library so server-side enrollment, future
// CLI rewrites, and the existing smoke harness all share one PIV
// vocabulary.
//
// # Profile gating
//
// Every operation consults the active piv/profile.Profile before
// emitting any APDU. Operations the profile does not claim are
// refused with piv.ErrUnsupportedByProfile, host-side, before any
// bytes go on the wire. Examples:
//
//   - PUT CERTIFICATE on slot 9a is allowed under both StandardPIV
//     and YubiKey profiles.
//
//   - GENERATE KEY for Ed25519 is refused under StandardPIV and
//     under YubiKey firmware older than 5.7.0.
//
//   - ATTEST is refused under StandardPIV (no attestation
//     instruction in SP 800-73-4) and accepted under YubiKey.
//
// # Transmitter
//
// A Session wraps any value implementing Transmitter, which is the
// same minimal interface used by piv/profile. Concrete transmitters:
//
//   - transport.Transport: raw, no secure channel.
//
//   - scp.Session (returned by scp03.Open or scp11.Open): all PIV
//     APDUs are wrapped with secure messaging by the underlying
//     channel layer.
//
//   - mockcard.Card: in-memory test target.
//
// OpenSCP11bPIV is provided as a convenience wrapper that establishes
// an SCP11b channel against the PIV applet and hands the resulting
// scp.Session to New. Other secure-channel modes are constructed by
// the caller and passed to New directly.
package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
)

// Transmitter is the minimal APDU pipe a Session uses. It matches
// scp.Session's Transmit signature so any established secure channel
// satisfies it directly, and it is also satisfied by transport.Transport
// for raw-channel use.
type Transmitter interface {
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
}

// Options configures a Session at construction time.
//
// Profile is the active capability profile. If nil, New runs Probe
// against the transmitter and uses the result; OpenRaw and
// OpenSCP11bPIV do the same. Pass an explicit profile when you
// already know what card class you're talking to (saves the probe
// round-trip), or to force a particular profile in testing.
type Options struct {
	// Profile is the capability profile the session enforces. nil
	// means "probe the card and use what comes back".
	Profile profile.Profile

	// SkipProbe disables the auto-probe path even when Profile is
	// nil. Used by tests that supply a transmitter without a working
	// SELECT response.
	SkipProbe bool

	// SkipSelect disables the unconditional SELECT AID PIV that New
	// runs before returning. Set this when the underlying transmitter
	// has already SELECTed the PIV applet (for example, an SCP11
	// session opened with cfg.SelectAID = scp11.AIDPIV; SCP11.Open
	// does the SELECT plaintext before the secure-channel handshake).
	// A second SELECT through an established secure channel is read
	// by some cards as a fresh-handshake signal and tears the session
	// down. OpenSCP11bPIV sets this for that reason.
	SkipSelect bool
}

// Session is a stateful PIV API over a transmitter. Instances are not
// safe for concurrent use; the underlying card serializes APDUs and
// the session tracks per-card state (PIN-verified, mgmt-auth-complete)
// that would race under concurrent access.
type Session struct {
	tx      Transmitter
	profile profile.Profile

	// pinVerified reflects whether VerifyPIN has succeeded since the
	// session was opened. Cleared by any operation that changes the
	// authorization state, including Reset and ChangePIN.
	pinVerified bool

	// mgmtAuthed reflects whether AuthenticateManagementKey has
	// succeeded since the session was opened. Cleared on Reset.
	mgmtAuthed bool

	// lastGeneratedSlot and lastGeneratedPubKey hold the result of the
	// most recent successful GenerateKey call, used by PutCertificate's
	// public-key binding check when the caller does not supply an
	// expected public key explicitly.
	lastGeneratedSlot   piv.Slot
	lastGeneratedPubKey interface{}
	lastGeneratedSet    bool
}

// New constructs a Session over an arbitrary transmitter.
//
// New always issues SELECT AID PIV against the transmitter before
// returning, unless opts.SkipSelect is set. The PIV applet must be
// selected on the card before any PIV instruction is accepted; doing
// it inside New means callers never have to remember and tests cannot
// get into a "send VERIFY before SELECT" state. The skip exists for
// callers that have already SELECTed through a different path,
// notably OpenSCP11bPIV where scp11.Open issues SELECT plaintext
// before the secure-channel handshake.
//
// If opts.Profile is nil and opts.SkipProbe is false, New also runs
// GET VERSION to detect a YubiKey firmware version and selects the
// resulting profile. If opts.Profile is set, New uses it without
// running GET VERSION; the SELECT still happens unless suppressed.
//
// If SELECT fails, New returns the underlying error. The session is
// not usable in that state.
func New(ctx context.Context, tx Transmitter, opts Options) (*Session, error) {
	if tx == nil {
		return nil, errors.New("piv/session: nil transmitter")
	}

	// SELECT AID PIV unless suppressed. Without it the card refuses
	// every PIV INS with 6985. Suppression is used when the underlying
	// transmitter (typically an established SCP11 session) has already
	// SELECTed the applet; sending a second SELECT through a secure
	// channel is read as a fresh-handshake signal by some cards and
	// tears the session down.
	if !opts.SkipSelect {
		// Try the full PIV AID first per SP 800-73-4 Part 1 §2.2;
		// fall back to the truncated 5-byte form on 6A82 for cards
		// that match by exact AID rather than prefix. See
		// profile.AIDPIVFull for the rationale; the same shape lives
		// here because session.New is the ground-floor path that
		// runs without a Probe (when opts.Profile is supplied).
		selectResp, err := selectPIV(ctx, tx, profile.AIDPIVFull)
		if err != nil {
			return nil, fmt.Errorf("piv/session: SELECT AID PIV transport: %w", err)
		}
		if !selectResp.IsSuccess() && selectResp.StatusWord() == 0x6A82 {
			selectResp, err = selectPIV(ctx, tx, profile.AIDPIV)
			if err != nil {
				return nil, fmt.Errorf("piv/session: SELECT AID PIV (truncated) transport: %w", err)
			}
		}
		if !selectResp.IsSuccess() {
			return nil, fmt.Errorf("piv/session: SELECT AID PIV failed (SW=%04X)",
				selectResp.StatusWord())
		}
	}

	prof := opts.Profile
	if prof == nil && !opts.SkipProbe {
		// Probe re-runs SELECT and adds GET VERSION. The extra SELECT
		// is harmless on a card that just accepted one. Trade-off:
		// one wasted APDU on the probe path, one fewer code path to
		// reason about. Skipped entirely when SkipSelect is set
		// because re-SELECTing through an SCP channel is unsafe; in
		// that case callers must supply Profile explicitly.
		if opts.SkipSelect {
			return nil, errors.New(
				"piv/session: SkipSelect requires an explicit Profile " +
					"because the auto-probe path issues SELECT")
		}
		res, err := profile.Probe(ctx, transmitterAdapter{tx})
		if err != nil {
			return nil, fmt.Errorf("piv/session: probe: %w", err)
		}
		prof = profile.NewProbedProfile(res)
	}
	if prof == nil {
		// SkipProbe with no profile: caller is using the SELECT we
		// just did and accepting Standard PIV as a baseline.
		prof = profile.NewStandardPIVProfile()
	}

	return &Session{tx: tx, profile: prof}, nil
}

// Profile returns the profile this session enforces. The returned
// value is the profile passed at construction (or selected by the
// auto-probe), unchanged.
func (s *Session) Profile() profile.Profile { return s.profile }

// Close is a no-op today. It exists so callers can defer Close in
// the same shape they would for a *scp.Session and so future
// resource cleanup (cached state, TLV scratch buffers, secure-memory
// scrubbing) has a place to live.
func (s *Session) Close() error { return nil }

// transmit is the single internal APDU path. Every session method
// goes through it. It exists so the wire-error -> *piv.CardError
// mapping happens in one place rather than at every call site, and
// so PIV's universal "SW=61xx means GET RESPONSE" behavior is
// applied transparently below the public API.
//
// Response chaining for SW=61xx is delegated to apdu.TransmitWithChaining
// so the same logic is available to other call sites that go around
// Session (currently cmd_piv_provision sending ATTEST directly over
// an scp11.Session). Without that, attestation against retail
// YubiKey 5.7+ — which routinely emits 61xx because cert chains
// span multiple frames — fails on the first GET RESPONSE the host
// declines to issue.
func (s *Session) transmit(ctx context.Context, op string, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := apdu.TransmitWithChaining(ctx, s.tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if !resp.IsSuccess() {
		// 63Cx carries the retry counter in the low nibble; expose it
		// via CardError.Message so RetriesRemaining can decode without
		// callers having to know the SW shape.
		sw := resp.StatusWord()
		msg := ""
		if sw >= 0x63C0 && sw <= 0x63CF {
			msg = fmt.Sprintf("retries remaining: %d", sw&0x000F)
		}
		return nil, piv.NewCardError(op, sw, msg)
	}
	return resp, nil
}

// transmitterAdapter wraps a session-shape Transmitter so it satisfies
// profile.Transmitter (same signature, different package). Avoids an
// import cycle between session and profile.
type transmitterAdapter struct {
	tx Transmitter
}

func (a transmitterAdapter) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return a.tx.Transmit(ctx, cmd)
}

// selectPIV sends a SELECT AID PIV with the given AID bytes. Errors
// are transport-level only; status-word interpretation is the
// caller's job because New wants to branch on 6A82 specifically
// before treating it as terminal.
//
// Routed through apdu.TransmitWithChaining so cards that respond
// to SELECT with SW=61xx ("application property template is xx
// bytes, fetch with GET RESPONSE") get their template assembled
// transparently. PR #150 fixed the same bug class in
// piv/profile/probe.go's selectPIVApplet; this is the parallel
// fix for the session-layer SELECT, which sits ahead of every
// PIV operation that goes through session.New.
func selectPIV(ctx context.Context, tx Transmitter, aid []byte) (*apdu.Response, error) {
	cmd := &apdu.Command{
		CLA:  0x00,
		INS:  0xA4,
		P1:   0x04,
		P2:   0x00,
		Data: aid,
		Le:   0,
	}
	return apdu.TransmitWithChaining(ctx, tx, cmd)
}
