package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/trust"
)

// SCP11bPIVOptions configures OpenSCP11bPIV. The two safe defaults
// (target the YubiKey 5.7+ PIV applet, expect SCP11b key set 0x13/0x01)
// are baked in; the trust posture must be supplied explicitly because
// "skip trust" is a deliberate decision that should never default.
type SCP11bPIVOptions struct {
	// Profile is the active capability profile. nil defaults to
	// profile.NewYubiKeyProfile() (YubiKey 5.7+).
	//
	// The default is YubiKey-only because SCP11b-on-PIV is itself a
	// YubiKey-only feature today: cards that lack SCP11b cannot reach
	// this code path, so a successful Open implies a 5.7+ YubiKey at
	// the other end. Probing over the secure channel after Open is a
	// future helper; today's Open is followed directly by session.New
	// with SkipSelect=true, which suppresses the probe path because
	// probing requires its own SELECT and a second SELECT through
	// the established secure channel is read as a fresh-handshake
	// signal by some cards.
	//
	// Set this field explicitly when targeting older firmware
	// (use NewYubiKeyProfileVersion) or when a non-YubiKey card with
	// SCP11b-on-PIV becomes a thing in the future.
	Profile profile.Profile

	// CardTrustPolicy is the SCP11 card-authentication trust policy.
	// Production code supplies a real policy here; lab/test code
	// can set InsecureSkipCardAuthentication instead.
	CardTrustPolicy *trust.Policy

	// InsecureSkipCardAuthentication mirrors scp11.Config's field of
	// the same name. Visible in any structured report that records
	// the session's posture so a downstream auditor can tell the
	// difference between an authenticated channel and a lab one.
	InsecureSkipCardAuthentication bool
}

// OpenSCP11bPIV establishes an SCP11b secure channel against the
// PIV applet and wraps the resulting scp11.Session as a PIV Session.
//
// The convention for SCP11b-on-PIV is documented at the SCP11
// package level: SelectAID is the PIV AID, ApplicationAID is nil,
// KeyID/KeyVersion default to YubiKey's 0x13/0x01 key set. This
// helper applies that convention; callers that need a different
// SCP11 configuration shape should call scp11.Open directly and
// pass the resulting *scp11.Session to New.
//
// One of opts.CardTrustPolicy or opts.InsecureSkipCardAuthentication
// must be set; otherwise the underlying scp11.Open fails closed.
func OpenSCP11bPIV(
	ctx context.Context,
	t transport.Transport,
	opts SCP11bPIVOptions,
) (*Session, error) {
	if t == nil {
		return nil, errors.New("piv/session: nil transport")
	}
	if opts.CardTrustPolicy == nil && !opts.InsecureSkipCardAuthentication {
		return nil, errors.New(
			"piv/session: SCP11b requires CardTrustPolicy or " +
				"InsecureSkipCardAuthentication to be set")
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	cfg.CardTrustPolicy = opts.CardTrustPolicy
	cfg.InsecureSkipCardAuthentication = opts.InsecureSkipCardAuthentication

	scpSess, err := scp11.Open(ctx, t, cfg)
	if err != nil {
		return nil, fmt.Errorf("piv/session: SCP11b open: %w", err)
	}

	// scp11.Session.Transmit matches the session.Transmitter shape;
	// no adapter needed. SkipSelect is true because scp11.Open did
	// SELECT AID PIV plaintext before the SCP handshake; a second
	// SELECT through the established secure channel would be read as
	// a fresh-handshake signal by some cards. SkipProbe tracks
	// Profile because the probe path issues its own SELECT and is
	// therefore blocked when SkipSelect is true.
	if opts.Profile == nil {
		// Without an explicit profile, default to the YubiKey 5.7+
		// profile. This is the safe default for an SCP11b-on-PIV
		// channel because cards that lack SCP11b-on-PIV (Standard
		// PIV) cannot reach this code path; if the channel
		// established, the card supports the YubiKey 5.7+ feature
		// set by definition.
		opts.Profile = profile.NewYubiKeyProfile()
	}
	sess, err := New(ctx, scpSess, Options{
		Profile:    opts.Profile,
		SkipProbe:  true,
		SkipSelect: true,
	})
	if err != nil {
		scpSess.Close()
		return nil, err
	}
	return sess, nil
}
