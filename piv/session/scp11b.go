package session

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
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

	// CardStaticPublicKey is PK.SD.ECKA — the Security Domain's static
	// SCP11 public key. When non-nil, OpenSCP11bPIV uses this key
	// directly and skips the SD discovery round trip. Production
	// callers that have already obtained and validated the key should
	// supply it here for predictability and to avoid a second
	// SELECT/GET DATA against the SD on every PIV open.
	//
	// When nil, OpenSCP11bPIV opens an unauthenticated SD session,
	// reads the certificate bundle for the SCP11b key (KID=0x13,
	// KVN=0x01 by default — see SCP11bKeyReference), validates the
	// chain per CardTrustPolicy / InsecureSkipCardAuthentication, and
	// extracts PK.SD.ECKA from the leaf.
	CardStaticPublicKey *ecdh.PublicKey

	// SCP11bKeyReference overrides the default SCP11b key reference
	// (KID=0x13, KVN=0x01) used during SD discovery. Has no effect
	// when CardStaticPublicKey is supplied. The zero value falls back
	// to KID=0x13, KVN=0x01.
	SCP11bKeyReference securitydomain.KeyReference
}

// OpenSCP11bPIV establishes an SCP11b secure channel against the
// PIV applet and wraps the resulting scp11.Session as a PIV Session.
//
// Wire flow on YubiKey:
//
//  1. SELECT the Security Domain.
//  2. GET DATA BF21 with the SCP11b key reference, retrieving the
//     card's certificate chain.
//  3. Validate the chain (or skip with InsecureSkipCardAuthentication).
//  4. Extract PK.SD.ECKA (the leaf's static ECDH public key).
//  5. SELECT the PIV applet.
//  6. Run the SCP11b handshake against PIV with the pre-supplied key.
//
// Steps 1-4 are required because the SCP11 certificate lives on the
// Security Domain, not the PIV applet — GET DATA BF21 against PIV
// returns SW=6D00 (instruction not supported). The PIV applet's SCP11b
// handshake uses the SD's underlying static private key implicitly.
//
// Callers can short-circuit steps 1-4 by supplying CardStaticPublicKey
// directly. That's the production path: validate the key once, cache
// it, and reuse it.
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

	pubKey, err := resolveCardStaticPublicKey(ctx, t, opts)
	if err != nil {
		return nil, fmt.Errorf("piv/session: resolve PK.SD.ECKA: %w", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	cfg.CardTrustPolicy = opts.CardTrustPolicy
	cfg.InsecureSkipCardAuthentication = opts.InsecureSkipCardAuthentication
	cfg.PreverifiedCardStaticPublicKey = pubKey

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

// resolveCardStaticPublicKey returns the PK.SD.ECKA the SCP11b
// handshake will use. If the caller pre-supplied one in opts, that
// is used directly. Otherwise the helper performs the SD-side
// discovery: select the SD unauthenticated, read the cert bundle for
// the configured SCP11b key reference, validate per the trust posture,
// and return the leaf public key.
func resolveCardStaticPublicKey(
	ctx context.Context,
	t transport.Transport,
	opts SCP11bPIVOptions,
) (*ecdh.PublicKey, error) {
	if opts.CardStaticPublicKey != nil {
		return opts.CardStaticPublicKey, nil
	}

	ref := opts.SCP11bKeyReference
	if ref == (securitydomain.KeyReference{}) {
		ref = securitydomain.NewKeyReference(securitydomain.KeyIDSCP11b, 0x01)
	}

	return securitydomain.FetchCardPublicKey(ctx, t, securitydomain.FetchCardPublicKeyOptions{
		KeyReference:                   ref,
		CardTrustPolicy:                opts.CardTrustPolicy,
		InsecureSkipCardAuthentication: opts.InsecureSkipCardAuthentication,
	})
}
