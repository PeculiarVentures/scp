// Package scp11 implements the SCP11 protocol state machine for
// establishing a secure channel between an off-card entity (OCE) and
// an applet on a smart card. The applet typically holds an SCP key
// set — most commonly the GlobalPlatform Issuer Security Domain, but
// also PIV, OATH, or any other applet that exposes its own SCP keys.
//
// The protocol flow (for SCP11b) is:
//
//  1. SELECT the target applet AID (configured via Config.SelectAID)
//  2. GET DATA to retrieve the card's certificate (CERT.SD.ECKA)
//     containing the card's static ECDH public key (PK.SD.ECKA)
//  3. OCE generates an ephemeral ECDH key pair
//  4. INTERNAL AUTHENTICATE: OCE sends its ephemeral public key;
//     card responds with its own ephemeral public key (and receipt for SCP11c)
//  5. Both sides perform dual ECDH:
//     - ShSee = ECDH(ePK.OCE, eSK.SD)  — ephemeral-ephemeral
//     - ShSes = ECDH(PK.SD, eSK.OCE)   — static-ephemeral
//  6. Derive session keys via X9.63 KDF
//  7. (SCP11a/c only) Verify receipt for mutual authentication
//  8. Wrap subsequent commands with secure messaging
//
// For SCP11a, the OCE first sends PERFORM SECURITY OPERATION with its
// certificate before step 4.
//
// The session layer orchestrates the complete SCP11 handshake
// the Session wraps a Transport and exposes a secure Transmit method.
//
// # Errors
//
// Open and Transmit wrap a small set of sentinel errors so callers
// can use errors.Is to discriminate categories without pattern-
// matching on message text. See ErrAuthFailed, ErrInvalidConfig,
// ErrInvalidResponse, and ErrTrustValidation.
package scp11

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/internal/secmem"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/trust"
)

// Variant selects the SCP11 protocol variant.
type Variant int

// SCP11 protocol variants per GP Amendment F. SCP11a and SCP11c are
// mutual-auth (the off-card entity authenticates to the card with a
// certificate chain); SCP11b is one-way (the card authenticates to
// the off-card entity but the OCE is unauthenticated).
const (
	SCP11a Variant = iota // Mutual auth, OCE provides cert first
	SCP11b                // One-way auth, no OCE cert validation by card
	SCP11c                // Mutual auth with receipt, scriptable
)

// State tracks the session lifecycle.
type State int

// Session lifecycle states. The transitions are linear except for
// StateFailed, which can be entered from any other state on a
// terminal error (handshake failure, MAC verification failure,
// counter exhaustion). A failed session cannot be reused; the
// caller must call Open again to establish a fresh channel.
const (
	StateNew           State = iota // Pre-Open: no APDUs sent yet
	StateSelected                   // Applet selected, handshake not started
	StateCertRetrieved              // Card cert chain retrieved and validated
	StateAuthenticated              // Secure channel established, ready for Transmit
	StateFailed                     // Terminal: keys zeroed, channel unusable
)

// KeyRef identifies a key set on the card by its Key Identifier
// (KID) and Key Version Number (KVN). Used in SCP11a/c to address
// the OCE certificate slot when uploading the OCE certificate chain
// via PERFORM SECURITY OPERATION.
type KeyRef struct {
	KID byte
	KVN byte
}

// Config holds the parameters for establishing an SCP11 session.
type Config struct {
	// Variant selects SCP11a, SCP11b, or SCP11c.
	Variant Variant

	// SelectAID is the applet AID to SELECT (unwrapped) before the
	// SCP handshake begins. The handshake (GET DATA, INTERNAL/MUTUAL
	// AUTHENTICATE) authenticates against the SCP key set held by
	// this applet:
	//
	//   - For Security Domain management: AIDSecurityDomain (default).
	//   - For PIV provisioning over SCP on YubiKey: AIDPIV.
	//
	// If nil, no SELECT is sent — the caller is expected to have
	// SELECTed the target applet through some other path (a test
	// harness, a multiplexing transport, etc.).
	//
	// This field replaces the previous SecurityDomainAID, which had
	// a misleading name: any applet's SCP key set can be the target,
	// not just the Issuer Security Domain.
	SelectAID []byte

	// ApplicationAID is an optional second applet to SELECT *through*
	// the secure channel after the handshake completes. Note: on
	// YubiKey, SCP is scoped to the SELECTed applet and selecting a
	// different applet through the channel terminates the session.
	// Set this to nil for YubiKey use; configure SelectAID instead.
	// Example (non-YubiKey hardware that supports cross-applet SCP):
	// AIDPIV = A000000308
	ApplicationAID []byte

	// KeyID and KeyVersion identify the key set on the card.
	// Default: 0x13 / 0x01 (SCP11b defaults)
	KeyID      byte
	KeyVersion byte

	// OCECertificates is the OCE's certificate chain for SCP11a/c,
	// in leaf-LAST order (intermediates first, OCE's own cert at the
	// end). Each cert in the chain is sent as a separate PERFORM
	// SECURITY OPERATION APDU per GP §7.5.2 and Yubico's reference
	// implementation. The card validates the chain against its trust
	// anchors before accepting the OCE's authentication.
	//
	// Required for SCP11a/c. Not used by SCP11b. A single self-signed
	// or directly-issued OCE cert is expressed as a one-element slice.
	OCECertificates []*x509.Certificate

	// OCEKeyReference identifies the OCE key set on the card. KVN is
	// sent as P1 of each PERFORM SECURITY OPERATION APDU; KID is sent
	// as P2 with the chain bit (0x80) set for non-final certs and
	// cleared for the final (leaf) cert. This matches Yubico's
	// reference implementation in yubikit-android's
	// SecurityDomainSession and yubikit's scp.py:
	//
	//   p2 = oce_ref.kid | (0x80 if i < n else 0)
	//
	// Required for SCP11a/c. Not used by SCP11b.
	OCEKeyReference KeyRef

	// OCEPrivateKey is the OCE's long-term ECDSA key for SCP11a/c
	// certificate-based authentication. Must correspond to the LEAF
	// certificate in OCECertificates (i.e. the last entry). Not
	// needed for SCP11b.
	OCEPrivateKey *ecdsa.PrivateKey

	// CardTrustAnchors validates the card's certificate chain via
	// x509.Verify with this CertPool as Roots. Intermediates from
	// the card's BF21 certificate store are added automatically.
	//
	// At least one of CardTrustAnchors, CardTrustPolicy, or
	// InsecureSkipCardAuthentication must be set; if all three are
	// nil, Open fails closed before any ECDH (an SCP11 session
	// against an unauthenticated card key is opportunistic
	// encryption, not authenticated key agreement).
	//
	// For richer validation (P-256 enforcement, serial allowlists,
	// SKI matching, EKU constraints), use CardTrustPolicy instead.
	CardTrustAnchors *x509.CertPool

	// CardTrustPolicy, if set, provides full SCP11 certificate chain
	// validation via the trust package. This supersedes CardTrustAnchors.
	// When set, the library parses all certificates from the card's
	// certificate store, validates the chain, enforces P-256, and
	// only extracts the public key after successful validation.
	// If validation fails, session establishment fails closed.
	CardTrustPolicy *trust.Policy

	// InsecureSkipCardAuthentication permits SCP11 without validating the
	// card certificate. This is intended only for tests and labs. Production
	// callers should configure CardTrustPolicy or CardTrustAnchors.
	InsecureSkipCardAuthentication bool

	// PreverifiedCardStaticPublicKey supplies PK.SD.ECKA — the card's
	// static SCP11 public key — that the caller has already obtained
	// and validated (typically by reading the Security Domain's
	// certificate store via securitydomain.Session.GetCertificates and
	// validating the chain). When non-nil, Open skips its internal
	// GET DATA BF21 step and uses this key directly.
	//
	// This split is required for SCP11b-on-PIV: the certificate lives
	// on the Security Domain (BF21 against PIV returns SW=6D00), while
	// the secure channel is established against PIV. Callers fetch and
	// verify the key against the SD, then open SCP11 against PIV with
	// the key already in hand.
	//
	// Trust-posture pairing.
	//
	// Setting this field bypasses the in-library chain-validation
	// path entirely — there is no cert fetch and no chain for
	// CardTrustPolicy or CardTrustAnchors to validate against
	// (Policy validates a cert chain, not a bare pubkey). Open
	// rejects the combination of PreverifiedCardStaticPublicKey with
	// CardTrustPolicy or CardTrustAnchors with ErrInvalidConfig.
	//
	// Callers using this field MUST set InsecureSkipCardAuthentication
	// = true as the trust-posture marker. The "Insecure" in the name
	// is loud on purpose: the in-library validation is being
	// deliberately bypassed, the asserted assumption being that the
	// caller validated upstream (e.g. via
	// securitydomain.FetchCardPublicKey applying their trust policy
	// to the SD's cert chain before extracting the leaf pubkey).
	PreverifiedCardStaticPublicKey *ecdh.PublicKey

	// HostID is the optional OCE identifier included in the KDF shared
	// info per GP SCP11 §3.1.2. If set, it is appended to the shared
	// info as a length-value pair: len(HostID) || HostID.
	//
	// Expansion target: the KDF shared-info path appends HostID
	// correctly, but the wire-side encoding is not yet wired — the
	// AUTHENTICATE command does not set the SCP11 parameter bit
	// indicating identifiers are included, and does not include the
	// tag-0x84 Host ID in the control reference template. Setting
	// this field today would derive a different key schedule than
	// the card, so Open fails closed when it is non-empty. Completing
	// the implementation covers the AUTHENTICATE parameter bit, tag
	// 0x84, and matching KDF shared-info behavior end-to-end.
	HostID []byte

	// CardGroupID is the optional card group identifier for SCP11c.
	// Included in the KDF shared info after HostID if set.
	//
	// Expansion target: same caveat as HostID — the KDF inclusion is
	// wired but the AUTHENTICATE parameter bit and tag 0x84 are not.
	// Open rejects sessions with this field set.
	CardGroupID []byte

	// SecurityLevel controls which secure messaging operations to apply.
	// Default: full security (C-MAC + C-DEC + R-MAC + R-ENC).
	SecurityLevel channel.SecurityLevel

	// InsecureTestOnlyEphemeralKey, if non-nil, overrides random
	// ephemeral ECDH key generation in the SCP11 handshake.
	//
	// SCP11's security depends on the ephemeral key being unique per
	// session and unpredictable. Setting this field DEFEATS that
	// property and reduces SCP11 to long-term-key-only authentication.
	// A static or known ephemeral key allows an attacker who has ever
	// observed it (or simply guessed it from the source) to recover
	// every session's traffic — past, present, and future.
	//
	// Production code MUST leave this nil. The only legitimate use is
	// byte-exact transcript tests against external implementations
	// (e.g. Samsung OpenSCP) where the published wire bytes are
	// computed from a known fixed ephemeral key. The field is named
	// "InsecureTestOnlyEphemeralKey" so that callers must explicitly
	// type "Insecure" and "TestOnly" to use it; the same prefix
	// convention is used by InsecureSkipCardAuthentication above.
	//
	// Must be a P-256 ECDH private key (curve enforced at Open time).
	InsecureTestOnlyEphemeralKey *ecdh.PrivateKey

	// InsecureAllowSCP11bWithoutReceipt permits SCP11b sessions where
	// the card's INTERNAL AUTHENTICATE response omits tag 0x86
	// (the receipt). By default, the library requires a receipt for
	// ALL SCP11 variants — matching Yubico's yubikit reference
	// implementation, which unconditionally extracts and verifies
	// tag 0x86 across SCP11a/b/c, and matching GP Amendment F v1.4,
	// which specifies receipts for all variants.
	//
	// Earlier Amendment F revisions did not require a receipt for
	// SCP11b. Accepting a missing receipt against a modern card is
	// both a security regression (the MAC chain seeds from zero
	// rather than from a verified key-confirmation value) and an
	// interop break with current YubiKey behavior. Default-fail-closed
	// is the right posture; this flag exists only for the narrow case
	// of older SCP11b cards that genuinely omit the receipt.
	//
	// Has no effect on SCP11a or SCP11c — those always require a
	// receipt because mutual authentication depends on it.
	InsecureAllowSCP11bWithoutReceipt bool

	// EmptyDataEncryption controls how the C-DECRYPT step handles a
	// command APDU with no data field. Default is
	// channel.EmptyDataYubico (pad-and-encrypt) which matches Yubico
	// yubikit and works against YubiKey 5.x. Set to
	// channel.EmptyDataGPLiteral for cards that strictly implement
	// the GP Amendment D §6.2.4 reading (skip encryption when data
	// is empty). See scp03.Config for fuller context.
	EmptyDataEncryption channel.EmptyDataPolicy
}

// Common AIDs.
var (
	// AIDSecurityDomain is the GlobalPlatform Issuer Security Domain.
	// This is where SCP11 keys and certificates are managed.
	AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

	// AIDPIV is the PIV applet AID (NIST SP 800-73).
	AIDPIV = []byte{0xA0, 0x00, 0x00, 0x03, 0x08}

	// AIDOATH is the OATH applet AID.
	AIDOATH = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}

	// AIDOTP is the YubiKey OTP applet AID.
	AIDOTP = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}
)

// YubiKeyDefaultSCP11bConfig returns a starting Config for SCP11b
// (one-way card-to-host authentication) tuned for YubiKey defaults:
// SD applet, KID 0x13, KVN 0x01, full security level, and the
// YubiKey-compatible empty-data encryption policy
// (channel.EmptyDataYubico, the zero value). The caller still has to
// configure card-trust validation: set CardTrustPolicy or
// CardTrustAnchors, or InsecureSkipCardAuthentication for tests.
//
// For spec-literal defaults that don't bake in YubiKey assumptions,
// see StrictGPSCP11bConfig.
func YubiKeyDefaultSCP11bConfig() *Config {
	return &Config{
		Variant:       SCP11b,
		SelectAID:     AIDSecurityDomain,
		KeyID:         0x13, // GP §7.1.1 SCP11b
		KeyVersion:    0x01,
		SecurityLevel: channel.LevelFull,
	}
}

// YubiKeyDefaultSCP11aConfig returns a starting Config for SCP11a
// (mutual authentication via OCE certificate chain), tuned for
// YubiKey. KeyID is set to the GP Amendment F §7.1.1 SCP11a slot
// (0x11). The caller must still populate OCECertificates,
// OCEPrivateKey, OCEKeyReference, and a card-trust configuration
// (CardTrustPolicy / CardTrustAnchors / InsecureSkipCardAuthentication)
// before calling Open.
//
// For spec-literal defaults, see StrictGPSCP11aConfig.
func YubiKeyDefaultSCP11aConfig() *Config {
	cfg := YubiKeyDefaultSCP11bConfig()
	cfg.Variant = SCP11a
	cfg.KeyID = 0x11 // GP §7.1.1 SCP11a
	return cfg
}

// YubiKeyDefaultSCP11cConfig returns a starting Config for SCP11c
// (mutual authentication with offline scripting), tuned for YubiKey.
// KeyID is set to the GP Amendment F §7.1.1 SCP11c slot (0x15).
// Same OCE/trust caveats as YubiKeyDefaultSCP11aConfig.
//
// For spec-literal defaults, see StrictGPSCP11cConfig.
func YubiKeyDefaultSCP11cConfig() *Config {
	cfg := YubiKeyDefaultSCP11bConfig()
	cfg.Variant = SCP11c
	cfg.KeyID = 0x15 // GP §7.1.1 SCP11c
	return cfg
}

// StrictGPSCP11bConfig returns an SCP11b Config with spec-literal
// defaults — no YubiKey-specific tinting. It explicitly sets
// EmptyDataEncryption to channel.EmptyDataGPLiteral, which matches
// the literal reading of GP Amendment D §6.2.4 (skip C-DEC encryption
// when data is empty). KeyVersion is left at zero ("any version"),
// since the GP-spec default does not pin a specific KVN.
//
// Use this against cards that strictly implement the GP spec rather
// than the YubiKey-compatible interpretation. Trust configuration
// requirements are the same as the YubiKey-default variant.
func StrictGPSCP11bConfig() *Config {
	return &Config{
		Variant:             SCP11b,
		SelectAID:           AIDSecurityDomain,
		KeyID:               0x13, // GP §7.1.1 SCP11b
		KeyVersion:          0x00, // GP-spec "any version"
		SecurityLevel:       channel.LevelFull,
		EmptyDataEncryption: channel.EmptyDataGPLiteral,
	}
}

// StrictGPSCP11aConfig returns an SCP11a Config with spec-literal
// defaults. See StrictGPSCP11bConfig for the rationale.
func StrictGPSCP11aConfig() *Config {
	cfg := StrictGPSCP11bConfig()
	cfg.Variant = SCP11a
	cfg.KeyID = 0x11 // GP §7.1.1 SCP11a
	return cfg
}

// StrictGPSCP11cConfig returns an SCP11c Config with spec-literal
// defaults. See StrictGPSCP11bConfig for the rationale.
func StrictGPSCP11cConfig() *Config {
	cfg := StrictGPSCP11bConfig()
	cfg.Variant = SCP11c
	cfg.KeyID = 0x15 // GP §7.1.1 SCP11c
	return cfg
}

// Session manages an SCP11 secure channel over a Transport.
//
// A Session is NOT safe for concurrent use. The secure channel state
// — the encryption counter and MAC chaining value — is mutated on
// every Transmit. Concurrent calls would race the counter and produce
// APDUs the card rejects, and would race the MAC chain producing
// observable corruption.
//
// If multiple goroutines need to send commands, serialize them
// externally (e.g. with a sync.Mutex around the Session, or by funneling
// commands through a single goroutine). For separate logical contexts,
// open separate Sessions.
type Session struct {
	config    *Config
	transport transport.Transport
	channel   *channel.SecureChannel
	state     State

	// Cryptographic state
	oceEphemeralKey  *ecdh.PrivateKey
	cardStaticPubKey *ecdh.PublicKey
	sessionKeys      *kdf.SessionKeys
}

// Open establishes an SCP11 secure channel over the given Transport.
// It performs the complete handshake: SELECT, GET DATA, key agreement,
// and session key derivation.
func Open(ctx context.Context, t transport.Transport, cfg *Config) (*Session, error) {
	if t == nil {
		return nil, fmt.Errorf("%w: transport is required", ErrInvalidConfig)
	}
	if cfg == nil {
		return nil, fmt.Errorf("%w: Config is required (use YubiKeyDefaultSCP11bConfig() or StrictGPSCP11bConfig() as a starting point)", ErrInvalidConfig)
	}
	// Shallow copy so we don't mutate the caller's Config. The fields
	// we override below (SecurityLevel) are scalars; the slice and
	// pointer fields we read are not mutated. Earlier versions modified
	// cfg in place, which surprised callers reusing a shared config
	// across sessions or applets.
	local := *cfg
	cfg = &local
	if cfg.SecurityLevel == 0 {
		cfg.SecurityLevel = channel.LevelFull
	}

	// Validate Variant. Variant is an int enum; if a caller built the
	// Config from JSON/YAML or passed a stale numeric value, an
	// unrecognized variant would silently default into SCP11b-like
	// behavior (params=0, INS=0x88) instead of failing closed. For
	// mutual-auth code, that is the wrong failure mode.
	switch cfg.Variant {
	case SCP11a, SCP11b, SCP11c:
		// ok
	default:
		return nil, fmt.Errorf("%w: unsupported SCP11 variant: %d (valid: SCP11a=0, SCP11b=1, SCP11c=2)", ErrInvalidConfig, cfg.Variant)
	}

	// Validate that the configured SecurityLevel is consistent with the
	// key usage qualifier (0x3C = full security) sent in INTERNAL/MUTUAL
	// AUTHENTICATE. The card enforces the negotiated level, so a mismatch
	// causes the host wrapper to diverge from what the card expects.
	if cfg.SecurityLevel != channel.LevelFull {
		return nil, fmt.Errorf("%w: SCP11 currently only supports full security level (C-MAC|C-DEC|R-MAC|R-ENC); "+
			"the key usage qualifier 0x3C negotiated with the card requires it", ErrInvalidConfig)
	}

	// HostID and CardGroupID are partially implemented: the KDF
	// appends them to SharedInfo, but AUTHENTICATE doesn't set the
	// SCP11 parameter bit nor include tag 0x84. Opening with these
	// set would silently derive different keys than the card. Fail
	// closed until the wire side is implemented.
	if len(cfg.HostID) > 0 || len(cfg.CardGroupID) > 0 {
		return nil, fmt.Errorf("%w: SCP11 HostID/CardGroupID identifiers are not fully implemented (KDF inclusion is wired but the AUTHENTICATE parameter bit and tag 0x84 are not); leave both nil", ErrInvalidConfig)
	}

	// Trust-posture guard. Caller must declare one of:
	//   - CardTrustPolicy: chain validation runs in legacyExtractAndStoreKey.
	//   - CardTrustAnchors: chain validation runs in extractCardPublicKey.
	//   - InsecureSkipCardAuthentication: explicit lab-mode opt-out.
	//
	// When PreverifiedCardStaticPublicKey is supplied the cert-fetch
	// path never runs, so the lazy guard inside legacyExtractAndStoreKey
	// would never fire. Check here so the same posture requirement
	// applies regardless of which discovery path the caller took.
	if cfg.CardTrustAnchors == nil &&
		cfg.CardTrustPolicy == nil &&
		!cfg.InsecureSkipCardAuthentication {
		return nil, fmt.Errorf(
			"%w: SCP11 requires an explicit trust posture: set CardTrustPolicy "+
				"or CardTrustAnchors for production, or InsecureSkipCardAuthentication "+
				"for lab use",
			ErrInvalidConfig,
		)
	}

	// Reject the trust-posture/preverified-key combination. When
	// PreverifiedCardStaticPublicKey is set the in-library chain-
	// validation path (GET DATA BF21 → trust.ValidateSCP11Chain) is
	// skipped entirely — there is no chain available for
	// CardTrustPolicy or CardTrustAnchors to validate against. A
	// caller setting both fields is most likely confused about
	// which path applies, expecting the policy to validate the
	// pre-supplied key (it can't — Policy validates a cert chain,
	// not a bare pubkey). Fail closed with a clear message rather
	// than silently bypassing the policy. Callers that have
	// validated upstream (e.g. via securitydomain.FetchCardPublicKey
	// applying their CardTrustPolicy to the SD's cert chain before
	// extracting the leaf pubkey) should set InsecureSkipCard-
	// Authentication=true on this second Open as the trust-posture
	// marker — the "Insecure" in the name is loud on purpose, since
	// the in-library validation is being deliberately bypassed.
	if cfg.PreverifiedCardStaticPublicKey != nil &&
		(cfg.CardTrustPolicy != nil || cfg.CardTrustAnchors != nil) {
		return nil, fmt.Errorf(
			"%w: PreverifiedCardStaticPublicKey is incompatible with "+
				"CardTrustPolicy or CardTrustAnchors — Policy validates a cert "+
				"chain, but the preverified path skips the cert fetch. Either "+
				"drop PreverifiedCardStaticPublicKey to use library chain "+
				"validation, or keep it and set InsecureSkipCardAuthentication=true "+
				"as the posture marker (validation already happened out-of-band)",
			ErrInvalidConfig,
		)
	}

	s := &Session{
		config:    cfg,
		transport: t,
		state:     StateNew,
	}

	// Step 1: SELECT the target applet (whose SCP key set we'll
	// authenticate against). Skipped if SelectAID is nil.
	if err := s.selectApplet(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("select applet: %w", err)
	}

	// Step 2: Retrieve the card's certificate and extract PK.SD.ECKA.
	// If the caller pre-supplied the public key (typical for SCP11b-on-
	// PIV, where PK.SD.ECKA must come from the Security Domain rather
	// than the target applet), skip the GET DATA BF21 round-trip.
	if cfg.PreverifiedCardStaticPublicKey != nil {
		s.cardStaticPubKey = cfg.PreverifiedCardStaticPublicKey
		s.state = StateCertRetrieved
	} else if err := s.getCardCertificate(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("get card cert: %w", err)
	}

	// Step 3 (SCP11a/c): Send OCE certificate chain via PERFORM SECURITY
	// OPERATION. Both SCP11a and SCP11c are mutual-auth variants that
	// require the OCE certificate(s) to be provided to the card before
	// MUTUAL AUTHENTICATE.
	if cfg.Variant == SCP11a || cfg.Variant == SCP11c {
		if cfg.OCEPrivateKey == nil {
			return nil, fmt.Errorf("%w: OCE private key required for SCP11a/c (mutual-auth variants)", ErrInvalidConfig)
		}
		if len(cfg.OCECertificates) == 0 {
			return nil, fmt.Errorf("%w: OCE certificate chain required for SCP11a/c (mutual-auth variants); set Config.OCECertificates to a non-empty slice in leaf-last order", ErrInvalidConfig)
		}
		// OCEKeyReference is sent on the wire as P1=KVN, P2=KID|chain-bit
		// in every PSO certificate-upload APDU (GP §7.5.2). The zero
		// value (KID=0, KVN=0) is not a meaningful card key reference;
		// silently sending PSO with P1=0 P2=0 produces opaque card
		// rejections during provisioning. Reject up front instead.
		if cfg.OCEKeyReference == (KeyRef{}) {
			return nil, fmt.Errorf("%w: OCEKeyReference required for SCP11a/c (mutual-auth variants); set Config.OCEKeyReference.KID and KVN to the card's OCE key slot (KID 0x10 is the YubiKey default)", ErrInvalidConfig)
		}
		// Defense-in-depth: ensure the configured private key actually
		// corresponds to the LEAF certificate (last entry) — that's the
		// cert the card uses to verify the OCE's signature. A mismatch
		// would either cause MUTUAL AUTHENTICATE to fail (best case) or,
		// worse, succeed against a permissive card while the host
		// believes it is presenting one identity but holds another.
		leaf := cfg.OCECertificates[len(cfg.OCECertificates)-1]
		if err := verifyOCEKeyMatchesCert(cfg.OCEPrivateKey, leaf); err != nil {
			return nil, fmt.Errorf("OCE key/leaf-certificate mismatch: %w", err)
		}
		if err := s.sendOCECertificate(ctx); err != nil {
			s.state = StateFailed
			return nil, fmt.Errorf("send OCE cert chain: %w", err)
		}
	}

	// Step 4: Perform key agreement via INTERNAL AUTHENTICATE.
	if err := s.performKeyAgreement(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("key agreement: %w", err)
	}

	// Step 5: Create the secure channel wrapper.
	s.channel = channel.New(s.sessionKeys, cfg.SecurityLevel)
	s.channel.EmptyDataEncryption = cfg.EmptyDataEncryption
	s.state = StateAuthenticated

	// Step 6: If the caller explicitly set ApplicationAID, SELECT the
	// applet through the secure channel. This is opt-in: the default
	// config leaves ApplicationAID nil because some platforms — notably
	// YubiKey — scope the SCP session to the currently selected applet
	// and selecting a different one terminates the session. The
	// supported pattern there is to SELECT the target applet first and
	// then call Open against that applet.
	if len(cfg.ApplicationAID) > 0 {
		if err := s.selectApplication(ctx); err != nil {
			s.state = StateFailed
			return nil, fmt.Errorf("select application: %w", err)
		}
	}

	return s, nil
}

// Transmit sends a command through the secure channel.
// GP SCP11 §4.8: After the secure channel is established, all commands
// MUST be sent through the channel. Plaintext commands would desynchronize
// the MAC chain and be rejected by the card. This method enforces that
// invariant — there is no way to send an unwrapped command through a Session.
func (s *Session) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.state != StateAuthenticated {
		return nil, errors.New("secure channel not established")
	}

	// Wrap the command with secure messaging.
	wrapped, err := s.channel.Wrap(cmd)
	if err != nil {
		return nil, fmt.Errorf("wrap command: %w", err)
	}

	// Transport-layer chaining. transport.TransmitWithChaining splits
	// wrapped.Data into ISO 7816-4 §5.1.1 chunks if it exceeds the
	// short-Lc bound, sends each, and returns only the final chunk's
	// response. Intermediate chunks return bare 9000 with no R-MAC;
	// that's correct because the SCP wrap (and its MAC chain advance)
	// happened ONCE above for the whole logical command. SCP03's
	// Transmit uses the same pattern; SCP11 needs it for symmetric
	// behavior on wrapped commands that exceed 255 bytes (cert
	// installs, large object writes, anything that pads or grows
	// past short-Lc once secure messaging is added).
	resp, err := transport.TransmitWithChaining(ctx, s.transport, wrapped)
	if err != nil {
		return nil, fmt.Errorf("transmit: %w", err)
	}

	// GP SCP03 §6.2.4 (applied to SCP11 by Amendment F): R-MAC and
	// R-ENC are applied only to responses with SW 9000 or warning SW1
	// 62/63. Card-side error status words (6Axx, 6Bxx, ...) are
	// returned unprotected and must pass through without R-MAC
	// verification — otherwise legitimate card errors look like MAC
	// failures and the session is needlessly torn down.
	if !channel.ResponseIsSecureMessagingProtected(resp.SW1, resp.SW2) {
		return resp, nil
	}

	// Unwrap the response.
	unwrapped, err := s.channel.Unwrap(resp)
	if err != nil {
		// GP §4.8: A MAC verification failure indicates a compromised
		// channel. The session MUST be terminated immediately and all
		// key material zeroed to prevent oracle attacks.
		s.Close()
		return nil, fmt.Errorf("unwrap response (session terminated): %w", err)
	}

	return unwrapped, nil
}

// Close ends the secure session and zeros all key material.
// The underlying transport is not closed; the caller manages that lifecycle.
func (s *Session) Close() {
	s.state = StateFailed
	if s.sessionKeys != nil {
		secmem.Zero(s.sessionKeys.SENC)
		secmem.Zero(s.sessionKeys.SMAC)
		secmem.Zero(s.sessionKeys.SRMAC)
		secmem.Zero(s.sessionKeys.DEK)
		secmem.Zero(s.sessionKeys.Receipt)
		secmem.Zero(s.sessionKeys.MACChain)
		s.sessionKeys = nil
	}
	s.channel = nil
}

// InsecureExportSessionKeysForTestOnly returns a defensive copy of
// the session's live cryptographic keys (S-ENC, S-MAC, S-RMAC, DEK,
// receipt key, MAC chain). It exists for two narrow uses: round-
// tripping byte-exact transcript tests against external reference
// implementations, and audit tooling that diffs derived material
// against a known-answer vector.
//
// Production callers MUST NOT call this. The returned material lets
// anyone who sees the bytes decrypt every wrapped command/response
// in this session, forge MACs against the card, and recover any key
// material wrapped under DEK. Logging it (even at debug level) means
// permanent compromise of every command in that session.
//
// The deliberately ugly name exists so this function is impossible
// to call by accident and obvious in code review.
func (s *Session) InsecureExportSessionKeysForTestOnly() *kdf.SessionKeys {
	return s.sessionKeys.Clone()
}

// SessionDEK returns a defensive copy of the Data Encryption Key
// derived during the SCP11 handshake.
//
// Returns nil if the session is closed or did not derive a DEK.
//
// This is a concrete method on *scp11.Session, not part of the
// scp.Session interface. The securitydomain package consumes it
// through an unexported capability interface, so a caller holding
// a generic scp.Session value cannot reach the DEK. Direct callers
// who genuinely need the DEK (a custom PUT KEY-equivalent flow,
// for example) can type-assert on this concrete type and must
// zero the returned slice when done.
func (s *Session) SessionDEK() []byte {
	if s.sessionKeys == nil || len(s.sessionKeys.DEK) == 0 {
		return nil
	}
	out := make([]byte, len(s.sessionKeys.DEK))
	copy(out, s.sessionKeys.DEK)
	return out
}

// OCEAuthenticated reports whether this SCP11 session authenticates
// the Off-Card Entity (host) to the card.
//
//   - SCP11a, SCP11c: yes. The OCE proves possession of its private
//     key during the variant's mutual-authentication phase, so the
//     card knows it is talking to an authorized administrator.
//   - SCP11b: no. The card authenticates to the host (the host learns
//     it is talking to a trusted card), but the host does not prove
//     identity to the card. SCP11b is appropriate for read-only or
//     diagnostic flows; OCE-gated management operations require
//     SCP11a/c (or SCP03).
//
// This is a concrete method, not part of the scp.Session interface.
// The securitydomain package consumes it through an unexported
// capability interface to gate management operations without
// pattern-matching on Protocol() string values.
func (s *Session) OCEAuthenticated() bool {
	if s.sessionKeys == nil {
		return false // closed session
	}
	switch s.config.Variant {
	case SCP11a, SCP11c:
		return true
	case SCP11b:
		return false
	default:
		return false
	}
}

// Protocol returns the protocol variant string (e.g. "SCP11b").
func (s *Session) Protocol() string {
	switch s.config.Variant {
	case SCP11a:
		return "SCP11a"
	case SCP11b:
		return "SCP11b"
	case SCP11c:
		return "SCP11c"
	default:
		return "SCP11"
	}
}

// --- Protocol Steps ---

func (s *Session) selectApplet(ctx context.Context) error {
	// If SelectAID is nil, the caller has already SELECTed the
	// target applet (e.g. through a test harness) and we just
	// proceed with the handshake.
	if len(s.config.SelectAID) == 0 {
		s.state = StateSelected
		return nil
	}
	// SELECT the target applet — UNENCRYPTED since we don't yet
	// have a secure channel. That applet's SCP key set is what the
	// handshake will authenticate against.
	cmd := apdu.NewSelect(s.config.SelectAID)
	resp, err := s.transport.Transmit(ctx, cmd)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return resp.Error()
	}
	s.state = StateSelected
	return nil
}

func (s *Session) selectApplication(ctx context.Context) error {
	// SELECT the target application THROUGH the secure channel.
	// This SELECT is encrypted and MACed like any other command.
	cmd := apdu.NewSelect(s.config.ApplicationAID)
	resp, err := s.Transmit(ctx, cmd)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return resp.Error()
	}
	return nil
}

func (s *Session) getCardCertificate(ctx context.Context) error {
	// Build the GET DATA command for the certificate store.
	// Tag 0xBF21 with the key reference as sub-TLV.
	keyRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyID, []byte{s.config.KeyID, s.config.KeyVersion}),
	)

	certStoreTag := uint16(tlv.TagCertStore)
	cmd := &apdu.Command{
		// CLA 0x00 = ISO interindustry GET DATA. This matches Yubico's
		// own SecurityDomainSession.java (which uses class 0 for
		// INS_GET_DATA), Samsung's reference SCP11 transcripts, and
		// the GP Card Spec ISO mode for pre-secure-channel commands.
		// Earlier this code sent 0x80 (GP proprietary), which worked
		// against this library's own mock card but diverged from real
		// implementations — including our own reference vector test
		// at TestGetDataAPDUConstruction.
		CLA:  0x00,
		INS:  0xCA, // GET DATA
		P1:   byte(certStoreTag >> 8),
		P2:   byte(certStoreTag),
		Data: keyRef.Encode(),
		Le:   0,
	}

	resp, err := transport.TransmitCollectAll(ctx, s.transport, cmd)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return resp.Error()
	}

	// If a full trust policy is configured, use the trust package
	// for rigorous chain validation before extracting the key.
	if s.config.CardTrustPolicy != nil {
		return s.validateCardCertChain(resp.Data)
	}

	return s.legacyExtractAndStoreKey(resp.Data)
}

// legacyExtractAndStoreKey is the pre-trust-policy code path: it parses
// the card certificate (or, with a configured trust pool, validates the
// chain) and stores the static public key for ECDH. It must fail closed
// when neither CardTrustAnchors nor InsecureSkipCardAuthentication are
// set — otherwise SCP11b reduces to opportunistic encryption against any
// responder, which is not authentication.
func (s *Session) legacyExtractAndStoreKey(data []byte) error {
	if s.config.CardTrustAnchors == nil && !s.config.InsecureSkipCardAuthentication {
		return fmt.Errorf("%w: SCP11 card certificate validation is required; configure CardTrustPolicy/CardTrustAnchors or set InsecureSkipCardAuthentication for tests", ErrInvalidConfig)
	}
	pubKey, err := extractCardPublicKey(data, s.config.CardTrustAnchors)
	if err != nil {
		return fmt.Errorf("extract card public key: %w", err)
	}

	s.cardStaticPubKey = pubKey
	s.state = StateCertRetrieved
	return nil
}

// validateCardCertChain handles the trust-policy path when
// CardTrustPolicy is configured. Two routes:
//
//   - Policy.CustomValidator set: hand the raw BF21 store bytes to
//     the caller's validator and use whatever public key it returns.
//     The library does no parsing, no chain checks, no EKU/serial/SKI
//     filtering — the validator owns the trust decision in full.
//     This is the path GP-proprietary cards take.
//
//   - Otherwise: parse as X.509, run ValidateSCP11Chain (P-256, chain,
//     EKU, serials, SKI, time), use the validated leaf's public key.
func (s *Session) validateCardCertChain(data []byte) error {
	if s.config.CardTrustPolicy.CustomValidator != nil {
		result, err := s.config.CardTrustPolicy.CustomValidator(data)
		if err != nil {
			return fmt.Errorf("custom card validator: %w", err)
		}
		if result == nil || result.PublicKey == nil {
			return fmt.Errorf("%w: custom card validator returned nil PublicKey", ErrTrustValidation)
		}
		// CustomValidator owns the trust decision in full, but two
		// invariants are non-negotiable for SCP11 to function at all:
		// (a) the key must be on a curve we can do ECDH on, and (b)
		// SCP11 mandates P-256. Enforce them after the validator
		// returns so a buggy or overly-permissive custom path can't
		// hand back a key the rest of the protocol can't use.
		if result.PublicKey.Curve == nil || result.PublicKey.Curve.Params().Name != "P-256" {
			return fmt.Errorf("%w: custom card validator returned non-P-256 key (curve %v); SCP11 requires P-256", ErrTrustValidation, result.PublicKey.Curve)
		}
		ecdhKey, err := result.PublicKey.ECDH()
		if err != nil {
			return fmt.Errorf("convert custom-validated key to ECDH: %w", err)
		}
		s.cardStaticPubKey = ecdhKey
		s.state = StateCertRetrieved
		return nil
	}

	certs, err := parseCertsFromStore(data)
	if err != nil {
		return fmt.Errorf("parse card certificates: %w", err)
	}
	if len(certs) == 0 {
		return fmt.Errorf("%w: no certificates in card response", ErrTrustValidation)
	}

	// Trust validation with try-each fallback.
	//
	// trust.ValidateSCP11Chain assumes leaf-last ordering (Yubico
	// convention). Cards or non-Yubico tooling may emit leaf-first
	// or otherwise unordered bundles; refusing those breaks legit
	// X.509 chains generated by generic tooling. The legacy
	// extractCardPublicKey path already does try-each; this brings
	// the trust-policy path in line.
	//
	// Strategy: try leaf-last (fast path); on failure with a multi-
	// cert bundle, iterate each cert as the candidate leaf and the
	// rest as intermediates. First ordering that validates wins.
	result, firstErr := trust.ValidateSCP11Chain(certs, *s.config.CardTrustPolicy)
	if firstErr != nil && len(certs) > 1 {
		for i := range certs {
			if i == len(certs)-1 {
				continue // already tried as the fast path
			}
			reordered := make([]*x509.Certificate, 0, len(certs))
			for j, c := range certs {
				if j != i {
					reordered = append(reordered, c)
				}
			}
			reordered = append(reordered, certs[i])
			if r, err := trust.ValidateSCP11Chain(reordered, *s.config.CardTrustPolicy); err == nil {
				result = r
				firstErr = nil
				break
			}
		}
	}
	if firstErr != nil {
		return fmt.Errorf("%w: card certificate chain validation: %w", ErrTrustValidation, firstErr)
	}

	// Convert the validated ECDSA key to ECDH for key agreement.
	ecdhKey, err := result.PublicKey.ECDH()
	if err != nil {
		return fmt.Errorf("convert validated key to ECDH: %w", err)
	}

	s.cardStaticPubKey = ecdhKey
	s.state = StateCertRetrieved
	return nil
}

// sendOCECertificate uploads the OCE certificate chain to the card
// via PERFORM SECURITY OPERATION (GP §7.5.2).
//
// Wire layout follows Yubico's reference implementation, which itself
// matches the spec:
//
//   - Each certificate in the chain is a SEPARATE PSO operation, sent
//     in leaf-LAST order.
//   - P1 = OCEKeyReference.KVN.
//   - P2 = OCEKeyReference.KID, with bit 0x80 set for non-final certs
//     (i.e. all but the LEAF cert) and cleared for the final cert.
//     This is the "P2 chain bit" from GP §7.5 §7.10 — it tells the
//     card whether THIS cert is the terminus or whether more certs
//     are coming after it.
//
//   - Each individual cert is sent as ONE OR MORE short APDUs using
//     ISO 7816-4 §5.1.1 command chaining: bit b5 of CLA (= 0x10) is
//     set on every chunk except the LAST chunk of that cert. Each
//     chunk carries up to 255 bytes of cert data. CLA = 0x80 base;
//     chained chunks therefore use CLA = 0x90 and the final chunk
//     uses CLA = 0x80.
//
// Earlier versions of this loop used ISO 7816-4 extended-length
// APDU encoding (3-byte Lc, single APDU per cert) when a cert
// exceeded 255 bytes. That sends a syntactically valid APDU but
// retail YubiKey 5.7.4 rejects PSO with SW=6A80 ("incorrect
// parameters in command data field") when the cert arrives in an
// extended-length wrapper. The card expects ISO command chaining
// even though it accepts extended-length encoding for OTHER
// commands. yubikit-python's SmartCardProtocol.send_apdu auto-
// promotes to ISO chaining for data > 255 bytes; mirroring that
// here closes the SW=6A80 path on retail hardware.
//
// Trust anchors are NOT sent. The OCE CA is installed on the card
// out-of-band (PUT KEY at the OCE CA reference, with the CA's SKI
// registered via STORE CA-IDENTIFIER) before SCP11a is opened. PSO
// uploads only the path BELOW the trust anchor — typically just
// the leaf, sometimes leaf+intermediates, but never the trust
// anchor itself. Re-uploading the trust anchor is what the card
// rejects with SW=6A80; it already has that cert and treats the
// duplicate as a malformed path. To make the API forgiving —
// callers commonly pass the same PEM file used during bootstrap
// (which DOES include the CA at chain[0]) — sendOCECertificate
// strips self-signed certs from the start of the chain before
// transmission.
func (s *Session) sendOCECertificate(ctx context.Context) error {
	if len(s.config.OCECertificates) == 0 {
		return fmt.Errorf("%w: OCE certificate chain required for SCP11a/c (mutual-auth variants)", ErrInvalidConfig)
	}

	// Filter out any self-signed certs at the start of the chain.
	// These are trust anchors and must not be re-uploaded — the
	// card already has the OCE CA installed at the OCE CA key
	// reference. See doc comment above for the SW=6A80 backstory.
	chain := stripLeadingTrustAnchors(s.config.OCECertificates)
	if len(chain) == 0 {
		return fmt.Errorf("%w: OCE certificate chain consists entirely of self-signed certs; "+
			"PSO uploads the path BELOW the trust anchor, so the chain "+
			"must contain at least one non-self-signed cert (the leaf)", ErrInvalidConfig)
	}
	lastIdx := len(chain) - 1

	for i, cert := range chain {
		// P2 chain bit: set on every cert EXCEPT the last (leaf).
		// Per yubikit scp.py: p2 = oce_ref.kid | (0x80 if i < n else 0).
		p2 := s.config.OCEKeyReference.KID
		if i < lastIdx {
			p2 |= 0x80
		}
		if err := s.psoSendCertChained(ctx, cert.Raw, p2, i+1, len(chain)); err != nil {
			return err
		}
	}
	return nil
}

// psoSendCertChained sends a single OCE certificate's DER bytes via
// PERFORM SECURITY OPERATION, using ISO 7816-4 §5.1.1 command
// chaining when the cert exceeds 255 bytes (most real OCE certs do).
//
// CLA scheme:
//
//   - Base CLA = 0x80 (GP proprietary class for SCP commands).
//   - Bit b5 (= 0x10) is the chaining indicator. Set on every chunk
//     except the LAST chunk of this cert. So intermediate chunks
//     carry CLA = 0x90 and the final chunk carries CLA = 0x80.
//
// Each chunk reuses the same INS/P1/P2; the cert is split at
// pscChunkSize (=255 bytes) boundaries with no additional framing.
//
// p2 already has the P2 chain bit (0x80) baked in by the caller —
// that bit signals "more CERTS coming", a different concept from
// CLA's "more CHUNKS coming for this cert".
//
// certIdx and certCount are 1-based and used only for error
// messages so a multi-cert chain failure tells the operator which
// cert in the chain failed.
func (s *Session) psoSendCertChained(ctx context.Context, certDER []byte, p2 byte, certIdx, certCount int) error {
	const pscChunkSize = 255
	total := len(certDER)
	for offset := 0; offset < total || total == 0; {
		end := offset + pscChunkSize
		if end > total {
			end = total
		}
		isLastChunk := end == total
		cla := byte(0x80)
		if !isLastChunk {
			cla = 0x90 // 0x80 | 0x10 (ISO command chaining)
		}
		cmd := &apdu.Command{
			CLA:  cla,
			INS:  0x2A, // PERFORM SECURITY OPERATION
			P1:   s.config.OCEKeyReference.KVN,
			P2:   p2,
			Data: certDER[offset:end],
			Le:   -1, // No response data on intermediate chunks; final chunk also returns no data on PSO.
		}
		resp, err := s.transport.Transmit(ctx, cmd)
		if err != nil {
			return fmt.Errorf("PSO cert %d/%d: %w", certIdx, certCount, err)
		}
		if !resp.IsSuccess() {
			return fmt.Errorf("PSO cert %d/%d: %w", certIdx, certCount, resp.Error())
		}
		offset = end
		if total == 0 {
			break // empty cert (degenerate); send one APDU and stop.
		}
	}
	return nil
}

func (s *Session) performKeyAgreement(ctx context.Context) error {
	// Generate or accept the OCE ephemeral ECDH key pair (P-256).
	// In production, InsecureTestOnlyEphemeralKey is nil and we
	// generate fresh randomness. Test transcripts inject a known
	// fixed key to make wire bytes deterministic for byte-exact
	// known-answer comparison.
	var ephKey *ecdh.PrivateKey
	if s.config.InsecureTestOnlyEphemeralKey != nil {
		// Validate the injected key is on P-256 — anything else
		// will produce a malformed EPK.OCE that the card rejects
		// after the host has already sent it on the wire.
		// Better to fail before APDU construction.
		if s.config.InsecureTestOnlyEphemeralKey.Curve() != ecdh.P256() {
			return fmt.Errorf("%w: InsecureTestOnlyEphemeralKey must be a P-256 ECDH private key (this implementation supports P-256 only)", ErrInvalidConfig)
		}
		ephKey = s.config.InsecureTestOnlyEphemeralKey
	} else {
		var err error
		ephKey, err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate ephemeral key: %w", err)
		}
	}
	s.oceEphemeralKey = ephKey

	// Build the INTERNAL AUTHENTICATE / MUTUAL AUTHENTICATE command.
	//
	// Data field per GP SCP11 §7.6.2.3:
	//   A6 { 90{KID, params}, 95{3C}, 80{88}, 81{10} }
	//   5F49 { ePK.OCE uncompressed point }
	//
	// GP §7.6.2.3 / §7.7.2.3: key params in A6 control reference template.
	// The TagKeyInfo TLV (0x90) carries [0x11, params_byte], where:
	//   - 0x11 is a fixed protocol/family identifier in this position
	//     (NOT the card's SCP key reference KID — that is sent in
	//     APDU P2 below). The Yubico yubikit reference implementation
	//     hardcodes 0x11 here for ALL SCP11 variants:
	//       Tlv(0x90, bytes([0x11, params]))
	//     and we match that for cross-implementation interop.
	//   - params encodes the variant per GPC v2.3 Amendment F §7.1.1:
	//     SCP11a=0x01, SCP11b=0x00, SCP11c=0x03.
	//
	// History note: an intermediate version of this code put
	// cfg.KeyID in this byte under the (incorrect) assumption that
	// the byte was the card's key reference. That happened to "work"
	// against any card whose SCP key set is at KID 0x11 (Samsung's
	// reference SCP11a vectors, lab cards) but would have produced
	// the wrong wire bytes against a YubiKey running SCP11b at KID
	// 0x13. The byte is now hardcoded back to 0x11 to match yubikit
	// and the byte-exact Samsung transcript (which is also 0x11).
	var params byte
	switch s.config.Variant {
	case SCP11a:
		params = 0x01
	case SCP11b:
		params = 0x00
	case SCP11c:
		params = 0x03
	}

	controlRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyInfo, []byte{0x11, params}),
		tlv.Build(tlv.TagKeyUsage, []byte{kdf.KeyUsage}),
		tlv.Build(tlv.TagKeyType, []byte{kdf.KeyTypeAES}),
		tlv.Build(tlv.TagKeyLength, []byte{kdf.SessionKeyLen}),
	)

	ephPubBytes := ephKey.PublicKey().Bytes()
	ephPubTLV := tlv.Build(tlv.TagEphPubKey, ephPubBytes)

	var data []byte
	data = append(data, controlRef.Encode()...)
	data = append(data, ephPubTLV.Encode()...)

	ins := byte(0x88) // INTERNAL AUTHENTICATE
	if s.config.Variant == SCP11a || s.config.Variant == SCP11c {
		ins = 0x82 // MUTUAL AUTHENTICATE (requires prior OCE cert for SCP11a)
	}

	cmd := &apdu.Command{
		CLA:  0x80,
		INS:  ins,
		P1:   s.config.KeyVersion,
		P2:   s.config.KeyID,
		Data: data,
		Le:   0,
	}

	resp, err := s.transport.Transmit(ctx, cmd)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return resp.Error()
	}

	// Parse the response: card's ephemeral public key + optional receipt.
	cardEphPubBytes, receipt, err := parseKeyAgreementResponse(resp.Data)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	cardEphPub, err := ecdh.P256().NewPublicKey(cardEphPubBytes)
	if err != nil {
		return fmt.Errorf("invalid card ephemeral key: %w", err)
	}

	// Perform dual ECDH:
	// ShSee = ECDH(eSK.OCE, ePK.SD) — ephemeral-ephemeral
	shSee, err := ephKey.ECDH(cardEphPub)
	if err != nil {
		return fmt.Errorf("ECDH (ephemeral-ephemeral): %w", err)
	}
	// TR-03111 §4.3.1: verify the shared secret is not the point at infinity
	// (which manifests as an all-zero byte string after coordinate extraction).
	if isZeroSecret(shSee) {
		return fmt.Errorf("%w: ECDH (ephemeral-ephemeral): shared secret is zero (invalid point)", ErrInvalidResponse)
	}

	// ShSes = ECDH(SK.OCE or eSK.OCE, PK.SD)
	// GP §3.1.1: For SCP11b, reuse the ephemeral key for ShSes.
	// For SCP11a/c: use the OCE static private key
	// For SCP11b: reuse the ephemeral private key (no static key available)
	var shSesKey *ecdh.PrivateKey
	if s.config.Variant == SCP11a || s.config.Variant == SCP11c {
		if s.config.OCEPrivateKey == nil {
			return fmt.Errorf("%w: OCE private key required for SCP11a/c", ErrInvalidConfig)
		}
		// Convert the OCE static ECDSA key to ECDH.
		oceStaticECDH, err := s.config.OCEPrivateKey.ECDH()
		if err != nil {
			return fmt.Errorf("convert OCE static key: %w", err)
		}
		shSesKey = oceStaticECDH
	} else {
		shSesKey = ephKey
	}

	shSes, err := shSesKey.ECDH(s.cardStaticPubKey)
	if err != nil {
		return fmt.Errorf("ECDH (static/ephemeral-static): %w", err)
	}
	if isZeroSecret(shSes) {
		return fmt.Errorf("%w: ECDH (static/ephemeral-static): shared secret is zero (invalid point)", ErrInvalidResponse)
	}

	// Derive session keys.
	// GP SCP11 §3.1.2: SharedInfo = keyUsage || keyType || keyLength
	// Optionally followed by: hostIDLen || hostID || cardGroupIDLen || cardGroupID
	keys, err := kdf.DeriveSessionKeysFromSharedSecrets(shSee, shSes,
		s.config.HostID, s.config.CardGroupID)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	// Receipt verification.
	//
	// GP SCP11 §3.1.2: receipt = AES-CMAC(receipt_key, command_data || ePK.SD.TLV)
	//
	// Default policy: require receipt for ALL variants (a/b/c).
	// Authority:
	//
	//   - GP Amendment F v1.4 specifies receipts for all SCP11
	//     variants. Earlier revisions did not for SCP11b.
	//   - Yubico's yubikit (yubikey-manager) reference implementation
	//     unconditionally unpacks tag 0x86 from the INTERNAL/MUTUAL
	//     AUTHENTICATE response and verifies it via AES-CMAC,
	//     regardless of variant. Modern YubiKey firmware (5.7.2+)
	//     follows this profile.
	//   - Without a receipt, the MAC chain seeds from zero — which
	//     means there is no key confirmation and a card can return
	//     arbitrary ephemeral material without proving it derived
	//     the same shared secret.
	//
	// Escape hatch: Config.InsecureAllowSCP11bWithoutReceipt
	// (SCP11b only). For older SCP11b cards that genuinely don't
	// include a receipt; never appropriate for SCP11a/c.
	if receipt == nil {
		switch s.config.Variant {
		case SCP11a, SCP11c:
			return fmt.Errorf("%w: expected receipt for SCP11a/c but none received (mutual auth requires it)", ErrAuthFailed)
		case SCP11b:
			if !s.config.InsecureAllowSCP11bWithoutReceipt {
				return fmt.Errorf("%w: expected receipt for SCP11b but none received; modern cards (Amendment F v1.4, YubiKey 5.7.2+) include one. Set Config.InsecureAllowSCP11bWithoutReceipt=true only for legacy SCP11b cards that omit it", ErrAuthFailed)
			}
		}
	}
	if receipt != nil {
		// Build key agreement data: the AUTHENTICATE data we sent,
		// concatenated with the card's ephemeral public key TLV.
		cardEphPubTLV := tlv.Build(tlv.TagEphPubKey, cardEphPubBytes)
		var keyAgreementData []byte
		keyAgreementData = append(keyAgreementData, data...)
		keyAgreementData = append(keyAgreementData, cardEphPubTLV.Encode()...)
		err = kdf.VerifyReceipt(keys.Receipt, keyAgreementData, receipt)
		if err != nil {
			return fmt.Errorf("%w: receipt verification: %w", ErrAuthFailed, err)
		}
	}

	s.sessionKeys = keys

	// MAC chain initialization. If a (now-verified) receipt was
	// returned, the chain seeds from it; otherwise zeros (only
	// reachable via InsecureAllowSCP11bWithoutReceipt).
	if receipt != nil {
		s.sessionKeys.MACChain = make([]byte, len(receipt))
		copy(s.sessionKeys.MACChain, receipt)
	}

	return nil
}

// stripLeadingTrustAnchors removes self-signed certs from the start
// of an OCE chain. Per the SCP11a/c provisioning model, the trust
// anchor (OCE CA) lives on the card — installed via PUT KEY at the
// OCE CA reference and registered via STORE CA-IDENTIFIER. The
// chain uploaded over PSO is the path *below* the trust anchor:
// typically just the leaf, optionally with intermediates, but
// never the anchor itself.
//
// Cards reject the trust-anchor cert during PSO with SW=6A80 because
// they already have it and treat the duplicate as an ill-formed
// path. The previous behavior — sending every cert in the chain —
// was the proximate cause of "PSO cert 1/N: SW=6A80" against retail
// YubiKey 5.7.4 in scpctl smoke runs (2026-05-04).
//
// Self-signed = Issuer DN equals Subject DN. The check is purely on
// the DN bytes; it does NOT verify the self-signature, because (a)
// validating signatures here would couple PSO to crypto we don't
// need, and (b) a non-self-signed cert with matching subject/issuer
// would itself be malformed. The strip is a heuristic to be
// forgiving about the common case of "user passed the bootstrap
// PEM file (CA + leaf) to scp11a-sd-read."
//
// Multiple leading self-signed certs (rare but possible — e.g. cross
// signed roots in a transitional rollout) all get stripped.
func stripLeadingTrustAnchors(chain []*x509.Certificate) []*x509.Certificate {
	for i, cert := range chain {
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return chain[i:]
		}
	}
	return nil
}
