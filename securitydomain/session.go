package securitydomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	scp "github.com/PeculiarVentures/scp"
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// AIDSecurityDomain is the GlobalPlatform Issuer Security Domain AID.
var AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

// Status words used during reset lockout.
const (
	swAuthMethodBlocked    uint16 = 0x6983
	swSecurityNotSatisfied uint16 = 0x6982
	swIncorrectParameters  uint16 = 0x6A80
)

// Session provides typed management operations over an authenticated
// Security Domain channel.
//
// Two construction modes are supported:
//
//   - Authenticated: via Open, OpenSCP11, or OpenWithSession.
//     All management operations are available.
//
//   - Unauthenticated: via OpenUnauthenticated.
//     Only read-only introspection operations are available.
//
// A Session is NOT safe for concurrent use. Like the underlying
// *scp03.Session and *scp11.Session it wraps, the secure-channel
// state is single-threaded: the encryption counter, MAC chain, and
// per-command APDU framing all assume one in-flight Transmit at a
// time. Callers driving the Security Domain from multiple goroutines
// must serialize externally (e.g. with a sync.Mutex around the
// Session, or by funneling all calls through one goroutine).
type Session struct {
	scpSession    scp.Session
	transport     transport.Transport
	authenticated bool

	// oceAuthenticated reports whether the off-card entity (us)
	// proved possession of a long-term secret to the card during
	// the handshake. This is the gate for OCE-required operations
	// like PUT KEY, GENERATE EC KEY, DELETE KEY, STORE CERTIFICATES,
	// and STORE DATA.
	//
	//   - SCP03 mutual auth      → true (host proves MAC key knowledge)
	//   - SCP11a (mutual)        → true (OCE proves possession of OCE static key)
	//   - SCP11c (mutual)        → true
	//   - SCP11b (one-way)       → FALSE — card authenticates to host,
	//                              host does NOT authenticate to card.
	//                              Card-side authorization will reject
	//                              OCE-gated commands; reject host-side
	//                              up front so the failure is clear.
	//   - Unauthenticated open   → false
	oceAuthenticated bool

	// dek is the Data Encryption Key from the SCP03 key set used to
	// authenticate this session. Required for PUT KEY operations that
	// encrypt key material before transmission. Nil for SCP11 sessions.
	dek []byte

	// profile gates vendor-extension operations against the
	// active card profile. Set via SetProfile after Open*; nil
	// means "no gating, send anything" (backward compat for
	// callers that haven't adopted the profile package yet).
	//
	// Wired into GenerateECKey today; future vendor-extension
	// methods will consult this field too. Set once at session
	// open and never mutated for the session's lifetime.
	profile profile.Profile

	// sdAID records which Security Domain AID this session
	// targets. Set at Open* via the explicit sdAID parameter
	// or defaulted to AIDSecurityDomain when none was given.
	//
	// Stored so callers / observers (telemetry, JSON output,
	// post-open diagnostics) can recover the addressed AID
	// without rebuilding it from external state. Read-only
	// after construction; cloneAID at Open* time means a
	// caller mutating the input slice can't corrupt this copy.
	//
	// Per the external review on feat/sd-keys-cli, Finding 2:
	// non-default ISD AIDs must be addressable via the Open*
	// API. The SDAID() accessor exposes the chosen value for
	// CLI output and for sanity-checks across nested calls
	// (e.g. lifecycle commands that want to assert they're
	// operating on the AID the operator named, not on the
	// implicit default).
	sdAID []byte
}

// dekProvider is the unexported capability interface that the SD
// layer type-asserts on to obtain a session DEK from a concrete
// SCP03 or SCP11 session. Keeping this private to the
// securitydomain package means a generic scp.Session value cannot
// reach the DEK by interface dispatch — only code in this package
// (or another package that explicitly type-asserts on the concrete
// session type) can.
//
// Both *scp03.Session and *scp11.Session satisfy this interface.
type dekProvider interface {
	// SessionDEK returns a defensive copy of the Data Encryption Key
	// derived during (or established at the start of) the secure
	// channel handshake. Returns nil if the session is closed or did
	// not produce a usable DEK. The DEK is the AES key the card
	// expects key material to be wrapped under for PUT KEY (GP
	// §11.1.4).
	SessionDEK() []byte
}

// oceAuthState is the unexported capability interface the SD layer
// type-asserts on to determine whether a session authenticates the
// off-card entity to the card. Replaces a previous string-match on
// scp.Session.Protocol(), which was brittle (a future protocol or
// variant rename would silently flip authorization decisions).
//
// Both *scp03.Session and *scp11.Session satisfy this interface.
// SCP03 always reports true (EXTERNAL AUTHENTICATE proves OCE
// possession of the MAC key); SCP11a/c report true; SCP11b reports
// false (only the card authenticates).
type oceAuthState interface {
	OCEAuthenticated() bool
}

// sessionOCEAuthenticated reports whether the underlying secure-
// channel session authenticates the OCE to the card.
//
// The check is strict: a session must implement oceAuthState (i.e.
// expose an OCEAuthenticated() bool method on the concrete type) to
// be considered for OCE-gated management operations. Concrete
// *scp03.Session and *scp11.Session both satisfy this; any other
// scp.Session implementation that wants to drive Security Domain
// management ops MUST implement the same method.
//
// Earlier versions fell back to a Protocol() string match
// ("SCP03"|"SCP11a"|"SCP11c" treated as OCE-authenticated). That was
// a soft guard: a malicious or buggy custom Session could return a
// favourable protocol string and pass the host-side gate without
// actually authenticating the OCE to the card. Card-side
// authorization would still reject the operation, but the host-side
// gate is meant to catch the misuse before the wire APDU goes out.
// Removing the fallback eliminates the soft path and forces explicit
// opt-in by adapter authors.
func sessionOCEAuthenticated(s scp.Session) bool {
	if s == nil {
		return false
	}
	if oa, ok := s.(oceAuthState); ok {
		return oa.OCEAuthenticated()
	}
	// Custom Session implementations that don't expose
	// OCEAuthenticated() are treated as not-OCE-authenticated.
	// Management operations (PUT KEY, DELETE KEY, GENERATE EC KEY,
	// STORE CERTIFICATES, STORE DATA, etc.) will fail at the
	// host-side gate with ErrNotAuthenticated.
	return false
}

// sessionDEK returns the underlying session's DEK if it exposes one.
// Returns nil if the session does not satisfy dekProvider or has no
// DEK to surface.
func sessionDEK(s scp.Session) []byte {
	if s == nil {
		return nil
	}
	if dp, ok := s.(dekProvider); ok {
		return dp.SessionDEK()
	}
	return nil
}

// OpenSCP03 establishes an authenticated Security Domain session
// using SCP03 with the supplied configuration. The config is
// shallow-copied before the SD-required fields are forced
// (SelectAID = AIDSecurityDomain, SecurityLevel = LevelFull), so a
// caller reusing a Config across applets/sessions stays intact.
//
//	sd, err := securitydomain.OpenSCP03(ctx, t, &scp03.Config{
//	    Keys:       scp03.DefaultKeys,
//	    KeyVersion: 0xFF,
//	})
//	defer sd.Close()
//
// The DEK from cfg.Keys is captured and used as the PUT KEY wrapping
// key for subsequent PutSCP03Key / PutECPrivateKey / PutECPublicKey
// calls. The DEK is validated at this boundary (length must be
// 16/24/32 bytes, all-zero rejected) so configuration mistakes
// surface here rather than at the first PUT KEY.
//
// SecurityLevel and SelectAID are always forced to LevelFull and
// AIDSecurityDomain regardless of the values in cfg — Security Domain
// management requires a fully-authenticated channel against the ISD,
// and the wrapper would otherwise silently downgrade.
//
// For non-default ISD AIDs (vendor-specific cards, Supplementary
// Security Domains addressed by AID), use OpenSCP03WithAID.
func OpenSCP03(ctx context.Context, t transport.Transport, cfg *scp03.Config) (*Session, error) {
	return OpenSCP03WithAID(ctx, t, cfg, nil)
}

// OpenSCP03WithAID is OpenSCP03 with an explicit Security Domain AID.
//
// sdAID controls which Security Domain the SCP03 session targets via
// the SELECT FILE that opens the channel:
//
//   - sdAID == nil OR len(sdAID) == 0: default to AIDSecurityDomain
//     (the GP-standard ISD AID A0000001510000). Identical behavior
//     to OpenSCP03; OpenSCP03 calls this function with nil.
//
//   - sdAID non-empty: SELECT this AID instead. Used for non-YubiKey
//     GP cards whose ISD lives at a vendor-specific AID, and for
//     Supplementary Security Domains (SSDs) addressed by AID rather
//     than as the implicit default.
//
// Per the external review on feat/sd-keys-cli, Finding 2: a
// --sd-aid plumb-through across generic SD commands is the biggest
// generic-GP interop blocker, since cards that use a non-default
// ISD AID currently cannot be addressed at all.
//
// SecurityLevel is still forced to LevelFull for the same reason as
// OpenSCP03 (full SCP03 SD management always requires a fully-
// authenticated channel; allowing partial security levels here would
// silently downgrade the channel). Only the AID is configurable.
func OpenSCP03WithAID(ctx context.Context, t transport.Transport, cfg *scp03.Config, sdAID []byte) (*Session, error) {
	if t == nil {
		return nil, errors.New("securitydomain: transport is required")
	}
	if cfg == nil {
		return nil, errors.New("securitydomain: scp03 Config is required")
	}

	// Validate the static DEK at the API boundary so configuration
	// mistakes (all-zero key, wrong length) surface here rather than
	// at the first PUT KEY call. The same helper backs OpenWithSession
	// and requireDEK so all three paths agree on what a usable DEK
	// looks like.
	if err := validateDEK(cfg.Keys.DEK); err != nil {
		return nil, fmt.Errorf("securitydomain: %w", err)
	}

	// Shallow copy so we don't mutate the caller's Config. The fields
	// we override are scalars / nil-able pointers, so a shallow copy
	// is enough to isolate the side effect.
	local := *cfg
	local.SelectAID = effectiveSDAID(sdAID)
	local.SecurityLevel = channel.LevelFull

	scpSess, err := scp03.Open(ctx, t, &local)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SCP03 session: %w", err)
	}

	// Store the DEK for use in PUT KEY operations.
	dek := make([]byte, len(cfg.Keys.DEK))
	copy(dek, cfg.Keys.DEK)

	return &Session{
		scpSession:       scpSess,
		transport:        t,
		authenticated:    true,
		oceAuthenticated: sessionOCEAuthenticated(scpSess),
		dek:              dek,
		sdAID:            cloneAID(local.SelectAID),
	}, nil
}

// OpenSCP11 establishes an authenticated Security Domain session using SCP11.
//
// The caller's cfg is not mutated: this function takes a shallow copy
// before forcing SelectAID = AIDSecurityDomain and ApplicationAID = nil,
// so configs reused across applets/sessions stay intact. Earlier
// versions modified cfg in place, which surprised callers reusing a
// shared config object.
//
// The DEK derived during SCP11 key agreement (one of the five outputs
// of the X9.63 KDF) is captured here so PUT KEY operations work over
// SCP11 without the caller needing to plumb the DEK manually. Earlier
// versions discarded the SCP11-derived DEK entirely, which meant
// PutSCP03Key, PutECPrivateKey, and PutECPublicKey all failed with
// "SCP03 session required" against an SCP11-authenticated session —
// even though the SCP11 session DOES derive a usable DEK.
//
// For non-default ISD AIDs (vendor-specific cards, Supplementary
// Security Domains addressed by AID), use OpenSCP11WithAID.
func OpenSCP11(ctx context.Context, t transport.Transport, cfg *scp11.Config) (*Session, error) {
	return OpenSCP11WithAID(ctx, t, cfg, nil)
}

// OpenSCP11WithAID is OpenSCP11 with an explicit Security Domain AID.
//
// sdAID semantics match OpenSCP03WithAID: nil/empty defaults to
// AIDSecurityDomain; non-empty selects that AID instead. Used for
// non-YubiKey GP cards and for Supplementary Security Domains.
//
// Per the external review on feat/sd-keys-cli, Finding 2.
func OpenSCP11WithAID(ctx context.Context, t transport.Transport, cfg *scp11.Config, sdAID []byte) (*Session, error) {
	if t == nil {
		return nil, errors.New("securitydomain: transport is required")
	}
	if cfg == nil {
		return nil, errors.New("securitydomain: scp11 Config is required (use scp11.YubiKeyDefaultSCP11bConfig() or scp11.StrictGPSCP11bConfig() as a starting point)")
	}
	local := *cfg
	local.SelectAID = effectiveSDAID(sdAID)
	local.ApplicationAID = nil

	scpSess, err := scp11.Open(ctx, t, &local)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SCP11 session: %w", err)
	}

	s := &Session{
		scpSession:       scpSess,
		transport:        t,
		authenticated:    true,
		oceAuthenticated: sessionOCEAuthenticated(scpSess),
		sdAID:            cloneAID(local.SelectAID),
	}
	if dek := sessionDEK(scpSess); len(dek) > 0 {
		// SCP11-derived DEK passes the same length check used for
		// SCP03 static DEKs (16/24/32 AES). The all-zero check would
		// false-positive on a freshly-derived key whose first byte
		// happens to be zero, so we only enforce the length+nonempty
		// here; the static-DEK all-zero check is a config-mistake
		// guard, not a runtime invariant.
		if len(dek) == 16 || len(dek) == 24 || len(dek) == 32 {
			s.dek = dek
		}
	}
	return s, nil
}

// OpenWithSession wraps an existing authenticated scp.Session.
//
// DEK selection:
//
//   - If dek is non-nil, it is validated and used as the PUT KEY
//     wrapping key (length must be 16/24/32, must not be all zero).
//   - If dek is nil, this function asks the underlying session for
//     a DEK via the dekProvider capability interface and uses what
//     comes back. *scp03.Session returns the static DEK; *session.
//     Session returns the SCP11 KDF-derived DEK. The all-zero
//     check is skipped for derived keys because a fresh KDF output
//     may legitimately start with a zero byte; the all-zero guard
//     is a config-mistake check, not a runtime invariant.
//   - If neither path produces a usable DEK, PUT KEY operations
//     will return ErrNotAuthenticated.
//
// Custom session implementations that don't satisfy dekProvider
// (e.g. test doubles or non-standard adapters) need to pass an
// explicit dek; OpenWithSession won't reach into a generic
// scp.Session for key material.
func OpenWithSession(scpSess scp.Session, t transport.Transport, dek []byte) (*Session, error) {
	if scpSess == nil {
		return nil, errors.New("securitydomain: scp.Session is required")
	}
	if t == nil {
		return nil, errors.New("securitydomain: transport is required")
	}
	s := &Session{
		scpSession:       scpSess,
		transport:        t,
		authenticated:    true,
		oceAuthenticated: sessionOCEAuthenticated(scpSess),
	}
	if len(dek) > 0 {
		if err := validateDEK(dek); err != nil {
			return nil, fmt.Errorf("securitydomain: %w", err)
		}
		s.dek = make([]byte, len(dek))
		copy(s.dek, dek)
	} else if sdek := sessionDEK(scpSess); len(sdek) > 0 {
		// Length-only validation for derived keys; the all-zero
		// check is a config-mistake guard (see validateDEK) and
		// doesn't apply to KDF output.
		if len(sdek) == 16 || len(sdek) == 24 || len(sdek) == 32 {
			s.dek = sdek
		}
	}
	return s, nil
}

// validateDEK enforces the structural and security requirements on a
// session DEK supplied at the API boundary. The same check is reapplied
// at use time by requireDEK to defend against later mutation, but
// catching it here means callers see the failure where they made it.
func validateDEK(dek []byte) error {
	switch len(dek) {
	case 16, 24, 32:
		// AES-128 / AES-192 / AES-256.
	default:
		return fmt.Errorf("DEK must be 16, 24, or 32 bytes; got %d", len(dek))
	}
	allZero := true
	for _, b := range dek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New("DEK is all zero; refusing to use a known key")
	}
	return nil
}

// OpenUnauthenticated opens a read-only session to the Security Domain.
//
// Targets the GP-standard ISD AID. For non-default AIDs use
// OpenUnauthenticatedWithAID.
func OpenUnauthenticated(ctx context.Context, t transport.Transport) (*Session, error) {
	return OpenUnauthenticatedWithAID(ctx, t, nil)
}

// OpenUnauthenticatedWithAID is OpenUnauthenticated with an explicit
// Security Domain AID.
//
// sdAID semantics match OpenSCP03WithAID: nil/empty defaults to
// AIDSecurityDomain; non-empty selects that AID instead. Used to
// run non-destructive reads (CRD, KIT, registry walk) against a
// non-default ISD AID or against a Supplementary Security Domain
// addressed by AID.
//
// Per the external review on feat/sd-keys-cli, Finding 2.
func OpenUnauthenticatedWithAID(ctx context.Context, t transport.Transport, sdAID []byte) (*Session, error) {
	if t == nil {
		return nil, errors.New("securitydomain: transport is required")
	}
	aid := effectiveSDAID(sdAID)
	cmd := apdu.NewSelect(aid)
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: select SD: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: select SD: %w", resp.Error())
	}
	return &Session{transport: t, authenticated: false, sdAID: cloneAID(aid)}, nil
}

// effectiveSDAID returns the AID an Open* call should target. Empty
// or nil input falls back to the GP-standard ISD AID; non-empty
// input is returned unchanged. The caller is responsible for cloning
// before storing — Open* functions store via cloneAID so per-Session
// state can't be mutated by a caller that retains a slice reference.
func effectiveSDAID(sdAID []byte) []byte {
	if len(sdAID) == 0 {
		return AIDSecurityDomain
	}
	return sdAID
}

// cloneAID copies an AID slice so the Session retains a stable
// reference even if the caller mutates the input.
func cloneAID(aid []byte) []byte {
	if len(aid) == 0 {
		return nil
	}
	out := make([]byte, len(aid))
	copy(out, aid)
	return out
}

// Close terminates the session and zeros key material.
// Close terminates the session. The underlying SCP session is closed
// (zeroing its key material), the DEK is zeroed and the slice header
// nilled, and the authentication flags are cleared so that subsequent
// calls observe a closed session rather than a session that thinks it
// is still authenticated with all-zero key material. Calling Close
// twice is safe.
func (s *Session) Close() {
	if s.scpSession != nil {
		s.scpSession.Close()
		s.scpSession = nil
	}
	for i := range s.dek {
		s.dek[i] = 0
	}
	s.dek = nil
	s.authenticated = false
	s.oceAuthenticated = false
}

// IsAuthenticated reports whether this session has a secure channel.
func (s *Session) IsAuthenticated() bool { return s.authenticated }

// SetProfile attaches a card profile for vendor-extension gating.
// Operations that require a vendor-specific feature consult the
// profile's Capabilities and return ErrUnsupportedByProfile if
// the profile does not claim that feature.
//
// Pass nil to clear any previously-set profile (the session then
// behaves as if no profile gating is in effect — equivalent to
// the pre-profile-package default of "send any APDU the caller
// requests").
//
// SetProfile is intended to be called once, immediately after
// Open*, before any vendor-extension method. The profile is
// captured by reference; mutating the underlying value after
// SetProfile has unspecified effects.
func (s *Session) SetProfile(p profile.Profile) { s.profile = p }

// Profile returns the active profile, or nil if SetProfile was
// never called or was called with nil.
func (s *Session) Profile() profile.Profile { return s.profile }

// OCEAuthenticated reports whether the off-card entity (host) was
// authenticated to the card during the handshake. SCP03 mutual auth
// and SCP11a/c return true; SCP11b (one-way card-to-host auth) and
// unauthenticated sessions return false.
//
// Use this to decide whether OCE-gated management operations
// (PUT KEY, GENERATE EC KEY, DELETE KEY, certificate/data store
// operations) will succeed. SCP11b is fine for read-only inspection
// but the card will reject management commands; this method gives
// callers a way to detect the limitation host-side without needing
// to attempt the operation.
func (s *Session) OCEAuthenticated() bool { return s.oceAuthenticated }

// Protocol returns the secure channel protocol in use, or "none".
func (s *Session) Protocol() string {
	if s.scpSession != nil {
		return s.scpSession.Protocol()
	}
	return "none"
}

// SDAID returns a defensive copy of the Security Domain AID this
// session targets. The AID was set at Open* — either explicitly via
// the sdAID parameter on the *WithAID variants or implicitly defaulted
// to AIDSecurityDomain (the GP-standard ISD) when no AID was given.
//
// The returned slice is a copy: mutating it does not affect the
// session's internal state, and the session's stored AID is never
// mutated after construction.
//
// Per the external review on feat/sd-keys-cli, Finding 2: lets
// callers verify which AID was actually addressed (useful in JSON
// output that should record both the operator's --sd-aid input and
// what the session ended up targeting).
func (s *Session) SDAID() []byte {
	return cloneAID(s.sdAID)
}

// transmit sends a command through the appropriate channel.
func (s *Session) transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		return s.scpSession.Transmit(ctx, cmd)
	}
	return s.transport.Transmit(ctx, cmd)
}

// transmitRaw sends a command through the raw transport, bypassing
// secure messaging. Used during reset where the SCP session is being
// deliberately destroyed.
func (s *Session) transmitRaw(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return s.transport.Transmit(ctx, cmd)
}

// transmitCollectAll handles GET RESPONSE chaining through the secure
// channel when authenticated, or via the unauthenticated transport path
// otherwise. Both paths share the same iteration- and byte-count caps
// from the transport package — a hostile or buggy card cannot loop the
// host indefinitely or coerce unbounded memory growth, regardless of
// whether secure messaging is engaged.
func (s *Session) transmitCollectAll(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		resp, err := s.scpSession.Transmit(ctx, cmd)
		if err != nil {
			return nil, err
		}
		var allData []byte
		allData = append(allData, resp.Data...)
		for i := 0; resp.IsMoreData(); i++ {
			if i >= transport.MaxGetResponseIterations {
				return nil, fmt.Errorf("GET RESPONSE exceeded %d iterations", transport.MaxGetResponseIterations)
			}
			if len(allData) > transport.MaxCollectedResponseBytes {
				return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", transport.MaxCollectedResponseBytes)
			}
			getResp := apdu.NewGetResponse(resp.SW2)
			resp, err = s.scpSession.Transmit(ctx, getResp)
			if err != nil {
				return nil, err
			}
			allData = append(allData, resp.Data...)
		}
		return &apdu.Response{Data: allData, SW1: resp.SW1, SW2: resp.SW2}, nil
	}
	return transport.TransmitCollectAll(ctx, s.transport, cmd)
}

func (s *Session) requireAuth() error {
	if !s.authenticated {
		return ErrNotAuthenticated
	}
	return nil
}

// requireOCEAuth gates operations that require the off-card entity
// to have authenticated to the card (PUT KEY, DELETE KEY, GENERATE
// EC KEY, STORE CERTIFICATES, STORE CA ISSUER, STORE ALLOWLIST,
// STORE DATA, RESET, and other management operations).
//
// On SCP11b the card authenticates to the host but the host does
// NOT authenticate to the card; the card-side authorization layer
// will reject these commands. Reject host-side first so the failure
// is clear rather than an opaque 6982 from the card.
func (s *Session) requireOCEAuth() error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if !s.oceAuthenticated {
		return fmt.Errorf("%w: this operation requires OCE authentication; %s does not authenticate the off-card entity to the card (use SCP03 or SCP11a/c for management operations)",
			ErrNotAuthenticated, s.Protocol())
	}
	return nil
}

func (s *Session) requireDEK() error {
	if len(s.dek) == 0 {
		return fmt.Errorf("%w: session DEK not available; PUT KEY requires either an SCP03 session or an SCP11a/c session that derived a DEK during key agreement", ErrNotAuthenticated)
	}
	// Re-validate at use time. Construction-time validation in Open
	// and OpenWithSession should already have caught a bad DEK, but
	// running the same checks here means construction and use cannot
	// drift if validateDEK gets stricter in the future, and it
	// defends against any later mutation of s.dek. Note: validateDEK
	// rejects all-zero, which is appropriate for static SCP03 DEKs
	// (config mistake) but a freshly-derived SCP11 DEK could in
	// principle be all-zero with negligible probability — that's the
	// "this card just gave us a degenerate KDF output, abort" case
	// and we should treat it the same way.
	if err := validateDEK(s.dek); err != nil {
		return fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
	}
	return nil
}

// Application-level command chaining used to live here. The
// canonical layering is now wrap-then-chain: scp03.Session.Transmit
// performs Wrap once over the whole logical APDU (extended-format
// MAC when Lc > 255) and the wrapped bytes are split at the
// transport layer in scp03.Session.sendPossiblyChained. The
// application layer never sees more than one logical APDU per
// command, so a transmitWithChaining helper here is no longer
// needed and would re-introduce the layering bug it was added to
// solve (per-chunk SCP wrapping desyncing the host MAC chain
// against a card that sees one logical command).

// transmitStoreData sends a STORE DATA APDU as a single LOGICAL
// command. When the payload exceeds a short-form APDU's capacity,
// transport-layer chaining inside scp03.Session.Transmit splits it
// into ISO 7816-4 §5.1.1 chained chunks; the application layer
// here always sees one logical APDU.
//
// The wire shape is the same one yubikit-python emits and the one
// retail YubiKey 5.7.4 accepts: single P1=0x90 P2=0x00 APDU at the
// SCP layer, with the SCP wrap (encrypt + MAC over extended-format
// header) computed once over the whole logical command, and the
// wrapped bytes split at the transport. GP §11.11's application-
// level block chaining (P2 = block number, P1 b8 cleared on non-
// final blocks) is OPTIONAL and the YubiKey doesn't implement it;
// we don't use it.
//
// For unauthenticated sessions, scp03 isn't in the path and the
// transport sees the bare STORE DATA APDU. STORE DATA is OCE-
// gated on the YubiKey, so the only call sites that reach here
// in practice already require an authenticated session.
func (s *Session) transmitStoreData(ctx context.Context, payload []byte) (*apdu.Response, error) {
	resp, err := s.transmit(ctx, storeDataCmd(payload))
	if err != nil {
		return nil, fmt.Errorf("STORE DATA: %w", err)
	}
	return resp, nil
}

// --- Introspection ---

// GetKeyInformation retrieves information about all installed keys.
func (s *Session) GetKeyInformation(ctx context.Context) ([]KeyInfo, error) {
	cmd := getDataCmd(p1p2KeyInfo, nil)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get key information: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get key information: %w: %w", ErrCardStatus, resp.Error())
	}
	return parseKeyInformation(resp.Data)
}

// GetCardRecognitionData retrieves the card recognition data (GP §H.2).
func (s *Session) GetCardRecognitionData(ctx context.Context) ([]byte, error) {
	cmd := getDataCmd(p1p2CardData, nil)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get card recognition data: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get card recognition data: %w: %w", ErrCardStatus, resp.Error())
	}
	return resp.Data, nil
}

// GetSupportedCaIdentifiers retrieves CA identifiers (SKIs) configured
// on the Security Domain.
func (s *Session) GetSupportedCaIdentifiers(ctx context.Context, kloc, klcc bool) ([]CaIdentifier, error) {
	if !kloc && !klcc {
		kloc = true
		klcc = true
	}

	var result []CaIdentifier
	for _, entry := range []struct {
		fetch bool
		tag   uint16
	}{
		{kloc, p1p2CaKlocID},
		{klcc, p1p2CaKlccID},
	} {
		if !entry.fetch {
			continue
		}
		cmd := getDataCmd(entry.tag, nil)
		resp, err := s.transmitCollectAll(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: get CA identifiers: %w", err)
		}
		if !resp.IsSuccess() {
			// Treat "not present" SWs as empty — these indicate
			// the optional DO simply isn't registered on this card.
			// Treat all other failures as real errors so callers
			// can distinguish "tag unsupported" (6D00) and "auth
			// required" (6982) from "tag exists but empty." Prior
			// behavior swallowed everything as empty, which made
			// it impossible to tell an unauthenticated card with
			// gated reads apart from a card with no KLOC/KLCC at
			// all — both surfaced as silent empty results.
			//
			// 6A88 = Referenced data or reference data not found
			//        (the addressed data object doesn't exist)
			// 6A82 = File or application not found (some applets
			//        return this for missing optional tags
			//        instead of 6A88; semantically equivalent for
			//        "not present" purposes)
			sw := resp.StatusWord()
			if sw == 0x6A88 || sw == 0x6A82 {
				continue
			}
			return nil, fmt.Errorf("securitydomain: get CA identifiers (tag 0x%04X): %w: %w",
				entry.tag, ErrCardStatus, resp.Error())
		}
		ids, err := parseSupportedCaIdentifiers(resp.Data)
		if err != nil {
			return nil, err
		}
		result = append(result, ids...)
	}
	return result, nil
}

// --- SCP03 key management ---

// PutSCP03Key installs or replaces an SCP03 key set.
//
// Key material is encrypted with the session DEK before transmission.
// replaceKvn is the KVN to replace, or 0 for a new key set.
//
// Requires an SCP03-authenticated session (DEK must be available).
func (s *Session) PutSCP03Key(ctx context.Context, ref KeyReference, keys scp03.StaticKeys, replaceKvn byte) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	if err := s.requireDEK(); err != nil {
		return err
	}

	cmd, expectedResponse, err := putKeySCP03Cmd(ref, keys.ENC, keys.MAC, keys.DEK, s.dek, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put SCP03 key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put SCP03 key: %w: %w", ErrCardStatus, resp.Error())
	}

	// Verify checksum: response should be KVN + KCV_enc + KCV_mac + KCV_dek.
	if !bytes.Equal(resp.Data, expectedResponse) {
		return fmt.Errorf("%w: response %X, expected %X", ErrChecksum, resp.Data, expectedResponse)
	}

	return nil
}

// --- SCP11 key management ---

// GenerateECKey generates a new NIST P-256 key pair on the device.
// The private key never leaves the device.
//
// Profile gating: when SetProfile has been called with a profile
// whose Capabilities().GenerateECKey is false (e.g. the standard
// GP profile), this method returns ErrUnsupportedByProfile
// without sending any APDU. GENERATE EC KEY (INS=0xF1) is a
// Yubico extension; standard GP cards reject it with SW=6D00.
// The host-side check turns that round-trip into a clear typed
// error.
func (s *Session) GenerateECKey(ctx context.Context, ref KeyReference, replaceKvn byte) (*ecdsa.PublicKey, error) {
	if err := s.requireOCEAuth(); err != nil {
		return nil, err
	}
	if s.profile != nil && !s.profile.Capabilities().GenerateECKey {
		return nil, fmt.Errorf("securitydomain: GenerateECKey: %w (profile %q)",
			profile.ErrUnsupportedByProfile, s.profile.Name())
	}

	cmd := generateECKeyCmd(ref, replaceKvn)
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: generate EC key: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: generate EC key: %w: %w", ErrCardStatus, resp.Error())
	}

	return parseGeneratedPublicKey(resp.Data)
}

// PutECPrivateKey imports an EC private key (NIST P-256).
// The key is encrypted with the session DEK before transmission.
//
// Requires an SCP03-authenticated session (DEK must be available).
func (s *Session) PutECPrivateKey(ctx context.Context, ref KeyReference, key *ecdsa.PrivateKey, replaceKvn byte) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	if err := s.requireDEK(); err != nil {
		return err
	}

	cmd, err := putKeyECPrivateCmd(ref, key, s.dek, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put EC private key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put EC private key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// PutECPublicKey imports an EC public key (NIST P-256).
// Typically used for OCE public keys in SCP11a/c.
// Public keys are not encrypted.
func (s *Session) PutECPublicKey(ctx context.Context, ref KeyReference, key *ecdsa.PublicKey, replaceKvn byte) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}

	cmd, err := putKeyECPublicCmd(ref, key, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put EC public key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put EC public key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Key deletion and reset ---

// DeleteKey deletes one or more keys matching the reference.
//
// SCP03 special case: SCP03 keys (KID 0x01, 0x02, 0x03) MUST be
// deleted by KVN only — yubikit's reference implementation rejects
// KID-bearing DELETE for SCP03 outright. Cards typically reject too.
// If ref.ID is an SCP03 KID, this method clears it before building
// the command so only the 0xD2 (KVN) tag is sent. ref.Version must
// be set in that case.
func (s *Session) DeleteKey(ctx context.Context, ref KeyReference, deleteLast bool) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}

	if isSCP03KeyID(ref.ID) {
		if ref.Version == 0 {
			return errors.New("securitydomain: SCP03 keys can only be deleted by KVN; set ref.Version to the key set version")
		}
		ref = NewKeyReference(0, ref.Version)
	}

	cmd, err := deleteKeyCmd(ref, deleteLast)
	if err != nil {
		return fmt.Errorf("securitydomain: delete key: %w", err)
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: delete key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: delete key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// isSCP03KeyID reports whether the given KID belongs to an SCP03
// static key set. GP defines KIDs 0x01, 0x02, 0x03 for the three
// SCP03 keys (ENC, MAC, DEK) within a key set; cards address the
// set as a whole by KVN.
func isSCP03KeyID(kid byte) bool {
	return kid == 0x01 || kid == 0x02 || kid == 0x03
}

// Reset triggers a Security Domain factory reset by blocking every
// installed key with deliberately-wrong credentials. After all keys
// are blocked, the card auto-restores factory state: default SCP03
// keys at KVN=0xFF, freshly-generated SCP11b key at KID=0x13/KVN=0x01,
// and any custom OCE/SCP11a/SCP11c material wiped.
//
// Reset is allowed from:
//   - Unauthenticated sessions (typical recovery path — see
//     ResetSecurityDomain top-level helper).
//   - OCE-authenticated sessions (SCP03 or SCP11a/c).
//
// Reset is rejected host-side from SCP11b sessions because SCP11b is
// one-way auth: the card authenticates to the host but the host
// doesn't authenticate to the card. The reset attempts would
// technically still work (they bypass the SM channel via
// transmitRaw), but doing so from inside an open SCP11b session is
// a confused user — the right shape is to close the SCP11b session
// and use ResetSecurityDomain (which opens an unauthenticated SD).
//
// The actual reset attempts go through transmitRaw, bypassing any
// secure channel. This matters for the recovery case: a card that's
// been provisioned with custom keys whose factory SCP03 is gone,
// where no authentication is possible until reset completes.
//
// The session is invalid after Reset returns — close it; the next
// call should open a new session against the now-factory card.
//
// Ref: Python SecurityDomainSession.reset(), C# SecurityDomainSession.Reset().
func (s *Session) Reset(ctx context.Context) error {
	// Defense-in-depth gate: reject if authenticated but NOT
	// OCE-authenticated. Unauthenticated sessions are explicitly
	// allowed (the recovery path); OCE-authenticated sessions are
	// allowed (SCP03 and SCP11a/c). Only SCP11b mid-session callers
	// are rejected — they have an SM channel that doesn't authorize
	// management ops, and this is the same surprising-failure-mode
	// guard that requireOCEAuth provides for PUT KEY, DELETE KEY,
	// STORE CERTIFICATES, etc.
	if s.authenticated && !s.oceAuthenticated {
		return fmt.Errorf("%w: SD reset requires OCE authentication or an unauthenticated session; "+
			"calling Reset from inside an SCP11b session is not allowed because SCP11b authenticates "+
			"the card to the host but not the host to the card. Close the session and call "+
			"securitydomain.ResetSecurityDomain (which opens an unauthenticated SD) instead",
			ErrNotAuthenticated)
	}

	// Get all installed keys.
	keys, err := s.GetKeyInformation(ctx)
	if err != nil {
		return fmt.Errorf("securitydomain: reset: get key info: %w", err)
	}

	// For each key, determine the appropriate INS and send 65 invalid
	// authentication attempts to trigger lockout.
	for _, ki := range keys {
		ins, shouldProcess := insForKeyReset(ki.Reference.ID)
		if !shouldProcess {
			continue
		}

		kvn := ki.Reference.Version
		kid := ki.Reference.ID

		// SCP03 special handling: use KID=0, KVN=0 to allow
		// deleting the default keys (which have KVN=0xFF).
		if ki.Reference.ID == KeyIDSCP03 {
			kvn = 0
			kid = 0
		}

		for attempt := 0; attempt < 65; attempt++ {
			cmd := resetLockoutCmd(ins, kvn, kid)
			resp, err := s.transmitRaw(ctx, cmd)
			if err != nil {
				// Transport errors during reset are not fatal —
				// the device may be resetting.
				break
			}
			sw := resp.StatusWord()
			if sw == swAuthMethodBlocked || sw == swSecurityNotSatisfied {
				break
			}
			// On INCORRECT_PARAMETERS or SUCCESS, continue attempting.
		}
	}

	return nil
}

// --- Certificate operations ---

// StoreCertificates stores an X.509 certificate chain on the card,
// associated with the given key reference. The chain order is leaf
// last (matches yubikit-python's get_certificate_bundle return order
// and store_certificate_bundle input order).
//
// Semantically, the chain stored at a key reference is the chain
// that certifies the PUBLIC KEY held at that reference. For SCP11
// SD keys (KID=0x11 SCP11a, 0x13 SCP11b, 0x15 SCP11c), this is the
// SD's attestation chain — the chain the OCE retrieves at session-
// open via GET DATA (TAG_CERTIFICATE_STORE = 0xBF21) to validate
// PK.SD.ECKA against trusted roots. The leaf cert in such a chain
// MUST certify the on-card SD pubkey; the YubiKey rejects with
// SW=6A80 if the chain content doesn't make sense at the chosen ref.
//
// This is NOT the function for storing the OCE's own chain. The
// OCE chain is sent on the wire at session-open via PSO (GP §7.5.3)
// and validated by the card against the registered KLOC CA pubkey
// + SKI (PutECPublicKey + StoreCaIssuer). The OCE chain is never
// stored on the card; passing the OCE chain here against the OCE
// CA key reference is a category error and the card will reject it.
//
// Requires OCE verification (the underlying SCP session must be
// SCP03 or an SCP11a/c session — both authenticate the OCE; SCP11b
// is one-way auth and STORE DATA writes need OCE auth).
func (s *Session) StoreCertificates(ctx context.Context, ref KeyReference, certs []*x509.Certificate) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}

	var derCerts [][]byte
	for _, c := range certs {
		derCerts = append(derCerts, c.Raw)
	}

	payload := storeCertificatesData(ref, derCerts)
	resp, err := s.transmitStoreData(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store certificates: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store certificates: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// GetCertificates retrieves the certificates for the given key reference.
// The leaf certificate is last in the returned slice.
func (s *Session) GetCertificates(ctx context.Context, ref KeyReference) ([]*x509.Certificate, error) {
	keyRefData := buildKeyRefTLV(ref)
	cmd := getDataCmd(p1p2CertStore, keyRefData)

	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get certificates: %w", err)
	}
	if !resp.IsSuccess() {
		// Reference data not found — no certificates stored.
		if resp.StatusWord() == 0x6A88 {
			return nil, nil
		}
		return nil, fmt.Errorf("securitydomain: get certificates: %w: %w", ErrCardStatus, resp.Error())
	}

	derCerts, err := parseCertificates(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// StoreCaIssuer stores the SKI for the CA associated with a key reference.
func (s *Session) StoreCaIssuer(ctx context.Context, ref KeyReference, ski []byte) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}

	payload := storeCaIssuerData(ref, ski)
	resp, err := s.transmitStoreData(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store CA issuer: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store CA issuer: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Allowlist operations ---

// StoreAllowlist replaces the certificate-serial-number allowlist
// for the given key reference. Each entry is a *big.Int matching
// what x509.Certificate.SerialNumber returns; the wire encoding is
// the unsigned big-endian byte representation. Negative or nil
// entries are rejected.
//
// Semantics are full-replacement: the supplied list becomes the new
// allowlist, regardless of what was there before. To clear, pass an
// empty (len 0) slice or nil — see also ClearAllowlist.
//
// Typical usage with serials pulled from x509 certificates:
//
//	var serials []*big.Int
//	for _, c := range trusted {
//	    serials = append(serials, c.SerialNumber)
//	}
//	if err := sd.StoreAllowlist(ctx, ref, serials); err != nil { ... }
//
// SerialFromHex is provided as a convenience for callers building
// allowlists from hex-encoded serial strings (e.g. from configuration
// files).
func (s *Session) StoreAllowlist(ctx context.Context, ref KeyReference, serials []*big.Int) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	// Profile gating: the wire shape this library emits for the
	// allowlist (BER-TLV nesting plus the integer-encoded serial
	// list) is the yubikit/Yubico shape, derived by reference-
	// implementation parity with yubikit-python's store_allowlist
	// and _int2asn1. We have not measured this wire shape against
	// any non-YubiKey card. Profiles that don't claim Allowlist
	// (currently: standard-sd) refuse the operation host-side
	// rather than emitting Yubico bytes against an unmeasured card.
	// When a non-YubiKey card is measured, lift the gate by setting
	// Allowlist=true on that profile.
	if s.profile != nil && !s.profile.Capabilities().Allowlist {
		return fmt.Errorf("securitydomain: StoreAllowlist: %w (profile %q): "+
			"the allowlist wire encoding is yubikit/Yubico-shape and has not been measured "+
			"on non-YubiKey cards; lift the gate by switching to a profile that claims Allowlist=true",
			profile.ErrUnsupportedByProfile, s.profile.Name())
	}

	payload, err := storeAllowlistData(ref, serials)
	if err != nil {
		return err
	}

	resp, err := s.transmitStoreData(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store allowlist: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store allowlist: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// ClearAllowlist removes the allowlist for the given key reference.
// Ref: C# ClearAllowList calls StoreAllowlist with empty list.
//
// Profile gating: same rationale as StoreAllowlist — the wire shape
// is yubikit/Yubico-specific and not measured on non-YubiKey cards.
// Profiles that don't claim Allowlist refuse the operation host-side.
// The check is duplicated here (rather than relying on the forwarding
// call to StoreAllowlist to surface it) so the error names the
// command the operator actually called.
func (s *Session) ClearAllowlist(ctx context.Context, ref KeyReference) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	if s.profile != nil && !s.profile.Capabilities().Allowlist {
		return fmt.Errorf("securitydomain: ClearAllowlist: %w (profile %q): "+
			"the allowlist wire encoding is yubikit/Yubico-shape and has not been measured "+
			"on non-YubiKey cards; lift the gate by switching to a profile that claims Allowlist=true",
			profile.ErrUnsupportedByProfile, s.profile.Name())
	}
	return s.StoreAllowlist(ctx, ref, nil)
}

// --- Raw data operations ---

// GetData sends a raw GET DATA command.
func (s *Session) GetData(ctx context.Context, tag uint16, data []byte) ([]byte, error) {
	cmd := getDataCmd(tag, data)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get data: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get data: %w: %w", ErrCardStatus, resp.Error())
	}
	return resp.Data, nil
}

// StoreData sends a STORE DATA command, fragmenting the payload into
// blocks if it exceeds a single APDU.
func (s *Session) StoreData(ctx context.Context, data []byte) error {
	if err := s.requireOCEAuth(); err != nil {
		return err
	}
	resp, err := s.transmitStoreData(ctx, data)
	if err != nil {
		return fmt.Errorf("securitydomain: store data: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store data: %w: %w", ErrCardStatus, resp.Error())
	}
	return nil
}

// --- Internal helpers ---

func buildKeyRefTLV(ref KeyReference) []byte {
	node := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)
	return node.Encode()
}
