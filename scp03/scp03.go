// Package scp03 implements GlobalPlatform Secure Channel Protocol 03
// (GP Card Spec v2.3, Amendment D) for establishing authenticated and
// encrypted communication with smart cards using pre-shared symmetric keys.
//
// SCP03 uses three static AES keys (ENC, MAC, DEK) that are pre-provisioned
// on both the host and the card. The handshake derives ephemeral session
// keys via NIST SP 800-108 KDF in counter mode, with host and card
// challenges providing freshness.
//
// # Key sizes and assurance
//
// scp03.Open supports AES-128, AES-192, and AES-256 at the channel-
// establishment layer. All three sizes are byte-exact-verified against
// Samsung OpenSCP-Java protocol vectors at the handshake, KDF, and
// secure-messaging layers. AES-128 is also verified against YubiKey
// hardware end-to-end; AES-192 / AES-256 are protocol-layer-verified
// pending hardware validation against a card that supports them.
//
// Note that this is the channel-establishment guarantee. The
// securitydomain.PutSCP03Key provisioning flow (the management-side
// PUT KEY for installing new SCP03 key sets) currently covers the
// AES-128 management profile; AES-192 / AES-256 PUT KEY shapes are
// expansion targets and need a card and reference vectors to validate
// against.
//
// S8 (8-byte MAC truncation) and S16 (16-byte MAC) are both supported.
// All six combinations (AES-128 / 192 / 256 × S8 / S16) are protocol-
// layer-verified; S8 is also hardware-verified against YubiKey.
// Hardware validation of S16 is an expansion target.
//
// # Protocol Flow
//
//	Host                              Card
//	 │── INITIALIZE UPDATE ──────────>│  host challenge (8 bytes S8 / 16 bytes S16)
//	 │<─ card challenge + cryptogram ─│  key diversification data, iParam selects S8/S16
//	 │                                │
//	 │   derive session keys (S-ENC, S-MAC, S-RMAC)
//	 │   verify card cryptogram
//	 │                                │
//	 │── EXTERNAL AUTHENTICATE ──────>│  host cryptogram + MAC
//	 │<─ 9000 ────────────────────────│
//	 │                                │
//	 │══ Secure channel established ══│
//
// # Usage
//
//	sess, err := scp03.Open(ctx, transport, &scp03.Config{
//	    Keys:          scp03.DefaultKeys, // For testing only!
//	    KeyVersion:    0x01,
//	    SecurityLevel: channel.LevelFull,
//	})
//	defer sess.Close()
//
//	resp, _ := sess.Transmit(ctx, myCommand) // Encrypted + MACed
//
// # Errors
//
// Open and Transmit wrap a small set of sentinel errors so callers
// can use errors.Is to discriminate categories without pattern-
// matching on message text. See ErrAuthFailed, ErrInvalidConfig,
// and ErrInvalidResponse.
package scp03

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/internal/secmem"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/transport"
)

// StaticKeys holds the three pre-shared AES keys for SCP03.
type StaticKeys struct {
	ENC []byte // Channel encryption key (16, 24, or 32 bytes)
	MAC []byte // Channel MAC key
	DEK []byte // Data encryption key
}

// DefaultKeys is the well-known default SCP03 key set shipped on most
// smart cards. These provide NO security and must be replaced in production.
var DefaultKeys = StaticKeys{
	ENC: []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F},
	MAC: []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F},
	DEK: []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F},
}

// StrictGPConfig returns an SCP03 Config with spec-literal defaults
// for the given key set: KeyVersion 0 ("any version" per GP), full
// security level by default, and EmptyDataEncryption set explicitly
// to channel.EmptyDataNoOp. Use this against cards that
// strictly implement GP Amendment D §6.2.4 rather than the YubiKey
// pad-and-encrypt interpretation.
//
// The caller supplies keys explicitly; there is no factory-key
// shortcut here because the GP spec test keys are themselves the
// scp03.DefaultKeys, and using them is already an opt-in.
func StrictGPConfig(keys StaticKeys) *Config {
	return &Config{
		Keys:                keys,
		KeyVersion:          0x00,
		EmptyDataEncryption: channel.EmptyDataNoOp,
	}
}

// Config holds the parameters for establishing an SCP03 session.
type Config struct {
	// Keys is the pre-shared static key set.
	Keys StaticKeys

	// KeyVersion identifies which key set to use on the card. The
	// correct value is vendor-specific:
	//
	//   - YubiKey factory:                       0xFF
	//   - Most GP-spec test/factory cards:       0x00 or 0x01
	//   - User-imported sets:                    1..3 typically
	//
	// Zero value (0x00) is sent on the wire as P1=0x00, which most
	// cards interpret as "first available key set." YubiKey rejects
	// this with 6A88 because the factory KVN is 0xFF; using
	// scp03.DefaultKeys against a factory YubiKey requires KeyVersion=0xFF.
	// See the README factory-keys table.
	KeyVersion byte

	// HostChallenge is the random value used in INITIALIZE UPDATE.
	// 8 bytes selects S8 (8-byte cryptograms and MACs); 16 bytes
	// selects S16. If nil, a random 8-byte challenge is generated.
	HostChallenge []byte

	// SelectAID is the applet AID to SELECT before the handshake.
	// The applet's SCP03 key set is what the handshake authenticates
	// against — typically the Issuer Security Domain, but any applet
	// holding an SCP03 key set is valid.
	// If nil, no SELECT is sent (assumes the target is already selected).
	SelectAID []byte

	// ApplicationAID is an optional applet to SELECT through the
	// secure channel after the handshake. Note: on YubiKey, doing
	// this terminates the SCP session — set SelectAID instead and
	// leave this nil.
	ApplicationAID []byte

	// SecurityLevel controls which secure messaging operations to apply.
	// Default: full security (C-MAC + C-DEC + R-MAC + R-ENC).
	//
	// Open rejects dangerous combinations by default — see
	// InsecureAllowPartialSecurityLevel below for the escape hatch.
	SecurityLevel channel.SecurityLevel

	// InsecureAllowPartialSecurityLevel disables the safety check on
	// SecurityLevel that rejects encryption-without-authentication
	// combinations (C-DEC without C-MAC, or R-ENC without R-MAC).
	//
	// Those combinations exist in the GP spec for completeness — a
	// client can technically negotiate "encrypt commands but don't
	// MAC them" — but they create real attack surface: encrypted
	// commands that aren't authenticated can be replayed or
	// blockwise-tampered, and the channel layer's CBC padding errors
	// become a side channel. Production callers want full security.
	//
	// The only legitimate use of this field is conformance testing
	// against the GP spec, where you're driving the card through
	// every spec-defined level to verify its parser. Real deployments
	// MUST leave this false. The deliberately ugly name matches the
	// "Insecure" prefix convention used elsewhere in this library
	// for opt-in defeat-the-defaults knobs.
	InsecureAllowPartialSecurityLevel bool

	// EmptyDataEncryption controls how the C-DECRYPT step handles a
	// command APDU with no data field. Two interpretations ship in
	// the wild:
	//
	//   - channel.EmptyDataPadAndEncrypt (default): pad empty data
	//     with 0x80 || 0x00*15 and encrypt as one block. Verified
	//     against YubiKey 5.x and matches Yubico's yubikit.
	//
	//   - channel.EmptyDataNoOp: skip encryption entirely when data
	//     is empty (counter still increments). Matches a literal
	//     reading of GP Amendment D §6.2.4 and is the right choice
	//     for cards that strictly implement that text.
	//
	// Mismatched policy across host/card silently corrupts every
	// empty-data command (the card decrypts to garbage and either
	// rejects the APDU or, worse, executes a different operation).
	// If the card returns 6F xx for empty-data commands but works
	// for non-empty commands, try toggling this field.
	EmptyDataEncryption channel.EmptyDataPolicy
}

// Session is an established SCP03 secure channel.
//
// A Session is NOT safe for concurrent use. The secure channel state
// — the encryption counter and MAC chaining value — is mutated on
// every Transmit. Concurrent calls would race the counter and produce
// APDUs that the card rejects, and would race the MAC chain producing
// observable corruption.
//
// If multiple goroutines need to send commands, serialize them
// externally (e.g. with a sync.Mutex around the Session, or by funneling
// commands through a single goroutine). For separate logical contexts,
// open separate Sessions.
type Session struct {
	config      *Config
	transport   transport.Transport
	channel     *channel.SecureChannel
	sessionKeys *kdf.SessionKeys
}

// Open establishes an SCP03 secure channel over the given Transport.
// It performs the complete handshake: INITIALIZE UPDATE, session key
// derivation, card cryptogram verification, and EXTERNAL AUTHENTICATE.
//
// cfg must be non-nil and cfg.Keys must be set explicitly. Earlier
// versions of this function fell back to DefaultKeys (the well-known
// 0x40..0x4F test keys shipped on factory-fresh cards) when cfg was
// nil — that was a footgun: production code could open a "secure"
// channel with publicly known keys and never notice. To use the test
// keys on a factory-fresh card, set cfg.Keys = scp03.DefaultKeys
// explicitly. The act of typing that name is the consent.
func Open(ctx context.Context, t transport.Transport, cfg *Config) (*Session, error) {
	if t == nil {
		return nil, fmt.Errorf("%w: transport is required", ErrInvalidConfig)
	}
	if cfg == nil {
		return nil, fmt.Errorf("%w: Config is required (cfg.Keys cannot be nil)", ErrInvalidConfig)
	}
	// Shallow copy so we don't mutate the caller's Config. The fields
	// we override below (SecurityLevel) are scalars, so a shallow copy
	// is enough to isolate the side effect; the slice-typed Keys
	// fields are read-only here. Earlier versions modified cfg in
	// place, which surprised callers reusing a shared config object
	// across sessions.
	local := *cfg
	cfg = &local
	if len(cfg.Keys.ENC) == 0 || len(cfg.Keys.MAC) == 0 || len(cfg.Keys.DEK) == 0 {
		return nil, fmt.Errorf("%w: Config.Keys must be set; for factory-fresh cards explicitly use scp03.DefaultKeys (test keys, no security)", ErrInvalidConfig)
	}

	// All three SCP03 static keys must be the same AES size (16, 24,
	// or 32 bytes). Allowing mixed sizes was non-standard and silently
	// derived MAC session keys at the ENC key length rather than the
	// MAC key length — confusing, non-interoperable cryptography.
	// Cards reject mixed sizes too; failing fast here gives a useful
	// error rather than an opaque card-side rejection later.
	encLen, macLen, dekLen := len(cfg.Keys.ENC), len(cfg.Keys.MAC), len(cfg.Keys.DEK)
	if encLen != 16 && encLen != 24 && encLen != 32 {
		return nil, fmt.Errorf("%w: Keys.ENC length %d invalid (must be 16, 24, or 32 for AES-128/192/256)", ErrInvalidConfig, encLen)
	}
	if macLen != encLen || dekLen != encLen {
		return nil, fmt.Errorf("%w: Keys.ENC, Keys.MAC, Keys.DEK must all be the same length (got %d/%d/%d)", ErrInvalidConfig, encLen, macLen, dekLen)
	}
	if cfg.SecurityLevel == 0 {
		cfg.SecurityLevel = channel.LevelFull
	}

	// Reject dangerous SecurityLevel combinations: encryption without
	// authentication is a real attack surface (replay, blockwise
	// tampering, CBC padding side channel) and is almost never what a
	// caller actually wants. The GP spec allows them for completeness,
	// but production deployments should run at full security. Gate
	// them behind InsecureAllowPartialSecurityLevel for spec
	// conformance testing.
	if !cfg.InsecureAllowPartialSecurityLevel {
		hasCDEC := cfg.SecurityLevel&channel.LevelCDEC != 0
		hasCMAC := cfg.SecurityLevel&channel.LevelCMAC != 0
		hasRENC := cfg.SecurityLevel&channel.LevelRENC != 0
		hasRMAC := cfg.SecurityLevel&channel.LevelRMAC != 0
		if hasCDEC && !hasCMAC {
			return nil, fmt.Errorf("%w: SecurityLevel includes C-DEC without C-MAC; encryption without authentication is unsafe (set InsecureAllowPartialSecurityLevel for spec conformance testing only)", ErrInvalidConfig)
		}
		if hasRENC && !hasRMAC {
			return nil, fmt.Errorf("%w: SecurityLevel includes R-ENC without R-MAC; encryption without authentication is unsafe (set InsecureAllowPartialSecurityLevel for spec conformance testing only)", ErrInvalidConfig)
		}
	}

	s := &Session{
		config:    cfg,
		transport: t,
	}

	// Step 1: SELECT the target applet (whose SCP03 key set we
	// authenticate against). Skipped if SelectAID is nil.
	if len(cfg.SelectAID) > 0 {
		resp, err := t.Transmit(ctx, apdu.NewSelect(cfg.SelectAID))
		if err != nil {
			return nil, fmt.Errorf("select applet: %w", err)
		}
		if !resp.IsSuccess() {
			return nil, fmt.Errorf("select applet: %w", resp.Error())
		}
	}

	// Step 2: Generate or use provided host challenge.
	hostChallenge := cfg.HostChallenge
	if len(hostChallenge) == 0 {
		hostChallenge = make([]byte, 8)
		if _, err := rand.Read(hostChallenge); err != nil {
			return nil, fmt.Errorf("generate host challenge: %w", err)
		}
	}
	if len(hostChallenge) != 8 && len(hostChallenge) != 16 {
		return nil, fmt.Errorf("%w: host challenge must be 8 bytes (S8) or 16 bytes (S16)", ErrInvalidConfig)
	}

	// Step 3: Send INITIALIZE UPDATE.
	initCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0x50, // INITIALIZE UPDATE
		P1:   cfg.KeyVersion,
		P2:   0x00,
		Data: hostChallenge,
		Le:   0,
	}

	resp, err := t.Transmit(ctx, initCmd)
	if err != nil {
		return nil, fmt.Errorf("INITIALIZE UPDATE: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("INITIALIZE UPDATE: %w", resp.Error())
	}

	// Step 4: Parse INITIALIZE UPDATE response.
	iur, err := parseInitUpdateResponse(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("parse INITIALIZE UPDATE response: %w", err)
	}

	// Step 5: Derive session keys from static keys via NIST SP 800-108 KDF.
	// Context = host_challenge || card_challenge
	kdfContext := make([]byte, 0, 16)
	kdfContext = append(kdfContext, hostChallenge...)
	kdfContext = append(kdfContext, iur.cardChallenge...)

	keyLen := len(cfg.Keys.ENC)

	senc, err := deriveSCP03Key(cfg.Keys.ENC, derivConstSENC, kdfContext, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive S-ENC: %w", err)
	}
	smac, err := deriveSCP03Key(cfg.Keys.MAC, derivConstSMAC, kdfContext, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive S-MAC: %w", err)
	}
	srmac, err := deriveSCP03Key(cfg.Keys.MAC, derivConstSRMAC, kdfContext, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive S-RMAC: %w", err)
	}

	s.sessionKeys = &kdf.SessionKeys{
		SENC:  senc,
		SMAC:  smac,
		SRMAC: srmac,
		// DEK in session keys is a clone of the *static* DEK from
		// the config. SCP03 secure messaging itself does not derive
		// a separate session DEK — but operations like PUT KEY that
		// run on top of the channel need the static DEK to wrap key
		// material before import. Yubico's yubikit does the same:
		// it preserves key_dek through derive() so it's available
		// for Security Domain operations.
		// Earlier versions stored nil here, forcing callers to keep
		// a separate copy or go through securitydomain.OpenSCP03 just
		// to get at the DEK. That was a silent footgun for direct
		// scp03 users.
		DEK:      cloneBytes(cfg.Keys.DEK),
		Receipt:  nil,              // SCP03 doesn't use receipts
		MACChain: make([]byte, 16), // Start with zeros
	}

	// Step 6: Verify card cryptogram.
	// GP Amendment D §6.2.2: The card/host cryptograms use the data
	// derivation scheme with S-MAC as the base key and derivation
	// constants 0x00 (card) / 0x01 (host). See also GlobalPlatformPro
	// GPSession.java which uses macKey for cryptogram computation.
	expectedCC, err := calculateCryptogram(smac, 0x00, kdfContext, iur.macSize)
	if err != nil {
		return nil, fmt.Errorf("calculate card cryptogram: %w", err)
	}
	if !constantTimeEqual(expectedCC, iur.cardCryptogram) {
		return nil, fmt.Errorf("%w: card cryptogram mismatch: possible MITM or wrong keys", ErrAuthFailed)
	}

	// Step 7: Calculate host cryptogram (also derived with S-MAC).
	hostCryptogram, err := calculateCryptogram(smac, 0x01, kdfContext, iur.macSize)
	if err != nil {
		return nil, fmt.Errorf("calculate host cryptogram: %w", err)
	}

	// Step 8: Send EXTERNAL AUTHENTICATE.

	// The EXTERNAL AUTHENTICATE command itself is MACed with the session keys.
	extAuthData := hostCryptogram
	extAuthCmd := &apdu.Command{
		CLA:  0x84, // CLA with secure messaging bit set
		INS:  0x82, // EXTERNAL AUTHENTICATE
		P1:   cfg.SecurityLevel.Byte(),
		P2:   0x00,
		Data: extAuthData,
		Le:   -1,
	}

	// EXTERNAL AUTHENTICATE is the command that establishes the secure
	// channel. It is C-MACed, but its host cryptogram is not C-ENC encrypted,
	// even when the requested post-authentication level includes C-DEC.
	wrappedExtAuth, err := wrapExternalAuthenticate(extAuthCmd, s.sessionKeys, iur.macSize)
	if err != nil {
		return nil, fmt.Errorf("wrap EXTERNAL AUTHENTICATE: %w", err)
	}

	resp, err = t.Transmit(ctx, wrappedExtAuth)
	if err != nil {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE: %w", resp.Error())
	}

	s.channel = channel.NewWithMACSize(s.sessionKeys, cfg.SecurityLevel, iur.macSize)
	s.channel.EmptyDataEncryption = cfg.EmptyDataEncryption

	// Step 9: SELECT application if configured.
	// Routed through Session.Transmit so R-MAC is verified on the
	// response when negotiated — the post-auth SELECT response is
	// part of the authenticated channel and must not bypass the
	// secure-messaging unwrap.
	if len(cfg.ApplicationAID) > 0 {
		resp, err = s.Transmit(ctx, apdu.NewSelect(cfg.ApplicationAID))
		if err != nil {
			return nil, fmt.Errorf("SELECT app: %w", err)
		}
		if !resp.IsSuccess() {
			return nil, fmt.Errorf("SELECT app: %w", resp.Error())
		}
	}

	return s, nil
}

// Transmit sends a command through the SCP03 secure channel.
//
// Layering follows the GP/yubikit canonical order: wrap the LOGICAL
// APDU once at the SCP layer (one MAC chain advance per logical
// command), then split the wrapped bytes at the transport layer
// using ISO 7816-4 §5.1.1 command chaining when the wrapped APDU
// exceeds short-form Lc (255 bytes).
//
// The earlier inversion — chain at the application layer, wrap each
// chunk independently — produced a different wire shape for long
// commands: each chunk MAC'd as a standalone APDU, the host-side
// MAC chain advancing per chunk while the card sees one logical
// STORE DATA. Worse, the YubiKey returns bare 9000 (no R-MAC) on
// intermediate chained chunks, which the host's R-MAC unwrap then
// rejected and used as a signal to terminate the session — leaving
// the NEXT command's Wrap to deref a nil channel.
//
// Wrap-then-chain matches yubikit-python's ScpProcessor +
// CommandChainingProcessor stack and what real cards expect. The
// MAC is computed over the extended-format header (Lc encoded as
// 3 bytes when > 255), so the card-side MAC math agrees regardless
// of how the wire is split.
func (s *Session) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	wrapped, err := s.channel.Wrap(cmd)
	if err != nil {
		return nil, fmt.Errorf("wrap command: %w", err)
	}

	// Transport-layer chaining. transport.TransmitWithChaining splits
	// wrapped.Data into ISO 7816-4 §5.1.1 chunks if it exceeds the
	// short-Lc bound, sends each, and returns only the final chunk's
	// response. Intermediate chunks return bare 9000 with no R-MAC;
	// that's correct because the SCP wrap (and its MAC chain advance)
	// happened ONCE above for the whole logical command.
	resp, err := transport.TransmitWithChaining(ctx, s.transport, wrapped)
	if err != nil {
		return nil, fmt.Errorf("transmit: %w", err)
	}

	// Inbound chaining: when the card returns SW=61xx, the
	// secure-messaging-protected payload (encrypted body + R-MAC)
	// has been split across multiple response APDUs. The card's
	// MAC was computed over the entire payload, so the host must
	// concatenate every GET RESPONSE chunk before verifying the
	// MAC. Skipping this step makes any APDU whose response
	// exceeds the short-Le bound (attest cert reads, large GET
	// DATA tags, registry walks with many entries, anything
	// where ciphertext + MAC tag pushes past 256 bytes) fail
	// R-MAC and tear down the session.
	//
	// Drain via the raw transport, not s.Transmit, so GET
	// RESPONSE bytes are not wrapped in their own SCP frame.
	// GET RESPONSE is a transport continuation, not an
	// application command; the card answers it in cleartext at
	// the SCP layer and only the assembled inner payload is
	// covered by the channel's MAC.
	resp, err = transport.DrainGetResponse(ctx, s.transport, resp)
	if err != nil {
		return nil, fmt.Errorf("transmit: drain chained response: %w", err)
	}

	// GP SCP03 §6.2.4: R-MAC / R-ENC are applied ONLY to responses
	// with SW 9000 or warning SW1 62/63. Error status words (6Axx,
	// 6Bxx, ...) are unprotected by the card and must pass through
	// without R-MAC verification — otherwise legitimate card errors
	// turn into spurious session terminations and any transport-
	// level attacker can DoS the channel by injecting an unprotected
	// error status word.
	if s.config.SecurityLevel&channel.LevelRMAC != 0 {
		if !channel.ResponseIsSecureMessagingProtected(resp.SW1, resp.SW2) {
			// Unprotected card error — return as-is. Session stays
			// open; the caller decides what to do with the SW.
			return resp, nil
		}
		unwrapped, err := s.channel.Unwrap(resp)
		if err != nil {
			// GP §4.8: MAC verification failure terminates the channel.
			s.Close()
			return nil, fmt.Errorf("unwrap response (session terminated): %w", err)
		}
		return unwrapped, nil
	}

	if !resp.IsSuccess() {
		return resp, nil
	}

	if len(resp.Data) > 0 {
		unwrapped, err := s.channel.Unwrap(resp)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("unwrap response (session terminated): %w", err)
		}
		return unwrapped, nil
	}

	return resp, nil
}

// Close terminates the session and zeros all key material.
func (s *Session) Close() {
	if s.sessionKeys != nil {
		secmem.Zero(s.sessionKeys.SENC)
		secmem.Zero(s.sessionKeys.SMAC)
		secmem.Zero(s.sessionKeys.SRMAC)
		secmem.Zero(s.sessionKeys.DEK)
		s.sessionKeys = nil
	}
	s.channel = nil
}

// InsecureExportSessionKeysForTestOnly returns a defensive copy of
// the session's live cryptographic keys (S-ENC, S-MAC, S-RMAC, DEK,
// MAC chain). It exists for two narrow uses: round-tripping byte-exact
// transcript tests against external reference implementations, and
// audit tooling that diffs derived material against a known-answer
// vector.
//
// Production callers MUST NOT call this. The returned material lets
// anyone who sees the bytes decrypt every wrapped command/response
// in this session, forge MACs against the card, and recover any key
// material wrapped under DEK. Logging it (even at debug level) means
// permanent compromise of every command in that session, including
// any keys uploaded via PUT KEY.
//
// The deliberately ugly name exists so this function is impossible
// to call by accident and obvious in code review.
func (s *Session) InsecureExportSessionKeysForTestOnly() *kdf.SessionKeys {
	return s.sessionKeys.Clone()
}

// SessionDEK returns a defensive copy of the SCP03 static DEK, used
// by the securitydomain layer for PUT KEY key wrapping.
//
// For SCP03, the "session" DEK is the static DEK from Config.Keys —
// SCP03 secure messaging does not derive a separate session DEK.
// Returns nil if the session is closed.
//
// This is a concrete method on *scp03.Session, not part of the
// scp.Session interface, so it cannot be reached through a value
// of generic interface type. The securitydomain package consumes
// it through an unexported capability interface; other callers
// who genuinely need the DEK (e.g. for a custom PUT KEY-equivalent
// flow) can type-assert on this concrete type. Callers must zero
// the returned slice when done.
func (s *Session) SessionDEK() []byte {
	if s.sessionKeys == nil || len(s.sessionKeys.DEK) == 0 {
		return nil
	}
	out := make([]byte, len(s.sessionKeys.DEK))
	copy(out, s.sessionKeys.DEK)
	return out
}

// OCEAuthenticated reports whether this session authenticates the
// Off-Card Entity to the card. SCP03 always does — host possession
// of the static MAC key is proved during EXTERNAL AUTHENTICATE, so
// the card knows it is talking to an authorized administrator.
//
// This is a concrete method, not part of the scp.Session interface.
// The securitydomain package consumes it through an unexported
// capability interface to gate management operations without
// pattern-matching on Protocol() string values.
func (s *Session) OCEAuthenticated() bool {
	// A closed session shouldn't be considered authenticated for
	// gating purposes. zeroSessionKeys clears sessionKeys on Close.
	return s.sessionKeys != nil
}

// Protocol returns "SCP03".
func (s *Session) Protocol() string {
	return "SCP03"
}

// --- SCP03 Handshake Internals ---

// NIST SP 800-108 derivation constants for SCP03 (GP Amendment D §6.2.2).
const (
	derivConstSENC       = 0x04
	derivConstSMAC       = 0x06
	derivConstSRMAC      = 0x07
	derivConstCardCrypto = 0x00
	derivConstHostCrypto = 0x01
)

// initUpdateResponse holds the parsed INITIALIZE UPDATE response.
type initUpdateResponse struct {
	keyDiversificationData []byte // 10 bytes
	keyVersion             byte
	scpID                  byte   // Should be 0x03
	iParam                 byte   // Implementation options (b1 = S16 if set)
	cardChallenge          []byte // 8 bytes (S8) or 16 bytes (S16)
	cardCryptogram         []byte // 8 bytes (S8) or 16 bytes (S16)
	sequenceCounter        []byte // 3 bytes (optional)
	macSize                int    // 8 for S8, 16 for S16
}

// parseInitUpdateResponse parses the card's response to INITIALIZE UPDATE.
// GP Amendment D §7.1.1: response is 28+ bytes.
func parseInitUpdateResponse(data []byte) (*initUpdateResponse, error) {
	if len(data) < 29 {
		return nil, fmt.Errorf("%w: INITIALIZE UPDATE response too short: %d bytes (need 29+)", ErrInvalidResponse, len(data))
	}

	r := &initUpdateResponse{
		keyDiversificationData: data[0:10],
		keyVersion:             data[10],
		scpID:                  data[11],
		iParam:                 data[12],
	}

	// Verify SCP identifier.
	if r.scpID != 0x03 {
		return nil, fmt.Errorf("%w: unexpected SCP identifier: 0x%02X (expected 0x03)", ErrInvalidResponse, r.scpID)
	}

	if r.iParam&0x01 != 0 {
		// S16 mode uses 16-byte host/card challenges and 16-byte cryptograms.
		if len(data) < 45 {
			return nil, fmt.Errorf("%w: INITIALIZE UPDATE S16 response too short: %d bytes (need 45+)", ErrInvalidResponse, len(data))
		}
		r.cardChallenge = data[13:29]
		r.cardCryptogram = data[29:45]
		r.macSize = 16
		if len(data) >= 48 {
			r.sequenceCounter = data[45:48]
		}
	} else {
		r.cardChallenge = data[13:21]
		r.cardCryptogram = data[21:29]
		r.macSize = 8
		// Optional: sequence counter (3 bytes) may follow.
		if len(data) >= 32 {
			r.sequenceCounter = data[29:32]
		}
	}

	return r, nil
}

// deriveSCP03Key derives a single session key using the NIST SP 800-108
// KDF in counter mode with AES-CMAC as PRF.
//
// GP Amendment D §6.2.2:
//
//	label = 11 zero bytes || derivation_constant
//	input = label || 0x00 || L(2B) || counter(1B) || context
func deriveSCP03Key(staticKey []byte, derivConst byte, context []byte, keyLen int) ([]byte, error) {
	keyLenBits := keyLen * 8
	iterations := (keyLen + 15) / 16

	var derived []byte
	for counter := byte(1); counter <= byte(iterations); counter++ {
		var input []byte
		input = append(input, make([]byte, 11)...)                   // 11 zero bytes
		input = append(input, derivConst)                            // derivation constant
		input = append(input, 0x00)                                  // separation indicator
		input = append(input, byte(keyLenBits>>8), byte(keyLenBits)) // L in bits
		input = append(input, counter)
		input = append(input, context...)

		mac, err := cmac.AESCMAC(staticKey, input)
		if err != nil {
			return nil, err
		}
		derived = append(derived, mac...)
	}

	return derived[:keyLen], nil
}

// calculateCryptogram computes a card or host cryptogram.
// GP Amendment D §6.2.2: The authentication cryptograms are computed
// using the data derivation scheme with S-MAC as the base key.
// Derivation constant 0x00 = card cryptogram, 0x01 = host cryptogram.
// Output is L=64 bits (8 bytes) for S8 mode, L=128 bits (16 bytes) for
// S16 mode, selected by macSize.
func calculateCryptogram(smac []byte, derivConst byte, context []byte, macSize int) ([]byte, error) {
	if macSize != 8 && macSize != 16 {
		return nil, fmt.Errorf("unsupported cryptogram length: %d", macSize)
	}
	cryptoLenBits := macSize * 8
	var input []byte
	input = append(input, make([]byte, 11)...)
	input = append(input, derivConst)
	input = append(input, 0x00)
	input = append(input, byte(cryptoLenBits>>8), byte(cryptoLenBits))
	input = append(input, 0x01) // counter = 1
	input = append(input, context...)

	mac, err := cmac.AESCMAC(smac, input)
	if err != nil {
		return nil, err
	}

	return mac[:macSize], nil
}

func wrapExternalAuthenticate(cmd *apdu.Command, keys *kdf.SessionKeys, macSize int) (*apdu.Command, error) {
	if len(keys.MACChain) != 16 {
		keys.MACChain = make([]byte, 16)
	}

	lc := len(cmd.Data) + macSize
	if lc > 255 {
		return nil, fmt.Errorf("EXTERNAL AUTHENTICATE data too large: %d", lc)
	}

	newCLA := cmd.CLA | 0x04
	var macInput []byte
	macInput = append(macInput, keys.MACChain...)
	macInput = append(macInput, newCLA, cmd.INS, cmd.P1, cmd.P2, byte(lc))
	macInput = append(macInput, cmd.Data...)

	mac, err := cmac.AESCMAC(keys.SMAC, macInput)
	if err != nil {
		return nil, fmt.Errorf("compute EXTERNAL AUTHENTICATE C-MAC: %w", err)
	}
	keys.MACChain = mac

	var wrappedData []byte
	wrappedData = append(wrappedData, cmd.Data...)
	wrappedData = append(wrappedData, mac[:macSize]...)

	return &apdu.Command{
		CLA:            newCLA,
		INS:            cmd.INS,
		P1:             cmd.P1,
		P2:             cmd.P2,
		Data:           wrappedData,
		Le:             cmd.Le,
		ExtendedLength: cmd.ExtendedLength,
	}, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// cloneBytes returns a deep copy of b. Used so the SessionKeys
// returned to callers don't alias the caller's StaticKeys.DEK,
// preventing accidental mutation of the original key material.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
