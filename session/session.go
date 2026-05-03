// Package session implements the SCP11 protocol state machine for
// establishing a secure channel between an off-card entity (OCE) and
// a GlobalPlatform Security Domain (SD) on a smart card.
//
// The protocol flow (for SCP11b) is:
//
//  1. SELECT the Security Domain AID
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
package session

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/trust"
)

// Variant selects the SCP11 protocol variant.
type Variant int

const (
	SCP11a Variant = iota // Mutual auth, OCE provides cert first
	SCP11b                // One-way auth, no OCE cert validation by card
	SCP11c                // Mutual auth with receipt, scriptable
)

// State tracks the session lifecycle.
type State int

const (
	StateNew State = iota
	StateSelected
	StateCertRetrieved
	StateAuthenticated
	StateFailed
)

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

	// OCECertificate is the OCE's certificate, required for SCP11a.
	// For SCP11b, this is sent but not validated by the card.
	OCECertificate *x509.Certificate

	// OCEPrivateKey is the OCE's long-term ECDSA key for SCP11a
	// certificate-based authentication. Not needed for SCP11b.
	OCEPrivateKey *ecdsa.PrivateKey

	// CardTrustAnchors validates the card's certificate chain.
	// If nil, the card certificate is not validated (SCP11b behavior).
	// For richer validation (P-256 enforcement, serial allowlists,
	// SKI matching), use CardTrustPolicy instead.
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

	// HostID is the optional OCE identifier included in the KDF shared
	// info per GP SCP11 §3.1.2. If set, it is appended to the shared
	// info as a length-value pair: len(HostID) || HostID.
	// Used in SCP11a/b/c. If nil, not included (the common case for
	// default behavior).
	HostID []byte

	// CardGroupID is the optional card group identifier for SCP11c.
	// Included in the KDF shared info after HostID if set.
	CardGroupID []byte

	// SecurityLevel controls which secure messaging operations to apply.
	// Default: full security (C-MAC + C-DEC + R-MAC + R-ENC).
	SecurityLevel channel.SecurityLevel
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

// DefaultConfig returns a Config for SCP11b with standard defaults.
//
// The handshake targets the GP Issuer Security Domain. ApplicationAID
// is left nil — callers should SELECT their target applet before
// calling Open, since some platforms (notably YubiKey) terminate an
// SCP session when a different applet is selected mid-channel.
//
// Trust is also unconfigured by default; the caller must set
// CardTrustPolicy, CardTrustAnchors, or InsecureSkipCardAuthentication
// before Open will agree to a key with the card.
func DefaultConfig() *Config {
	return &Config{
		Variant:           SCP11b,
		SelectAID:         AIDSecurityDomain,
		ApplicationAID:    nil,
		KeyID:             0x13,
		KeyVersion:        0x01,
		SecurityLevel:     channel.LevelFull,
	}
}

// Session manages an SCP11 secure channel over a Transport.
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
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.SecurityLevel == 0 {
		cfg.SecurityLevel = channel.LevelFull
	}

	// Validate that the configured SecurityLevel is consistent with the
	// key usage qualifier (0x3C = full security) sent in INTERNAL/MUTUAL
	// AUTHENTICATE. The card enforces the negotiated level, so a mismatch
	// causes the host wrapper to diverge from what the card expects.
	if cfg.SecurityLevel != channel.LevelFull {
		return nil, errors.New("SCP11 currently only supports full security level (C-MAC|C-DEC|R-MAC|R-ENC); " +
			"the key usage qualifier 0x3C negotiated with the card requires it")
	}

	s := &Session{
		config:    cfg,
		transport: t,
		state:     StateNew,
	}

	// Step 1: Select the Security Domain.
	if err := s.selectSD(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("select SD: %w", err)
	}

	// Step 2: Retrieve the card's certificate and extract PK.SD.ECKA.
	if err := s.getCardCertificate(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("get card cert: %w", err)
	}

	// Step 3 (SCP11a/c): Send OCE certificate via PERFORM SECURITY OPERATION.
	// Both SCP11a and SCP11c are mutual-auth variants that require the OCE
	// certificate to be provided to the card before MUTUAL AUTHENTICATE.
	if cfg.Variant == SCP11a || cfg.Variant == SCP11c {
		if cfg.OCEPrivateKey == nil {
			return nil, errors.New("OCE private key required for SCP11a/c (mutual-auth variants)")
		}
		if cfg.OCECertificate == nil {
			return nil, errors.New("OCE certificate required for SCP11a/c (mutual-auth variants)")
		}
		// Defense-in-depth: ensure the configured private key actually
		// corresponds to the certificate sent to the card. A mismatch
		// would either cause MUTUAL AUTHENTICATE to fail (best case) or,
		// worse, succeed against a permissive card while the host
		// believes it is presenting one identity but holds another.
		if err := verifyOCEKeyMatchesCert(cfg.OCEPrivateKey, cfg.OCECertificate); err != nil {
			return nil, fmt.Errorf("OCE key/certificate mismatch: %w", err)
		}
		if err := s.sendOCECertificate(ctx); err != nil {
			s.state = StateFailed
			return nil, fmt.Errorf("send OCE cert: %w", err)
		}
	}

	// Step 4: Perform key agreement via INTERNAL AUTHENTICATE.
	if err := s.performKeyAgreement(ctx); err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("key agreement: %w", err)
	}

	// Step 5: Create the secure channel wrapper.
	s.channel = channel.New(s.sessionKeys, cfg.SecurityLevel)
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

	// Send through the underlying transport.
	resp, err := s.transport.Transmit(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("transmit: %w", err)
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
		zeroBytes(s.sessionKeys.SENC)
		zeroBytes(s.sessionKeys.SMAC)
		zeroBytes(s.sessionKeys.SRMAC)
		zeroBytes(s.sessionKeys.DEK)
		zeroBytes(s.sessionKeys.Receipt)
		zeroBytes(s.sessionKeys.MACChain)
		s.sessionKeys = nil
	}
	s.channel = nil
}

//go:noinline
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SessionKeys returns a defensive copy of the session keys for audit
// or debugging. Mutations to the returned struct do not affect the
// session's live key material.
func (s *Session) SessionKeys() *kdf.SessionKeys {
	return s.sessionKeys.Clone()
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

func (s *Session) selectSD(ctx context.Context) error {
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
		CLA:  0x80,
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
		return errors.New("SCP11 card certificate validation is required; configure CardTrustPolicy/CardTrustAnchors or set InsecureSkipCardAuthentication for tests")
	}
	pubKey, err := extractCardPublicKey(data, s.config.CardTrustAnchors)
	if err != nil {
		return fmt.Errorf("extract card public key: %w", err)
	}

	s.cardStaticPubKey = pubKey
	s.state = StateCertRetrieved
	return nil
}

// validateCardCertChain parses all certificates from the card's cert
// store response and validates them using the trust package. This is
// the preferred path when CardTrustPolicy is configured — it enforces
// P-256, chain validation, and optional serial/SKI constraints before
// allowing the card's public key to be used for key agreement.
func (s *Session) validateCardCertChain(data []byte) error {
	certs, err := parseCertsFromStore(data)
	if err != nil {
		return fmt.Errorf("parse card certificates: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("no certificates in card response")
	}

	result, err := trust.ValidateSCP11Chain(certs, *s.config.CardTrustPolicy)
	if err != nil {
		return fmt.Errorf("card certificate chain validation: %w", err)
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

func (s *Session) sendOCECertificate(ctx context.Context) error {
	if s.config.OCECertificate == nil {
		return errors.New("OCE certificate required for SCP11a/c (mutual-auth variants)")
	}

	// PERFORM SECURITY OPERATION sends the OCE certificate chain.
	// GP §7.5: Certificate chaining for PERFORM SECURITY OPERATION.
	//   - Intermediate chunks: CLA |= 0x10 (chaining bit), P1 |= 0x80
	//   - Final chunk: original CLA, original P1
	//   - Each chunk max 255 bytes
	certData := s.config.OCECertificate.Raw
	p1Base := byte(0x00)
	p2 := byte(0x00)

	offset := 0
	maxChunk := 255
	for offset < len(certData) {
		remaining := len(certData) - offset
		chunkLen := remaining
		if chunkLen > maxChunk {
			chunkLen = maxChunk
		}
		isLast := (offset + chunkLen) >= len(certData)

		cla := byte(0x80)
		p1 := p1Base
		if !isLast {
			cla |= 0x10 // Command chaining
			p1 |= 0x80  // GP §7.5.2.1: more certificate data follows
		}

		cmd := &apdu.Command{
			CLA:  cla,
			INS:  0x2A, // PERFORM SECURITY OPERATION
			P1:   p1,
			P2:   p2,
			Data: certData[offset : offset+chunkLen],
			Le:   0,
		}

		resp, err := s.transport.Transmit(ctx, cmd)
		if err != nil {
			return err
		}
		if !resp.IsSuccess() {
			return resp.Error()
		}

		offset += chunkLen
	}

	return nil
}

func (s *Session) performKeyAgreement(ctx context.Context) error {
	// Generate OCE ephemeral ECDH key pair (P-256).
	curve := ecdh.P256()
	ephKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	s.oceEphemeralKey = ephKey

	// Build the INTERNAL AUTHENTICATE / MUTUAL AUTHENTICATE command.
	//
	// Data field per GP SCP11 §7.6.2.3:
	//   A6 { 90{11, params}, 95{3C}, 80{88}, 81{10} }
	//   5F49 { ePK.OCE uncompressed point }
	//
	// GP §7.6.2.3 / §7.7.2.3: key params in A6 control reference template.
	// The params byte varies by variant: SCP11a=0x01, SCP11b=0x00, SCP11c=0x03.
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

	cardEphPub, err := curve.NewPublicKey(cardEphPubBytes)
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
		return errors.New("ECDH (ephemeral-ephemeral): shared secret is zero (invalid point)")
	}

	// ShSes = ECDH(SK.OCE or eSK.OCE, PK.SD)
	// GP §3.1.1: For SCP11b, reuse the ephemeral key for ShSes.
	// For SCP11a/c: use the OCE static private key
	// For SCP11b: reuse the ephemeral private key (no static key available)
	var shSesKey *ecdh.PrivateKey
	if s.config.Variant == SCP11a || s.config.Variant == SCP11c {
		if s.config.OCEPrivateKey == nil {
			return errors.New("OCE private key required for SCP11a/c")
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
		return errors.New("ECDH (static/ephemeral-static): shared secret is zero (invalid point)")
	}

	// Derive session keys.
	// GP SCP11 §3.1.2: SharedInfo = keyUsage || keyType || keyLength
	// Optionally followed by: hostIDLen || hostID || cardGroupIDLen || cardGroupID
	keys, err := kdf.DeriveSessionKeysFromSharedSecrets(shSee, shSes,
		s.config.HostID, s.config.CardGroupID)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	// For SCP11a/c: verify the receipt.
	// GP SCP11 §3.1.2: receipt = AES-CMAC(receipt_key, command_data || ePK.SD.TLV)
	if s.config.Variant == SCP11a || s.config.Variant == SCP11c {
		if receipt == nil {
			return errors.New("expected receipt for SCP11a/c but none received")
		}
		// Build key agreement data: the MUTUAL AUTH data field we sent,
		// concatenated with the card's ephemeral public key TLV.
		cardEphPubTLV := tlv.Build(tlv.TagEphPubKey, cardEphPubBytes)
		var keyAgreementData []byte
		keyAgreementData = append(keyAgreementData, data...)
		keyAgreementData = append(keyAgreementData, cardEphPubTLV.Encode()...)
		err = kdf.VerifyReceipt(keys.Receipt, keyAgreementData, receipt)
		if err != nil {
			return fmt.Errorf("receipt verification: %w", err)
		}
	}

	s.sessionKeys = keys

	// GP §5.3.2: macChain is initialized to the receipt for SCP11a/c.

	if receipt != nil {
		s.sessionKeys.MACChain = make([]byte, len(receipt))
		copy(s.sessionKeys.MACChain, receipt)
	}

	return nil
}
