// Package scp03 implements GlobalPlatform Secure Channel Protocol 03
// (GP Card Spec v2.3, Amendment D) for establishing authenticated and
// encrypted communication with smart cards using pre-shared symmetric keys.
//
// SCP03 uses three static AES keys (ENC, MAC, DEK) that are pre-provisioned
// on both the host and the card. The handshake derives ephemeral session
// keys via NIST SP 800-108 KDF in counter mode, with host and card
// challenges providing freshness.
//
// # Protocol Flow
//
//	Host                              Card
//	 │── INITIALIZE UPDATE ──────────>│  host challenge (8 bytes)
//	 │<─ card challenge + cryptogram ─│  key diversification data
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
package scp03

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
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

// Config holds the parameters for establishing an SCP03 session.
type Config struct {
	// Keys is the pre-shared static key set.
	Keys StaticKeys

	// KeyVersion identifies which key set to use on the card.
	// Default: 0x00 (card chooses first available).
	KeyVersion byte

	// HostChallenge is the 8-byte random value used in INITIALIZE UPDATE.
	// If nil, a random challenge is generated.
	HostChallenge []byte

	// SecurityDomainAID is the AID to SELECT before the handshake.
	// If nil, no SELECT is sent (assumes the SD is already selected).
	SecurityDomainAID []byte

	// ApplicationAID is the target applet to SELECT after the secure
	// channel is established. If nil, no application SELECT is performed.
	ApplicationAID []byte

	// SecurityLevel controls which secure messaging operations to apply.
	// Default: full security (C-MAC + C-DEC + R-MAC + R-ENC).
	SecurityLevel channel.SecurityLevel
}

// Session is an established SCP03 secure channel.
type Session struct {
	config      *Config
	transport   transport.Transport
	channel     *channel.SecureChannel
	sessionKeys *kdf.SessionKeys
}

// Open establishes an SCP03 secure channel over the given Transport.
// It performs the complete handshake: INITIALIZE UPDATE, session key
// derivation, card cryptogram verification, and EXTERNAL AUTHENTICATE.
func Open(ctx context.Context, t transport.Transport, cfg *Config) (*Session, error) {
	if cfg == nil {
		cfg = &Config{Keys: DefaultKeys}
	}
	if cfg.SecurityLevel == 0 {
		cfg.SecurityLevel = channel.LevelFull
	}

	s := &Session{
		config:    cfg,
		transport: t,
	}

	// Step 1: SELECT Security Domain if configured.
	if len(cfg.SecurityDomainAID) > 0 {
		resp, err := t.Transmit(ctx, apdu.NewSelect(cfg.SecurityDomainAID))
		if err != nil {
			return nil, fmt.Errorf("select SD: %w", err)
		}
		if !resp.IsSuccess() {
			return nil, fmt.Errorf("select SD: %w", resp.Error())
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
	if len(hostChallenge) != 8 {
		return nil, errors.New("host challenge must be 8 bytes")
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
		SENC:     senc,
		SMAC:     smac,
		SRMAC:    srmac,
		DEK:      make([]byte, keyLen), // DEK derived on demand
		Receipt:  nil,                  // SCP03 doesn't use receipts
		MACChain: make([]byte, 16),     // Start with zeros
	}

	// Step 6: Verify card cryptogram.
	// Card cryptogram = AES-MAC(S-MAC, host_challenge || card_challenge)
	// using the derived S-MAC with derivation constant 0x00.
	expectedCC, err := calculateCryptogram(senc, 0x00, kdfContext, keyLen)
	if err != nil {
		return nil, fmt.Errorf("calculate card cryptogram: %w", err)
	}
	if !constantTimeEqual(expectedCC, iur.cardCryptogram) {
		return nil, errors.New("card cryptogram mismatch: possible MITM or wrong keys")
	}

	// Step 7: Calculate host cryptogram.
	hostCryptogram, err := calculateCryptogram(senc, 0x01, kdfContext, keyLen)
	if err != nil {
		return nil, fmt.Errorf("calculate host cryptogram: %w", err)
	}

	// Step 8: Send EXTERNAL AUTHENTICATE.
	s.channel = channel.New(s.sessionKeys, cfg.SecurityLevel)

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

	// Wrap with C-MAC only (no encryption for EXTERNAL AUTHENTICATE).
	wrappedExtAuth, err := s.channel.Wrap(extAuthCmd)
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

	// Step 9: SELECT application if configured.
	if len(cfg.ApplicationAID) > 0 {
		selectCmd := apdu.NewSelect(cfg.ApplicationAID)
		wrappedSelect, err := s.channel.Wrap(selectCmd)
		if err != nil {
			return nil, fmt.Errorf("wrap SELECT app: %w", err)
		}
		resp, err = t.Transmit(ctx, wrappedSelect)
		if err != nil {
			return nil, fmt.Errorf("SELECT app: %w", err)
		}
		if !resp.IsSuccess() {
			// Unwrap to get the real error
			return nil, fmt.Errorf("SELECT app: %w", resp.Error())
		}
	}

	return s, nil
}

// Transmit sends a command through the SCP03 secure channel.
func (s *Session) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	wrapped, err := s.channel.Wrap(cmd)
	if err != nil {
		return nil, fmt.Errorf("wrap command: %w", err)
	}

	resp, err := s.transport.Transmit(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("transmit: %w", err)
	}
	if !resp.IsSuccess() {
		return resp, nil
	}

	if len(resp.Data) > 0 {
		unwrapped, err := s.channel.Unwrap(resp)
		if err != nil {
			// GP §4.8: MAC verification failure terminates the channel.
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
		zeroBytes(s.sessionKeys.SENC)
		zeroBytes(s.sessionKeys.SMAC)
		zeroBytes(s.sessionKeys.SRMAC)
		zeroBytes(s.sessionKeys.DEK)
		s.sessionKeys = nil
	}
	s.channel = nil
}

// SessionKeys returns the derived session keys for audit or debugging.
func (s *Session) SessionKeys() *kdf.SessionKeys {
	return s.sessionKeys
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
	iParam                 byte   // Implementation options
	cardChallenge          []byte // 8 bytes
	cardCryptogram         []byte // 8 bytes
	sequenceCounter        []byte // 3 bytes (optional)
}

// parseInitUpdateResponse parses the card's response to INITIALIZE UPDATE.
// GP Amendment D §7.1.1: response is 28+ bytes.
func parseInitUpdateResponse(data []byte) (*initUpdateResponse, error) {
	if len(data) < 29 {
		return nil, fmt.Errorf("INITIALIZE UPDATE response too short: %d bytes (need 29+)", len(data))
	}

	r := &initUpdateResponse{
		keyDiversificationData: data[0:10],
		keyVersion:             data[10],
		scpID:                  data[11],
		iParam:                 data[12],
		cardChallenge:          data[13:21],
		cardCryptogram:         data[21:29],
	}

	// Verify SCP identifier.
	if r.scpID != 0x03 {
		return nil, fmt.Errorf("unexpected SCP identifier: 0x%02X (expected 0x03)", r.scpID)
	}

	// Optional: sequence counter (3 bytes) may follow.
	if len(data) >= 32 {
		r.sequenceCounter = data[29:32]
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
		input = append(input, make([]byte, 11)...) // 11 zero bytes
		input = append(input, derivConst)           // derivation constant
		input = append(input, 0x00)                 // separation indicator
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
// GP Amendment D §6.2.2: cryptogram = first 8 bytes of
// KDF(S-ENC, derivation_constant, context) with L=64 bits.
func calculateCryptogram(senc []byte, derivConst byte, context []byte, keyLen int) ([]byte, error) {
	cryptoLenBits := 64
	var input []byte
	input = append(input, make([]byte, 11)...)
	input = append(input, derivConst)
	input = append(input, 0x00)
	input = append(input, byte(cryptoLenBits>>8), byte(cryptoLenBits))
	input = append(input, 0x01) // counter = 1
	input = append(input, context...)

	mac, err := cmac.AESCMAC(senc, input)
	if err != nil {
		return nil, err
	}

	return mac[:8], nil
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

//go:noinline
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
