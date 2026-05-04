package scp03

import (
	"context"
	"crypto/rand"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
)

// MockCard simulates a GlobalPlatform card supporting SCP03 for
// end-to-end testing. It implements INITIALIZE UPDATE, EXTERNAL
// AUTHENTICATE, secure messaging (C-MAC | C-DEC | R-MAC | R-ENC),
// and a small set of post-handshake commands the test fixtures use.
//
// Lives in this package rather than in the central mockcard
// package because SCP03's setup is pre-shared symmetric keys
// (StaticKeys), while mockcard.Card configures around an asymmetric
// SCP11 key and certificate. The two protocols have genuinely
// different setup needs; rather than collapse them into one
// either/or Card type, each protocol's mock lives next to its
// implementation. See mockcard.Card for the SCP11 counterpart.
//
// MockCard is for tests, examples, and local development only. It is
// not a reference implementation: it covers the subset of card
// behavior the SCP03 host code exercises, not arbitrary GlobalPlatform
// card behavior.
type MockCard struct {
	Keys StaticKeys

	// Session state (nil until EXTERNAL AUTHENTICATE succeeds).
	session *mockSession
}

type mockSession struct {
	keys *kdf.SessionKeys
	ch   *channel.SecureChannel
}

// NewMockCard creates an SCP03 mock card configured with the given
// static keys (typically scp03.DefaultKeys for factory-fresh card
// emulation, or a freshly generated set for testing key rotation).
//
// The returned MockCard is usable as a Transport via its Transport()
// method, which produces something satisfying transport.Transport.
func NewMockCard(keys StaticKeys) *MockCard {
	return &MockCard{Keys: keys}
}

// Transport returns a transport.Transport backed by this mock card.
// Multiple calls return independent MockTransport instances; the
// underlying card state is shared.
func (c *MockCard) Transport() *MockTransport {
	return &MockTransport{card: c}
}

func (c *MockCard) processAPDU(cmd *apdu.Command) (*apdu.Response, error) {
	// EXTERNAL AUTHENTICATE uses CLA=0x84 (secure messaging bit set)
	// but arrives before the session is fully established. Route it
	// explicitly before the secure messaging check.
	if cmd.INS == 0x82 { // EXTERNAL AUTHENTICATE
		return c.doExternalAuthenticate(cmd)
	}

	// Secure messaging active. Detection is class-aware (the SM bit
	// position differs between first-interindustry / proprietary
	// CLAs and further-interindustry CLAs); see channel.IsSecureMessaging.
	if c.session != nil && c.session.ch != nil && channel.IsSecureMessaging(cmd.CLA) {
		return c.processSecure(cmd)
	}

	switch cmd.INS {
	case 0xA4: // SELECT
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0x50: // INITIALIZE UPDATE
		return c.doInitializeUpdate(cmd)
	case 0xCA: // GET DATA — allow tag 0x66 (CRD) unauthenticated;
		// real cards typically permit CRD probe before any session.
		// Other tags require secure messaging.
		if cmd.P1 == 0x00 && cmd.P2 == 0x66 {
			return c.doGetData(cmd.P1, cmd.P2)
		}
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil // security status not satisfied
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

func (c *MockCard) doInitializeUpdate(cmd *apdu.Command) (*apdu.Response, error) {
	if len(cmd.Data) != 8 {
		return &apdu.Response{SW1: 0x6A, SW2: 0x80}, nil
	}
	hostChallenge := cmd.Data

	// Generate card challenge
	cardChallenge := make([]byte, 8)
	if _, err := rand.Read(cardChallenge); err != nil {
		return nil, err
	}

	// Key diversification data (10 bytes, mock)
	keyDivData := make([]byte, 10)
	_, _ = rand.Read(keyDivData)

	// Derive session keys
	kdfContext := make([]byte, 0, 16)
	kdfContext = append(kdfContext, hostChallenge...)
	kdfContext = append(kdfContext, cardChallenge...)

	keyLen := len(c.Keys.ENC)

	senc, err := deriveSCP03Key(c.Keys.ENC, derivConstSENC, kdfContext, keyLen)
	if err != nil {
		return nil, err
	}
	smac, err := deriveSCP03Key(c.Keys.MAC, derivConstSMAC, kdfContext, keyLen)
	if err != nil {
		return nil, err
	}
	srmac, err := deriveSCP03Key(c.Keys.MAC, derivConstSRMAC, kdfContext, keyLen)
	if err != nil {
		return nil, err
	}

	// Calculate card cryptogram (using S-MAC per GP SCP03 spec)
	cardCryptogram, err := calculateCryptogram(smac, derivConstCardCrypto, kdfContext, 8)
	if err != nil {
		return nil, err
	}

	// Store session state for EXTERNAL AUTHENTICATE
	c.session = &mockSession{
		keys: &kdf.SessionKeys{
			SENC:     senc,
			SMAC:     smac,
			SRMAC:    srmac,
			DEK:      make([]byte, keyLen),
			MACChain: make([]byte, 16),
		},
	}

	// Also store context + smac for cryptogram verification in EXTERNAL AUTH
	c.session.keys.Receipt = smac // Reuse receipt field to pass smac to extAuth

	// Build response: keyDivData(10) || keyVersion(1) || scpID(1) || iParam(1) ||
	//                  cardChallenge(8) || cardCryptogram(8) = 29 bytes
	var resp []byte
	resp = append(resp, keyDivData...)
	resp = append(resp, cmd.P1) // key version from command
	resp = append(resp, 0x03)   // SCP03
	resp = append(resp, 0x70)   // i=0x70: C-MAC + C-DEC + R-MAC + R-ENC
	resp = append(resp, cardChallenge...)
	resp = append(resp, cardCryptogram...)

	// Store kdfContext for host cryptogram verification
	c.session.keys.DEK = kdfContext // Reuse DEK field temporarily

	return &apdu.Response{Data: resp, SW1: 0x90, SW2: 0x00}, nil
}

func (c *MockCard) doExternalAuthenticate(cmd *apdu.Command) (*apdu.Response, error) {
	if c.session == nil {
		return &apdu.Response{SW1: 0x69, SW2: 0x85}, nil
	}

	// Initialize the channel so we can verify the C-MAC.
	c.session.ch = channel.New(c.session.keys, channel.LevelFull)

	data := cmd.Data
	macSize := c.session.ch.MACSize()
	if len(data) < macSize+8 {
		c.session = nil
		return &apdu.Response{SW1: 0x6A, SW2: 0x80}, nil
	}

	// Verify C-MAC on the EXTERNAL AUTHENTICATE command.
	receivedMAC := data[len(data)-macSize:]
	payload := data[:len(data)-macSize]

	var macInput []byte
	macInput = append(macInput, c.session.ch.ExportMACChain()...)
	macInput = append(macInput, cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	macInput = append(macInput, byte(len(data)))
	macInput = append(macInput, payload...)

	expectedMAC, err := cmac.AESCMAC(c.session.keys.SMAC, macInput)
	if err != nil {
		c.session = nil
		return nil, err
	}
	if !constantTimeEqual(expectedMAC[:macSize], receivedMAC) {
		c.session = nil
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}
	c.session.ch.SetMACChain(expectedMAC)

	// EXTERNAL AUTHENTICATE carries the host cryptogram in cleartext plus C-MAC.
	hostCryptogram := payload

	// Verify host cryptogram.
	kdfContext := c.session.keys.DEK // Retrieved from temp storage
	smac := c.session.keys.Receipt   // Retrieved from temp storage (S-MAC key)
	keyLen := len(smac)

	expectedHC, err := calculateCryptogram(smac, derivConstHostCrypto, kdfContext, 8)
	if err != nil {
		c.session = nil
		return nil, err
	}

	if !constantTimeEqual(expectedHC, hostCryptogram) {
		c.session = nil
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}

	// Restore proper DEK and Receipt fields.
	c.session.keys.DEK = make([]byte, keyLen)
	c.session.keys.Receipt = nil

	return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
}

func (c *MockCard) processSecure(cmd *apdu.Command) (*apdu.Response, error) {
	sess := c.session
	if sess == nil || sess.ch == nil {
		return &apdu.Response{SW1: 0x69, SW2: 0x85}, nil
	}

	data := cmd.Data
	macSize := sess.ch.MACSize()
	if len(data) < macSize {
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}

	// Verify C-MAC
	receivedMAC := data[len(data)-macSize:]
	encData := data[:len(data)-macSize]

	var macInput []byte
	macInput = append(macInput, sess.ch.ExportMACChain()...)
	macInput = append(macInput, cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	macInput = append(macInput, byte(len(data)))
	macInput = append(macInput, encData...)

	expectedMAC, err := cmac.AESCMAC(sess.keys.SMAC, macInput)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(expectedMAC[:macSize], receivedMAC) {
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}
	sess.ch.SetMACChain(expectedMAC)

	// Decrypt
	var plainData []byte
	if len(encData) > 0 {
		plainData, err = sess.ch.DecryptCommand(encData)
		if err != nil {
			return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
		}
	} else {
		_, _ = sess.ch.DecryptCommand(nil)
	}

	// Process plain command
	plainResp, err := c.processPlain(cmd.INS, cmd.P1, cmd.P2, plainData)
	if err != nil {
		return nil, err
	}

	return sess.ch.WrapResponse(plainResp)
}

func (c *MockCard) processPlain(ins, p1, p2 byte, data []byte) (*apdu.Response, error) {
	switch ins {
	case 0xA4: // SELECT
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0xFD: // Echo (test)
		return &apdu.Response{Data: data, SW1: 0x90, SW2: 0x00}, nil
	case 0xCA: // GET DATA
		return c.doGetData(p1, p2)
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

// doGetData answers the small set of GET DATA tags the host code in
// this repo issues during smoke and integration tests:
//
//   - 0x0066 — Card Recognition Data (a synthetic GP 2.3.1 / SCP03
//     i=0x65 blob, same shape as the cardrecognition package's
//     test fixtures).
//   - 0x00E0 — Key Information Template (one C0 entry: KID=0x01,
//     KVN=0xFF, component {0x88: 0x10} — AES-128 marker).
//
// Other tags return 6A88 (reference data not found), matching real
// card behavior. The mock does not attempt to be exhaustive — it
// covers the GP §H.2 + §11.3.3.1 reads the host's Session methods
// (GetCardRecognitionData, GetKeyInformation) actually issue.
func (c *MockCard) doGetData(p1, p2 byte) (*apdu.Response, error) {
	tag := uint16(p1)<<8 | uint16(p2)
	switch tag {
	case 0x0066:
		return &apdu.Response{Data: append([]byte(nil), syntheticCRD...), SW1: 0x90, SW2: 0x00}, nil
	case 0x00E0:
		return &apdu.Response{Data: append([]byte(nil), syntheticKeyInfo...), SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil // reference data not found
	}
}

// syntheticCRD is the Card Recognition Data blob the mock returns
// for GET DATA tag 0x0066. Hand-assembled per GP Card Spec §H.2:
// outer 66 LL, inner 73 LL OID list, GP RID marker + GP version
// (1.2.840.114283.2.2.3.1 = 2.3.1) + SCP info OID
// (1.2.840.114283.4.3.65 = SCP03 i=0x65). Same shape as the test
// fixture used by the cardrecognition package and #41 trace tests.
var syntheticCRD = []byte{
	0x66, 0x26,
	0x73, 0x24,
	0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
	0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
	0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x65,
}

// syntheticKeyInfo is a minimal Key Information Template the mock
// returns for GET DATA tag 0x00E0. It advertises one keyset:
//
//	E0 06              -- Key Information container, 6 bytes
//	  C0 04            -- one Key Information Template, 4 bytes
//	    01             -- KID = 0x01 (SCP03)
//	    FF             -- KVN = 0xFF (YubiKey factory)
//	    88 10          -- component pair (algorithm 0x88 = AES, length-id 0x10)
//
// Decoded by securitydomain.parseKeyInformation as:
//
//	KeyInfo{Reference: {ID: 0x01, Version: 0xFF}, Components: {0x88: 0x10}}
var syntheticKeyInfo = []byte{
	0xE0, 0x06,
	0xC0, 0x04, 0x01, 0xFF, 0x88, 0x10,
}

// MockTransport implements transport.Transport for the SCP03 mock card.
type MockTransport struct {
	card *MockCard
}

// Transmit dispatches a parsed APDU to the mock card and returns
// the parsed response. Implements transport.Transport.
func (t *MockTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return t.card.processAPDU(cmd)
}

// TransmitRaw parses the raw request bytes (short-form ISO 7816-4
// only — the SCP03 mock does not support extended-length APDUs)
// and dispatches them to the mock card. Implements
// transport.Transport.
func (t *MockTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	cmd := &apdu.Command{Le: -1}
	if len(raw) >= 4 {
		cmd.CLA = raw[0]
		cmd.INS = raw[1]
		cmd.P1 = raw[2]
		cmd.P2 = raw[3]
	}
	if len(raw) > 5 {
		lc := int(raw[4])
		if len(raw) >= 5+lc {
			cmd.Data = raw[5 : 5+lc]
		}
	}
	resp, err := t.card.processAPDU(cmd)
	if err != nil {
		return nil, err
	}
	return append(resp.Data, resp.SW1, resp.SW2), nil
}

// Close is a no-op for the SCP03 mock transport. The mock has no
// physical resource to release.
func (t *MockTransport) Close() error { return nil }
