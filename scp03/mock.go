package scp03

import (
	"context"
	"crypto/rand"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
)

// MockCard simulates a GP card supporting SCP03 for end-to-end testing.
type MockCard struct {
	Keys StaticKeys

	// Session state (nil until EXTERNAL AUTHENTICATE succeeds).
	session *mockSession
}

type mockSession struct {
	keys *kdf.SessionKeys
	ch   *channel.SecureChannel
}

// NewMockCard creates a mock card with the given static keys.
func NewMockCard(keys StaticKeys) *MockCard {
	return &MockCard{Keys: keys}
}

// Transport returns a transport backed by this mock card.
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

	// Secure messaging active
	if c.session != nil && c.session.ch != nil && cmd.CLA&0x04 != 0 {
		return c.processSecure(cmd)
	}

	switch cmd.INS {
	case 0xA4: // SELECT
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0x50: // INITIALIZE UPDATE
		return c.doInitializeUpdate(cmd)
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

	// Calculate card cryptogram
	cardCryptogram, err := calculateCryptogram(senc, derivConstCardCrypto, kdfContext, keyLen)
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

	// Also store context + senc for cryptogram verification in EXTERNAL AUTH
	c.session.keys.Receipt = senc // Reuse receipt field to pass senc to extAuth

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
	if len(data) < channel.MACLen+8 {
		c.session = nil
		return &apdu.Response{SW1: 0x6A, SW2: 0x80}, nil
	}

	// Verify C-MAC on the EXTERNAL AUTHENTICATE command.
	receivedMAC := data[len(data)-channel.MACLen:]
	payload := data[:len(data)-channel.MACLen]

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
	if !constantTimeEqual(expectedMAC[:channel.MACLen], receivedMAC) {
		c.session = nil
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}
	c.session.ch.SetMACChain(expectedMAC)

	// Decrypt the payload to get the host cryptogram.
	var hostCryptogram []byte
	if len(payload) > 0 {
		hostCryptogram, err = c.session.ch.DecryptCommand(payload)
		if err != nil {
			c.session = nil
			return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
		}
	}

	// Verify host cryptogram.
	kdfContext := c.session.keys.DEK // Retrieved from temp storage
	senc := c.session.keys.Receipt   // Retrieved from temp storage
	keyLen := len(senc)

	expectedHC, err := calculateCryptogram(senc, derivConstHostCrypto, kdfContext, keyLen)
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
	if len(data) < channel.MACLen {
		return &apdu.Response{SW1: 0x69, SW2: 0x82}, nil
	}

	// Verify C-MAC
	receivedMAC := data[len(data)-channel.MACLen:]
	encData := data[:len(data)-channel.MACLen]

	var macInput []byte
	macInput = append(macInput, sess.ch.ExportMACChain()...)
	macInput = append(macInput, cmd.CLA, cmd.INS, cmd.P1, cmd.P2)
	macInput = append(macInput, byte(len(data)))
	macInput = append(macInput, encData...)

	expectedMAC, err := cmac.AESCMAC(sess.keys.SMAC, macInput)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(expectedMAC[:channel.MACLen], receivedMAC) {
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
	plainResp, err := c.processPlain(cmd.INS, plainData)
	if err != nil {
		return nil, err
	}

	return sess.ch.WrapResponse(plainResp)
}

func (c *MockCard) processPlain(ins byte, data []byte) (*apdu.Response, error) {
	switch ins {
	case 0xA4: // SELECT
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0xFD: // Echo (test)
		return &apdu.Response{Data: data, SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

// MockTransport implements transport.Transport for the SCP03 mock card.
type MockTransport struct {
	card *MockCard
}

func (t *MockTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return t.card.processAPDU(cmd)
}

func (t *MockTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
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

func (t *MockTransport) Close() error { return nil }

