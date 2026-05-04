// Package mockcard implements an in-memory GlobalPlatform Security
// Domain that speaks SCP11 (a, b, and c) and a slice of management
// commands. It exists so the SCP11 stack can be exercised end-to-end
// without hardware: handshake, OCE certificate upload, secure
// messaging, replay rejection, and Security Domain key/cert/data
// operations all flow through this fake card in tests.
//
// Scope:
//
//   - Card: SCP11-only mock. Configures with a P-256 key and an
//     auto-generated self-signed cert. Tests that need to vary the
//     card's behavior (variant, legacy receipt-omission) tweak the
//     exported fields before calling Transport().
//
//   - For SCP03 testing, see scp03.MockCard / scp03.NewMockCard /
//     scp03.MockTransport in the scp03 package. SCP03 and SCP11
//     have different setup requirements (pre-shared symmetric keys
//     vs. asymmetric key + certificate), so the mocks live in their
//     respective packages rather than being conflated into one
//     either/or configuration on a single Card type.
//
//   - Both mocks expose a Transport() method that returns something
//     satisfying transport.Transport, so test code at a layer above
//     transport (session-level, securitydomain-level) can be
//     parameterized over the mock if it needs to cover both
//     protocols.
//
// This package is intended for tests, examples, and local development
// only. It is not a reference implementation: it covers the subset
// of card behavior the SCP11 host code exercises, not arbitrary
// GlobalPlatform card behavior.
package mockcard

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
)

// Card simulates a GP Security Domain with SCP11b support.
type Card struct {
	mu sync.Mutex

	// Variant controls the SCP11 mode the card responds to.
	// 0=SCP11b (default), 1=SCP11a, 2=SCP11c.
	Variant int

	// LegacySCP11bNoReceipt models pre-Amendment-F-v1.4 SCP11b cards
	// that did not return a receipt in tag 0x86. Default false:
	// modern behavior (matches YubiKey 5.7.2+ and yubikit). Set true
	// only to exercise the legacy compatibility path.
	LegacySCP11bNoReceipt bool

	staticKey *ecdsa.PrivateKey
	certDER   []byte

	// OCE static public key, received via PERFORM SECURITY OPERATION.
	// Used for ShSes in SCP11a/c. Nil for SCP11b.
	oceStaticPub *ecdh.PublicKey

	// Accumulator for chained PSO data.
	psoBuf []byte

	session     *cardSession
	selectedAID []byte
	pivSelected bool
}

type cardSession struct {
	keys *kdf.SessionKeys
	ch   *channel.SecureChannel
}

var (
	aidSD  = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	aidPIV = []byte{0xA0, 0x00, 0x00, 0x03, 0x08}
)

// New creates a mock card with a fresh P-256 key and self-signed cert.
func New() (*Card, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mock SD Certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &Card{staticKey: key, certDER: der}, nil
}

// Transport returns a Transport backed by this card.
func (c *Card) Transport() *MockTransport {
	return &MockTransport{card: c}
}

func (c *Card) processAPDU(cmd *apdu.Command) (*apdu.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil && channel.IsSecureMessaging(cmd.CLA) {
		return c.processSecure(cmd)
	}

	// GP §4.8: After secure channel establishment, only SELECT, GET DATA,
	// and channel initiation commands are allowed in plaintext.
	// All other commands must use secure messaging (the SM bit set per
	// the CLA's class encoding — bit 0x04 for first-interindustry and
	// proprietary, bit 0x20 for further-interindustry).
	if c.session != nil {
		// Allow SELECT (0xA4) — needed to switch applets.
		// Reject everything else without the secure messaging bit.
		if cmd.INS != 0xA4 {
			return mkSW(0x6982), nil // Security status not satisfied
		}
	}

	switch cmd.INS {
	case 0xA4:
		return c.doSelect(cmd)
	case 0xCA:
		return c.doGetData(cmd)
	case 0x88: // INTERNAL AUTHENTICATE (SCP11b)
		return c.doInternalAuth(cmd)
	case 0x82: // EXTERNAL AUTHENTICATE (SCP11a/c - mutual auth)
		return c.doInternalAuth(cmd)
	case 0x2A: // PERFORM SECURITY OPERATION (OCE cert for SCP11a)
		return c.doPerformSecurityOp(cmd)
	default:
		return mkSW(0x6D00), nil
	}
}

func (c *Card) doSelect(cmd *apdu.Command) (*apdu.Response, error) {
	if bytesEq(cmd.Data, aidSD) {
		c.selectedAID = aidSD
		c.pivSelected = false
		return mkSW(0x9000), nil
	}
	if bytesEq(cmd.Data, aidPIV) {
		c.selectedAID = aidPIV
		c.pivSelected = true
		return mkSW(0x9000), nil
	}
	return mkSW(0x6A82), nil
}

func (c *Card) doGetData(cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.P1 != 0xBF || cmd.P2 != 0x21 {
		return mkSW(0x6A88), nil
	}
	certNode := tlv.Build(tlv.TagCertificate, c.certDER)
	storeNode := tlv.BuildConstructed(tlv.TagCertStore, certNode)
	return &apdu.Response{Data: storeNode.Encode(), SW1: 0x90, SW2: 0x00}, nil
}

func (c *Card) doPerformSecurityOp(cmd *apdu.Command) (*apdu.Response, error) {
	// Accumulate certificate data. Chained commands have CLA|=0x10.
	c.psoBuf = append(c.psoBuf, cmd.Data...)

	isChained := cmd.CLA&0x10 != 0
	if isChained {
		return mkSW(0x9000), nil // More data expected
	}

	// Final chunk received. Parse the complete certificate.
	certData := c.psoBuf
	c.psoBuf = nil

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		// Not a valid cert — accept anyway for mock flexibility.
		return mkSW(0x9000), nil
	}
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return mkSW(0x6A80), nil
	}
	ecdhPub, err := ecPub.ECDH()
	if err != nil {
		return mkSW(0x6A80), nil
	}
	c.oceStaticPub = ecdhPub
	return mkSW(0x9000), nil
}

func (c *Card) doInternalAuth(cmd *apdu.Command) (*apdu.Response, error) {
	nodes, err := tlv.Decode(cmd.Data)
	if err != nil {
		return mkSW(0x6A80), nil
	}

	epkNode := tlv.Find(nodes, tlv.TagEphPubKey)
	if epkNode == nil || len(epkNode.Value) != 65 {
		return mkSW(0x6A80), nil
	}

	oceEphPub, err := ecdh.P256().NewPublicKey(epkNode.Value)
	if err != nil {
		return mkSW(0x6A80), nil
	}

	cardEphKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	cardStaticECDH, err := c.staticKey.ECDH()
	if err != nil {
		return nil, err
	}

	shSee, err := cardEphKey.ECDH(oceEphPub)
	if err != nil {
		return nil, err
	}
	// ShSes: depends on variant.
	// SCP11b: ECDH(SK.SD, ePK.OCE) — card static against OCE ephemeral
	// SCP11a/c: ECDH(SK.SD, PK.OCE) — card static against OCE static (from cert)
	var shSesTarget *ecdh.PublicKey
	if c.Variant != 0 && c.oceStaticPub != nil {
		shSesTarget = c.oceStaticPub // SCP11a/c: OCE static public key
	} else {
		shSesTarget = oceEphPub // SCP11b: reuse OCE ephemeral
	}
	shSes, err := cardStaticECDH.ECDH(shSesTarget)
	if err != nil {
		return nil, err
	}

	keys, err := kdf.DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, nil)
	if err != nil {
		return nil, err
	}

	cardEphPubTLV := tlv.Build(tlv.TagEphPubKey, cardEphKey.PublicKey().Bytes())
	var kaData []byte
	kaData = append(kaData, cmd.Data...)
	kaData = append(kaData, cardEphPubTLV.Encode()...)
	receipt, err := kdf.ComputeReceipt(keys.Receipt, kaData)
	if err != nil {
		return nil, err
	}

	// SCP11b modern (Amendment F v1.4 / YubiKey 5.7.2+): macChain
	//   seeds from receipt, receipt included in response.
	// SCP11b legacy (pre-Amendment-F-v1.4): macChain seeds from
	//   zeros, no receipt in response. Modeled by LegacySCP11bNoReceipt.
	// SCP11a/c: macChain seeds from receipt, receipt included.
	includeReceipt := !(c.Variant == 0 && c.LegacySCP11bNoReceipt)
	if includeReceipt {
		keys.MACChain = make([]byte, len(receipt))
		copy(keys.MACChain, receipt)
	} else {
		keys.MACChain = make([]byte, 16)
	}
	c.session = &cardSession{
		keys: keys,
		ch:   channel.New(keys, channel.LevelFull),
	}

	// Build response.
	var respData []byte
	respData = append(respData, cardEphPubTLV.Encode()...)
	if includeReceipt {
		respData = append(respData, tlv.Build(tlv.TagReceipt, receipt).Encode()...)
	}

	return &apdu.Response{Data: respData, SW1: 0x90, SW2: 0x00}, nil
}

func (c *Card) processSecure(cmd *apdu.Command) (*apdu.Response, error) {
	sess := c.session
	if sess == nil {
		return mkSW(0x6985), nil
	}

	data := cmd.Data
	macSize := sess.ch.MACSize()
	if len(data) < macSize {
		return mkSW(0x6982), nil
	}

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
	if !ctEq(expectedMAC[:macSize], receivedMAC) {
		return mkSW(0x6982), nil
	}
	sess.ch.SetMACChain(expectedMAC)

	var plainData []byte
	if len(encData) > 0 {
		plainData, err = sess.ch.DecryptCommand(encData)
		if err != nil {
			return mkSW(0x6982), nil
		}
	} else {
		_, _ = sess.ch.DecryptCommand(nil)
	}

	plainCmd := &apdu.Command{
		CLA: channel.ClearSecureMessagingCLA(cmd.CLA), INS: cmd.INS, P1: cmd.P1, P2: cmd.P2,
		Data: plainData, Le: -1,
	}
	plainResp, err := c.processPlain(plainCmd)
	if err != nil {
		return nil, err
	}

	return sess.ch.WrapResponse(plainResp)
}

func (c *Card) processPlain(cmd *apdu.Command) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4:
		return c.doSelect(cmd)
	case 0xFD: // Echo for testing
		return &apdu.Response{Data: cmd.Data, SW1: 0x90, SW2: 0x00}, nil
	case 0x47: // PIV GENERATE KEY
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		pub := make([]byte, 65)
		pub[0] = 0x04
		_, _ = rand.Read(pub[1:])
		return &apdu.Response{Data: pub, SW1: 0x90, SW2: 0x00}, nil
	default:
		return mkSW(0x6D00), nil
	}
}

// --- MockTransport ---

// MockTransport implements transport.Transport.
type MockTransport struct {
	card   *Card
	closed bool
}

// Transmit dispatches a parsed APDU to the mock card and returns
// the parsed response. Implements transport.Transport.
func (t *MockTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if t.closed {
		return nil, errors.New("transport closed")
	}
	return t.card.processAPDU(cmd)
}

// TransmitRaw parses raw request bytes (short or extended ISO 7816-4
// form) via parseRaw and dispatches them to the mock card.
// Implements transport.Transport.
func (t *MockTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	if t.closed {
		return nil, errors.New("transport closed")
	}
	resp, err := t.card.processAPDU(parseRaw(raw))
	if err != nil {
		return nil, err
	}
	return append(resp.Data, resp.SW1, resp.SW2), nil
}

// Close marks the transport closed; subsequent Transmit / TransmitRaw
// calls return an error. The underlying mock card is not destroyed —
// a fresh transport can be obtained from the same card.
func (t *MockTransport) Close() error { t.closed = true; return nil }

// --- Helpers ---

func mkSW(code uint16) *apdu.Response {
	return &apdu.Response{SW1: byte(code >> 8), SW2: byte(code)}
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ctEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// parseRaw decodes a wire-format APDU (ISO 7816-4) into an apdu.Command.
// Handles both short and extended length encoding:
//
//   short:    CLA INS P1 P2 [Lc Data ...] [Le]
//             Lc is 1 byte (1-255), Le is 1 byte (0 means 256).
//
//   extended: CLA INS P1 P2 [00 Lc_hi Lc_lo Data ...] [Le_hi Le_lo]
//             Lc is 2 bytes after a 0x00 marker (1-65535).
//             Le, when present, is the trailing 2 bytes (no marker
//             since the extended marker was already consumed).
//
// An earlier version handled only short encoding, which silently
// dropped the data field of any extended-length command — a real
// problem for SCP11a OCE certificate uploads (~300 byte certs use
// extended length) and any other large-payload command. The mock
// would receive an empty data field, fail to populate state, and
// drift out of sync with the host's protocol expectation.
func parseRaw(raw []byte) *apdu.Command {
	if len(raw) < 4 {
		return &apdu.Command{INS: 0xFF}
	}
	cmd := &apdu.Command{CLA: raw[0], INS: raw[1], P1: raw[2], P2: raw[3], Le: -1}

	// No payload, possibly Le-only:
	switch len(raw) {
	case 4:
		return cmd // header only
	case 5:
		// CLA INS P1 P2 Le (short)
		cmd.Le = int(raw[4])
		if cmd.Le == 0 {
			cmd.Le = 256
		}
		return cmd
	case 7:
		// Could be CLA INS P1 P2 00 Le_hi Le_lo (extended Le, no data).
		if raw[4] == 0x00 {
			cmd.ExtendedLength = true
			cmd.Le = int(raw[5])<<8 | int(raw[6])
			if cmd.Le == 0 {
				cmd.Le = 65536
			}
			return cmd
		}
	}

	// Short encoding with data: byte 4 is non-zero Lc.
	if raw[4] != 0x00 {
		lc := int(raw[4])
		if len(raw) < 5+lc {
			return cmd // truncated; mockcard doesn't try to recover
		}
		cmd.Data = raw[5 : 5+lc]
		// Optional trailing Le.
		if len(raw) == 5+lc+1 {
			cmd.Le = int(raw[5+lc])
			if cmd.Le == 0 {
				cmd.Le = 256
			}
		}
		return cmd
	}

	// Extended encoding with data: 00 Lc_hi Lc_lo at bytes 4..6.
	if len(raw) < 7 {
		return cmd // header + extended marker incomplete
	}
	cmd.ExtendedLength = true
	lc := int(raw[5])<<8 | int(raw[6])
	if len(raw) < 7+lc {
		return cmd
	}
	cmd.Data = raw[7 : 7+lc]
	// Optional trailing extended Le (2 bytes, no marker — the 0x00
	// at byte 4 already declared extended-length encoding).
	if len(raw) == 7+lc+2 {
		cmd.Le = int(raw[7+lc])<<8 | int(raw[7+lc+1])
		if cmd.Le == 0 {
			cmd.Le = 65536
		}
	}
	return cmd
}
