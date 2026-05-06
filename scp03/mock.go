package scp03

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
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

	// recorded captures the post-decryption shape of every
	// write-class APDU (PUT KEY, STORE DATA, etc.) that the mock
	// processed under secure messaging. Read-only commands and
	// pre-handshake commands are not recorded.
	recorded []RecordedAPDU

	// chainBuffer accumulates data fields from a sequence of ISO
	// 7816-4 §5.1.1 chained APDUs (CLA bit b5 = 0x10) until the
	// final chunk arrives. The chained APDUs share INS/P1/P2; we
	// concatenate the data and process once at the final chunk.
	// This mirrors what real cards do at the transport layer
	// before secure messaging is even applied.
	//
	// Modeling chaining at the mock is load-bearing for
	// regression coverage: the bug that motivated the
	// wrap-then-chain refactor (per-chunk SCP wrapping desyncing
	// the host MAC chain because the card sees one logical
	// command) is invisible if the mock dispatches each chained
	// chunk as if it were independent. With reassembly here, a
	// host that wraps each chunk separately fails MAC verification
	// at the assembled-command boundary, exactly like retail
	// hardware does.
	chainBuffer []byte
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
	// ISO 7816-4 §5.1.1 transport-level command chaining. Real cards
	// reassemble chained chunks BEFORE applying any application or
	// secure-messaging logic; we mirror that here. The chaining bit
	// (CLA b5 = 0x10) on a chunk says "more chunks follow"; clear
	// means "this is the final (or only) chunk." Intermediate
	// chunks return 9000 with no data — the card has buffered them
	// and is waiting for more. The final chunk is dispatched with
	// CLA bit cleared and the full concatenated data field.
	//
	// Modeling chaining at the mock is load-bearing for regression
	// coverage: the bug that motivated the wrap-then-chain refactor
	// (per-chunk SCP wrapping desyncing the host MAC chain because
	// the card sees one logical command) is invisible if the mock
	// dispatches each chained chunk as if it were independent. With
	// reassembly here, a host that wraps each chunk separately
	// fails C-MAC verification at the assembled-command boundary,
	// exactly like retail hardware does.
	if cmd.CLA&0x10 != 0 {
		c.chainBuffer = append(c.chainBuffer, cmd.Data...)
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	}
	if len(c.chainBuffer) > 0 {
		// Final chunk of a chained sequence. Reassemble: drop the
		// chaining bit (already clear on this chunk), concatenate
		// data, dispatch as one logical APDU. Reset the buffer
		// regardless of dispatch outcome — a partial chain
		// shouldn't bleed into the next command.
		fullData := append(c.chainBuffer, cmd.Data...) //nolint:gocritic // intentional: assembling chained payload
		c.chainBuffer = nil
		reassembled := &apdu.Command{
			CLA:            cmd.CLA, // chaining bit already clear on the final chunk
			INS:            cmd.INS,
			P1:             cmd.P1,
			P2:             cmd.P2,
			Data:           fullData,
			Le:             cmd.Le,
			ExtendedLength: cmd.ExtendedLength,
		}
		return c.dispatchReassembled(reassembled)
	}

	return c.dispatchReassembled(cmd)
}

// dispatchReassembled runs the post-reassembly APDU through the
// EXTERNAL-AUTH / secure-messaging / plain-INS dispatch table. Split
// out from processAPDU so chained and unchained APDUs go through the
// same code path once the chaining wrapper is removed.
func (c *MockCard) dispatchReassembled(cmd *apdu.Command) (*apdu.Response, error) {
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
	// Extended-format Lc encoding when the wrapped data exceeds
	// short-Lc capacity. Mirrors channel.SecureChannel.Wrap on the
	// host side (channel.go: "Extended APDUs must MAC the extended
	// length form, not byte(lc)"). After ISO 7816-4 §5.1.1 chain
	// reassembly the data field can be > 255 bytes even though the
	// individual on-wire chunks were short-form; the host MAC'd
	// once over the LOGICAL command using extended-format Lc, and
	// we have to follow suit here or the MAC won't match.
	if len(data) > 255 {
		if len(data) > 65535 {
			return &apdu.Response{SW1: 0x6A, SW2: 0x80}, nil // wrong length
		}
		macInput = append(macInput, 0x00, byte(len(data)>>8), byte(len(data)))
	} else {
		macInput = append(macInput, byte(len(data)))
	}
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
	case 0xE2, 0xE4:
		// STORE DATA (0xE2), DELETE KEY (0xE4) — the OCE-write
		// commands the bootstrap-oce CLI issues. The mock records
		// each write so tests can assert the host sent the right
		// shape; the response is unconditionally 9000 because
		// validating wire format is the securitydomain package's
		// job, not the mock's. (The mock does not persist anything
		// — a follow-up GET DATA against the same key reference
		// will not return what was just PUT.)
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0xD8:
		// PUT KEY (GP §11.8). Three flavors land here, each with a
		// different response shape. We parse the body to choose the
		// right one rather than blindly returning 9000-with-empty-
		// body — the SCP03 key-set flavor expects the card to echo
		// back KVN || KCV_enc || KCV_mac || KCV_dek, and the
		// library's Session.PutSCP03Key checks that response with
		// ErrChecksum on mismatch.
		//
		// Body distinguisher: the SCP03 AES key-set body starts with
		// the new KVN byte and is followed by Tlv(0x88, encrypted)
		// + 0x03 + KCV repeated three times. EC private (0xA1/0xB1)
		// and EC public (0xB0) bodies have different leading tags
		// and don't carry the KVN-then-tag pattern, so a single byte
		// of lookahead is enough to disambiguate.
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		if resp, ok := c.synthesizeSCP03KeySetPutKeyResponse(data); ok {
			return &apdu.Response{Data: resp, SW1: 0x90, SW2: 0x00}, nil
		}
		// EC public / EC private PUT KEY: 9000 with no body, which
		// is what real cards return and what PutECPublicKey /
		// PutECPrivateKey expect.
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0xF0:
		// SET STATUS (GP §11.1.10). Recorded for wire-shape
		// inspection. The mock does not persist a lifecycle byte
		// — there's no GET STATUS handler here either; tests that
		// need pre/post lifecycle state should use the mockcard
		// package's SCP11 mock, which DOES round-trip lifecycle.
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case 0xF1:
		// GENERATE EC KEY (Yubico extension). Unlike PUT KEY, this
		// returns response data: Tlv(0xB0, <65-byte uncompressed
		// SEC1 point>). The host parses that as the public half of
		// the keypair the card just generated. To exercise the
		// happy path in tests we synthesize a valid response by
		// generating a fresh P-256 key here and emitting its public
		// point — the mock discards the matching private key (it
		// has no notion of long-lived SD state, so there's nothing
		// to "store"). Tests that care about specific keys
		// generated by GENERATE KEY can either parse the response
		// out of the recorded transmit or override this method.
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		respData, err := synthesizeGenerateKeyResponse()
		if err != nil {
			// Crypto failure here would mean Go's stdlib RNG broke,
			// not anything the test can recover from. Return SW=6F00
			// (no precise diagnostic) so the test surfaces the
			// failure clearly rather than masking it as a parse
			// error downstream.
			return &apdu.Response{SW1: 0x6F, SW2: 0x00}, nil
		}
		return &apdu.Response{Data: respData, SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

// RecordedAPDU is the post-decryption shape of a write-class APDU
// that reached the SCP03 mock through secure messaging. Useful in
// tests that need to confirm the CLI issued the right sequence
// (e.g. "did bootstrap-oce send a PUT KEY before STORE DATA?")
// without depending on wire-byte equality.
type RecordedAPDU struct {
	INS  byte
	P1   byte
	P2   byte
	Data []byte
}

// Recorded returns a snapshot of the writes the mock has observed
// since New. The returned slice is a copy; mutating it does not
// affect future recordings.
func (c *MockCard) Recorded() []RecordedAPDU {
	out := make([]RecordedAPDU, len(c.recorded))
	copy(out, c.recorded)
	return out
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

// TrustBoundary reports TrustBoundaryUnknown for the same reasons
// the mockcard MockTransport does: this is a test fixture, not a
// physical transport, and callers gating raw-mode operations
// should refuse it by default.
func (t *MockTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// synthesizeGenerateKeyResponse builds a wire-shape response that
// Session.GenerateECKey's parser accepts: Tlv(0xB0, <65-byte SEC1
// uncompressed P-256 point>). The matching private key is discarded
// because MockCard does not persist SD state — a subsequent
// authenticated read against the supposed new KID will not work, but
// the GENERATE KEY round-trip itself does.
//
// Tests that need to drive a specific keypair through GENERATE KEY
// can replace this stub by wrapping the transport returned by
// Transport(); for the common case (CLI hitting a synthetic card and
// asserting the public key parses) the random keypair is enough.
func synthesizeGenerateKeyResponse() ([]byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	point := priv.PublicKey().Bytes() // 65-byte uncompressed SEC1 (0x04 || X || Y)
	return tlv.Build(tlv.Tag(0xB0), point).Encode(), nil
}

// synthesizeSCP03KeySetPutKeyResponse parses an SCP03 AES key-set
// PUT KEY body and produces the response a real card would emit:
//
//	KVN || KCV_enc || KCV_mac || KCV_dek    (1 + 3 + 3 + 3 = 10 bytes)
//
// Returns (response, true) when the body matches the SCP03 key-set
// shape; (nil, false) when it doesn't (e.g. EC private or public key
// PUT KEY, which use different tag layouts and don't carry KCVs in
// the body).
//
// Body shape from securitydomain.putKeySCP03Cmd, which the GP spec
// (§11.8.2.3) anchors:
//
//	byte 0: KVN
//	repeated 3 times:
//	  byte: 0x88                    (key-type tag = AES)
//	  byte: 0x10                    (length = 16, AES-128)
//	  16 bytes: encrypted_key       (AES-CBC(static-DEK, key))
//	  byte: 0x03                    (KCV length)
//	  3 bytes: KCV                  (host-computed; the card
//	                                 recomputes after decryption)
//
// We faithfully recompute the KCVs after decryption rather than
// echoing back the host's. A real card would catch a mismatch
// between the encrypted-key payload and the host's KCV claim, and
// the mock should match that behavior so tests for adversarial
// transmission paths produce the same result against the mock as
// against a real card.
//
// Decryption: AES-CBC under c.Keys.DEK (the static DEK, the third
// component of the SCP03 StaticKeys triple) with a zero IV. The
// 16-byte ciphertext is exactly one AES block, so PKCS#7 padding
// from the encryption side adds a second block of all-0x10 bytes
// — but the library's encryption produces a 16-byte ciphertext
// (single block, no padding written) for AES-128 keys. We mirror
// that: decrypt 16 bytes, no unpad, the result is the new key.
//
// Returns (nil, false) on any structural problem: too-short body,
// wrong tag, bad length byte, missing KCV byte. The caller falls
// back to the EC-key path, which returns 9000-empty — that matches
// the strict semantics of "this isn't an SCP03 key-set body."
func (c *MockCard) synthesizeSCP03KeySetPutKeyResponse(body []byte) ([]byte, bool) {
	// Minimum size: 1 (KVN) + 3 × (1 tag + 1 len + 16 enc + 1 kcv-len + 3 kcv) = 1 + 66 = 67 bytes.
	const wantLen = 1 + 3*(1+1+16+1+3)
	if len(body) < wantLen {
		return nil, false
	}
	// The static DEK is what the host used to encrypt; we use the
	// same to decrypt. If the mock was constructed without a DEK
	// (zero-length), this is not an SCP03-key-set-capable mock and
	// we fall back to the EC path.
	if len(c.Keys.DEK) != 16 {
		return nil, false
	}

	kvn := body[0]
	resp := make([]byte, 0, 1+3*3)
	resp = append(resp, kvn)

	off := 1
	for k := 0; k < 3; k++ {
		// Tag must be 0x88 (keyTypeAES).
		if body[off] != 0x88 {
			return nil, false
		}
		// Length must be 0x10 (16 bytes, AES-128).
		if body[off+1] != 0x10 {
			return nil, false
		}
		encryptedKey := body[off+2 : off+2+16]
		off += 2 + 16
		// KCV length must be 0x03.
		if body[off] != 0x03 {
			return nil, false
		}
		// Skip the host's claimed KCV; we recompute.
		off += 1 + 3

		// Decrypt the 16-byte block under static DEK with a zero IV.
		// PutKeySCP03Cmd uses aesCBCEncrypt which PKCS#7-pads input,
		// but a 16-byte AES key fits in one block — pkcs7Pad would
		// in principle add a 16-byte all-0x10 padding block, BUT
		// the library code only emits the FIRST block of the
		// ciphertext for AES-128 (the encryptedKey is exactly the
		// 16-byte CBC encryption of the key). So we decrypt exactly
		// one block, no unpad.
		newKey := make([]byte, 16)
		decryptOneAESBlock(c.Keys.DEK, encryptedKey, newKey)
		// KCV = AES-CBC(new_key, IV=0, ones_block)[:3].
		kcvCipher := make([]byte, 16)
		ones := make([]byte, 16)
		for i := range ones {
			ones[i] = 0x01
		}
		decryptOneAESBlockWithEncrypt(newKey, ones, kcvCipher)
		resp = append(resp, kcvCipher[:3]...)
	}
	return resp, true
}

// decryptOneAESBlock decrypts a single 16-byte block under the
// AES-128 key with a zero IV (CBC mode degenerates to ECB for one
// block when IV is zero, but we use the CBC API for symmetry with
// the library encryption side that uses crypto/cipher.NewCBCDecrypter).
func decryptOneAESBlock(key, ciphertext, out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(out, ciphertext)
}

// decryptOneAESBlockWithEncrypt is intentionally named "with
// encrypt" because the KCV computation per GP Card Specification
// is the ENCRYPTION of an all-ones block under the candidate key;
// the result's first 3 bytes are the KCV. Using the CBC encrypter
// (zero IV) for one block matches the library's computeAESKCV.
func decryptOneAESBlockWithEncrypt(key, plaintext, out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := make([]byte, aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(out, plaintext)
}
