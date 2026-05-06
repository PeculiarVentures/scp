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

	// certStore holds cert chains written via STORE DATA tag
	// 0xBF21 + key reference. Read back via GET DATA tag 0xBF21
	// + the same key reference. The key is the wire-encoded
	// (KID<<8 | KVN) for a small fixed-size hash key.
	//
	// The mock previously had no cert-store persistence — STORE
	// DATA was a record-and-9000 no-op and GET DATA tag 0xBF21
	// returned 6A88. That's fine for tests that only assert the
	// write APDU shape, but it blocks any test that wants to
	// round-trip a chain (write then read on the same mock
	// instance) — including the SCP11 cert-store flow used by
	// bootstrap-scp11a-sd's chain validation step. Fixing the
	// gap here makes the mock a faithful simulator of the
	// cert-store life cycle, not just an APDU recorder.
	//
	// Stored bytes are the raw concatenated DER from the
	// BF21{...} payload — we don't re-wrap on read because the
	// library's parseCertificates accepts both the BF21-wrapped
	// and bare 0x30-prefixed concatenated DER shapes. We return
	// BF21{stored} to match what storeCertificatesData put on
	// the wire originally; that round-trips cleanly through
	// parseCertificates on the way back.
	certStore map[uint16][]byte

	// inventory tracks installed keys and shows up in the GET
	// DATA tag 0x00E0 response (Key Information Template).
	// Default state is one entry: the factory SCP03 key set at
	// 0x01/0xFF, AES-128 — matching what the static
	// syntheticKeyInfo blob used to advertise unconditionally.
	//
	// PUT KEY registers at (KID, new_KVN); DELETE KEY removes
	// the targeted entries; GENERATE EC KEY registers the
	// generated keypair. GET DATA tag 0x00E0 builds the response
	// from this map, replacing the previously-static blob.
	//
	// Why this matters: tests that want to verify post-install
	// state via sd keys list need the mock's KIT response to
	// reflect what was just written. Without this, the mock
	// returned the same fixed blob regardless of what had been
	// installed — fine for APDU-emission-only tests, broken for
	// round-trip workflow tests.
	//
	// Map key is (KID<<8 | KVN), same compact form as certStore.
	// Entries are intentionally simple — a (KID, KVN) tuple plus
	// a Components byte slice that gets emitted into the C0
	// template body verbatim. We don't model lifecycle,
	// privileges, or other registry fields here; tests that need
	// those would use the GP §11.4.2 GET STATUS path which the
	// mock still doesn't support (that's a separate gap, called
	// out in the design doc — fix when a caller surfaces it).
	inventory map[uint16]mockKeyEntry
}

// mockKeyEntry represents one installed key in the mock's
// inventory. Intentionally minimal: the (KID, KVN) tuple plus a
// Components byte slice that gets emitted into the C0 template
// body during GET DATA tag 0x00E0 response synthesis.
//
// Components is encoded as pairs of bytes where each pair is
// (algorithm_tag, length_id) per GP §11.3.3.1. Common values:
//
//	{0x88, 0x10}             -- AES-128 (SCP03)
//	{0x88, 0x18}             -- AES-192 (SCP03 192-bit variant)
//	{0x88, 0x20}             -- AES-256 (SCP03 256-bit variant)
//	{0x88, 0x88}             -- ECC, P-256 (SCP11 family)
//
// These match the yubikit-go test fixtures and the values our own
// parseKeyInformation expects to round-trip. Future component
// shapes (multiple pairs per template, additional algorithm tags)
// are accepted by the parser but not currently emitted by this
// mock.
type mockKeyEntry struct {
	KID        byte
	KVN        byte
	Components []byte
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
//
// Initial inventory: one entry for the SCP03 key set at KID=0x01,
// KVN=0xFF, components {0x88, 0x10} (AES-128). This matches what
// the previously-static syntheticKeyInfo blob advertised — every
// test that asserted "GET DATA tag E0 returns a KIT showing the
// factory key" continues to pass without modification. PUT KEY,
// DELETE KEY, and GENERATE EC KEY operations mutate the inventory
// from this baseline.
//
// To start with a different inventory (e.g. a card simulating a
// post-rotation state), call MockCard.SetInventory after
// construction.
func NewMockCard(keys StaticKeys) *MockCard {
	c := &MockCard{Keys: keys}
	c.inventory = make(map[uint16]mockKeyEntry)
	c.registerKey(0x01, 0xFF, []byte{0x88, 0x10})
	return c
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
	case 0xCA: // GET DATA — pre-session reads of operator-discoverable
		// data objects. Real YubiKeys permit two paths without
		// authentication:
		//
		//   - tag 0x0066 (Card Recognition Data per GP §H.2): the
		//     pre-handshake "what kind of card is this" probe
		//     scpctl uses for unauthenticated identification.
		//   - tag 0x5FC1 (sub-tag 09 = firmware version): the
		//     YubiKey version object the profile package's Probe
		//     reads to distinguish YubiKey from standard GP
		//     cards. Standard GP cards return 6A88 for this tag;
		//     since this mock is YubiKey-shaped, it answers as a
		//     YubiKey would.
		//
		// Other GET DATA tags require secure messaging and get
		// SW=6982 here.
		if cmd.P1 == 0x00 && cmd.P2 == 0x66 {
			return c.doGetData(cmd.P1, cmd.P2, cmd.Data)
		}
		if cmd.P1 == 0x5F && cmd.P2 == 0xC1 {
			return c.doGetData(cmd.P1, cmd.P2, cmd.Data)
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
		return c.doGetData(p1, p2, data)
	case 0xE2, 0xE4:
		// STORE DATA (0xE2), DELETE KEY (0xE4) — the OCE-write
		// commands the bootstrap-oce CLI issues. The mock records
		// each write so tests can assert the host sent the right
		// shape; the response is unconditionally 9000 because
		// validating wire format is the securitydomain package's
		// job, not the mock's. (Most STORE DATA shapes are pure
		// recording — the mock has no persistence for allowlists
		// or CA-issuer SKIs because no test currently rounds them
		// trip via GET DATA against the same mock instance.)
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		if ins == 0xE2 {
			// Cert-chain STORE DATA is the one shape we DO persist:
			// it round-trips with GET DATA tag BF21 in the same
			// session, which is the bootstrap-scp11a-sd chain-
			// validation flow. tryStoreCertChain returns true when
			// the body matches A6{83{KID,KVN}} || BF21{certs}; for
			// other STORE DATA shapes (allowlist, CA issuer, etc.)
			// it returns false and we fall through to plain 9000.
			c.tryStoreCertChain(data)
		}
		if ins == 0xE4 {
			// DELETE KEY: parse D0{KID} and/or D2{KVN} from the
			// body and remove matching inventory entries. Real
			// cards are idempotent for "delete a key that doesn't
			// exist" — they return 9000 either way; the mock
			// matches that behavior. Only the inventory-side
			// effect is conditional on the entry actually existing.
			c.applyDeleteKeyToInventory(p2, data)
		}
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
		// Inventory side-effect: register the newly installed key
		// (or replace an existing entry) before formulating the
		// response. Errors here are non-fatal — the inventory
		// model is a best-effort tracker, not a constraint on
		// what bodies the mock accepts.
		c.applyPutKeyToInventory(p1, p2, data)
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
		//
		// Inventory side-effect: register at (P2 & 0x7F, P1 if
		// non-zero else body[0]) with EC components. The library's
		// generateECKeyCmd places the new KVN in P1; we also fall
		// through to body[0] for safety in case future surface
		// shifts to a body-carried KVN (matches the PUT KEY EC
		// path's convention).
		c.recorded = append(c.recorded, RecordedAPDU{INS: ins, P1: p1, P2: p2, Data: append([]byte(nil), data...)})
		c.applyGenerateKeyToInventory(p1, p2, data)
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
// this repo issues during smoke and integration tests. requestBody
// is the GET DATA body (typically empty for tag-only reads, but
// non-empty for tag BF21 which carries the key reference of the
// chain to fetch). Callers without a body pass nil.
func (c *MockCard) doGetData(p1, p2 byte, requestBody []byte) (*apdu.Response, error) {
	tag := uint16(p1)<<8 | uint16(p2)
	switch tag {
	case 0x0066:
		return &apdu.Response{Data: append([]byte(nil), syntheticCRD...), SW1: 0x90, SW2: 0x00}, nil
	case 0x00E0:
		// Key Information Template. Built dynamically from the
		// inventory map so post-install state shows up in
		// sd keys list output. Initial inventory is the factory
		// SCP03 key at 0x01/0xFF, which marshals to the same bytes
		// as the legacy syntheticKeyInfo blob — every existing
		// test that asserted "GET DATA tag E0 returns the factory
		// key" still passes unchanged.
		return &apdu.Response{Data: c.buildKeyInfoResponse(), SW1: 0x90, SW2: 0x00}, nil
	case 0xBF21:
		// Cert store read: parse key reference from request body,
		// look up against the persisted certStore map. The library
		// returns 6A88 for "no chain stored" via parseCertificates;
		// we mirror that exactly.
		stored, ok := c.lookupCertChain(requestBody)
		if !ok {
			return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil
		}
		return &apdu.Response{Data: stored, SW1: 0x90, SW2: 0x00}, nil
	case 0x5FC1:
		// YubiKey firmware version object (tag 5FC109). The
		// profile package's Probe sends GET DATA with P1=0x5F
		// P2=0xC1 and reads the response as raw
		// major.minor.patch — three bytes. Real YubiKey 5.x
		// hardware advertises this; standard GP cards return
		// 6A88 because the tag is a Yubico extension. The mock
		// is a YubiKey-shaped simulator, so it should answer
		// the way a YubiKey does: SW=9000 with three bytes.
		// Without this case, profile.Probe defaults to
		// StandardSDProfile against the mock, which then breaks
		// any test that exercises GenerateECKey through the
		// profile gate.
		//
		// Returning 5.7.1 specifically: the mock's behavior is
		// modeled on YubiKey 5.7.x firmware (SCP11 support,
		// AES-128 SCP03 key sets, etc.); 5.7.1 is the published
		// version that matches that surface. Operators reading
		// trace logs see a familiar version.
		return &apdu.Response{Data: []byte{5, 7, 1}, SW1: 0x90, SW2: 0x00}, nil
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

// tryStoreCertChain inspects a STORE DATA body for the cert-chain
// shape (A6{83{KID,KVN}} || BF21{cert_DER_concat}) and persists it
// to the cert store on hit. Returns true on hit, false on any other
// shape (allowlist, CA-issuer SKI, etc.) — the caller falls back to
// the plain record-and-9000 behavior for non-cert STORE DATA.
//
// We don't enforce the exact tag order or insist on no other tags
// being present; the parser walks top-level nodes and pairs the
// first A6 (control reference) with the first BF21 (cert store) it
// sees. This matches storeCertificatesData's emission order
// (A6 first, BF21 second) without breaking on potential future
// shapes that interleave additional tags.
//
// Persisting the BF21 *value* (the concatenated DER bytes) — not
// the wrapper — keeps the storage canonical. On read we re-wrap
// in BF21 so the response matches the on-the-wire shape that
// parseCertificates round-trips cleanly.
func (c *MockCard) tryStoreCertChain(body []byte) bool {
	nodes, err := tlv.Decode(body)
	if err != nil {
		return false
	}
	ref, refOK := extractKeyRefFromControlRef(nodes)
	if !refOK {
		return false
	}
	store := tlv.Find(nodes, tlv.Tag(0xBF21))
	if store == nil || len(store.Value) == 0 {
		return false
	}
	if c.certStore == nil {
		c.certStore = make(map[uint16][]byte)
	}
	c.certStore[refKey(ref)] = append([]byte(nil), store.Value...)
	return true
}

// lookupCertChain parses a key reference from a GET DATA tag BF21
// request body and returns the BF21-wrapped stored chain bytes if
// present. Returns (nil, false) if no chain is stored at that ref or
// the request body is malformed; caller surfaces this as 6A88, the
// same status real cards return when no cert is stored at the
// requested reference.
//
// We re-wrap the stored bytes in BF21 on read because that's what
// storeCertificatesData put on the wire originally and what the
// library's parseCertificates expects to round-trip. Keeping the
// store canonical (DER concat, no wrapper) and re-wrapping on read
// avoids redundant wrap/unwrap state in the storage map.
func (c *MockCard) lookupCertChain(reqBody []byte) ([]byte, bool) {
	if len(c.certStore) == 0 {
		return nil, false
	}
	nodes, err := tlv.Decode(reqBody)
	if err != nil {
		return nil, false
	}
	ref, ok := extractKeyRefFromControlRef(nodes)
	if !ok {
		return nil, false
	}
	stored, ok := c.certStore[refKey(ref)]
	if !ok {
		return nil, false
	}
	return tlv.Build(tlv.Tag(0xBF21), stored).Encode(), true
}

// keyRef holds (KID, KVN) in a small fixed-size struct usable as a
// map key. Unlike securitydomain.KeyReference this is package-local
// to avoid pulling securitydomain into scp03 (would create an import
// cycle: securitydomain imports scp03 already).
type keyRef struct {
	KID byte
	KVN byte
}

// refKey packs (KID, KVN) into a uint16 for use as a map key.
// MSB = KID, LSB = KVN. The compact form keeps the certStore map
// small even with many keys.
func refKey(r keyRef) uint16 {
	return uint16(r.KID)<<8 | uint16(r.KVN)
}

// extractKeyRefFromControlRef walks a TLV node list looking for
// A6 { 83 { KID, KVN } } and returns the parsed key reference.
// Returns (zero, false) if the shape doesn't match or 83's value
// isn't exactly two bytes.
//
// The control-reference tag (A6) wraps key-management TLVs
// throughout SCP11: storeCertificatesData, storeCaIssuerData, and
// buildKeyRefTLV all emit A6{83{KID,KVN}} as the address field.
// Centralizing the parser here means all three paths (store certs,
// store CA issuer, get certs) extract the ref the same way.
func extractKeyRefFromControlRef(nodes []*tlv.Node) (keyRef, bool) {
	ctrl := tlv.Find(nodes, tlv.Tag(0xA6))
	if ctrl == nil {
		return keyRef{}, false
	}
	keyID := tlv.Find(ctrl.Children, tlv.Tag(0x83))
	if keyID == nil || len(keyID.Value) != 2 {
		return keyRef{}, false
	}
	return keyRef{KID: keyID.Value[0], KVN: keyID.Value[1]}, true
}

// --- Inventory model: PUT KEY / DELETE KEY / GENERATE EC KEY
//     register and unregister entries; GET DATA tag 0x00E0 reads
//     them out as the Key Information Template the library expects.

// registerKey adds or replaces an entry in the inventory. Idempotent
// at the (KID, KVN) tuple level — re-registering an existing entry
// updates its components in place.
func (c *MockCard) registerKey(kid, kvn byte, components []byte) {
	if c.inventory == nil {
		c.inventory = make(map[uint16]mockKeyEntry)
	}
	c.inventory[uint16(kid)<<8|uint16(kvn)] = mockKeyEntry{
		KID:        kid,
		KVN:        kvn,
		Components: append([]byte(nil), components...),
	}
}

// unregisterKey removes a single (KID, KVN) entry. Idempotent —
// removing a non-existent entry is a no-op, matching real-card
// DELETE KEY semantics where deleting a key that isn't installed
// returns 9000 (success, no-op).
func (c *MockCard) unregisterKey(kid, kvn byte) {
	if c.inventory == nil {
		return
	}
	delete(c.inventory, uint16(kid)<<8|uint16(kvn))
}

// unregisterAllAtKVN removes every entry with the given KVN,
// regardless of KID. Used by DELETE KEY when only a KVN is
// specified — the real-card semantic for "delete the keyset at
// this version" affects all keys at that version (e.g. an SCP03
// keyset comprises ENC, MAC, DEK with the same KVN; deleting "the
// keyset" deletes all three).
func (c *MockCard) unregisterAllAtKVN(kvn byte) {
	for k, e := range c.inventory {
		if e.KVN == kvn {
			delete(c.inventory, k)
		}
	}
}

// unregisterAllAtKID removes every entry with the given KID,
// regardless of KVN. Used by DELETE KEY when only a KID is
// specified — semantic is "delete all versions of this key" which
// is rarer in practice but supported by the GP DELETE KEY surface.
func (c *MockCard) unregisterAllAtKID(kid byte) {
	for k, e := range c.inventory {
		if e.KID == kid {
			delete(c.inventory, k)
		}
	}
}

// SetInventory replaces the entire inventory. Useful for tests that
// want to start from a non-default state — e.g. simulating a card
// where the factory keys have been rotated and additional keys
// installed.
//
// Pass an empty slice to clear the inventory entirely. The mock
// will then advertise zero installed keys until something gets
// registered.
func (c *MockCard) SetInventory(entries []mockKeyEntry) {
	c.inventory = make(map[uint16]mockKeyEntry, len(entries))
	for _, e := range entries {
		c.inventory[uint16(e.KID)<<8|uint16(e.KVN)] = mockKeyEntry{
			KID:        e.KID,
			KVN:        e.KVN,
			Components: append([]byte(nil), e.Components...),
		}
	}
}

// applyPutKeyToInventory updates the inventory after a PUT KEY
// command lands. Three flavors:
//
//   - SCP03 AES key set (body starts with KVN, then tag 0x88):
//     register at (0x01, body[0]) with AES-128 components. If
//     P1 is non-zero, the existing keyset at (0x01, P1) is
//     unregistered first — that's the GP "replace" semantic.
//   - EC private (body starts with KVN, then tag 0xA1 or 0xB1):
//     register at (P2 & 0x7F, body[0]) with EC components.
//   - EC public / trust anchor (body starts with KVN, then tag 0xB0):
//     same registration as EC private.
//
// The inventory mutation is best-effort. A malformed body that
// can't be classified just leaves the inventory untouched; the
// APDU still records and the response still goes out. Tests that
// want to verify post-install inventory state should drive PUT
// KEY through the library's typed API, which produces well-formed
// bodies.
//
// The 0x80 bit on P2 is the "multiple keys in this command" flag
// per GP §11.8.2.2. We mask it off because the inventory tracks
// the KID itself, not the wire flag.
func (c *MockCard) applyPutKeyToInventory(p1, p2 byte, body []byte) {
	if len(body) < 2 {
		return
	}
	newKVN := body[0]
	firstTag := body[1]
	kid := p2 & 0x7F

	var components []byte
	switch firstTag {
	case 0x88: // AES key set (SCP03)
		// SCP03 always installs at KID=0x01 logically (the keyset
		// is one entry from the host's KIT view, regardless of
		// the three sub-KIDs ENC/MAC/DEK that the card creates
		// internally). We register at 0x01 ignoring the P2 KID
		// because for SCP03 the wire P2 also carries 0x01 with
		// the multi-key flag set.
		kid = 0x01
		// AES-128 only (16-byte key). The mock's
		// synthesizeSCP03KeySetPutKeyResponse already requires
		// the body length match an AES-128 keyset shape, so
		// bodies that get this far have been validated.
		components = []byte{0x88, 0x10}
	case 0xA1, 0xB1: // EC private (SCP11 SD slot installation)
		components = []byte{0x88, 0x88}
	case 0xB0: // EC public (CA/OCE trust anchor)
		components = []byte{0x88, 0x88}
	default:
		// Unknown PUT KEY shape: don't touch inventory, but don't
		// reject the APDU either (the response side already
		// handles the EC-keyless / SCP03-keyless fallback case
		// correctly).
		return
	}

	// Replace semantic: if P1 is non-zero, the new key replaces
	// an existing keyset at version P1. Unregister the old entry
	// before adding the new one. For additive installs (P1=0x00)
	// we just add.
	if p1 != 0 {
		c.unregisterKey(kid, p1)
	}
	c.registerKey(kid, newKVN, components)
}

// applyGenerateKeyToInventory registers an entry for a key just
// generated on-card via GENERATE EC KEY (INS=0xF1). The library's
// generateECKeyCmd places:
//
//   - the REPLACE KVN in P1 (0x00 = additive install)
//   - the KID in P2
//   - the NEW KVN as body[0]
//   - F0 TLV (curve params) following body[0]
//
// On a non-zero P1 we also remove the old entry at (KID, P1) — the
// GP "replace" semantic — before registering the new one.
func (c *MockCard) applyGenerateKeyToInventory(p1, p2 byte, body []byte) {
	if len(body) < 1 {
		return
	}
	kid := p2 & 0x7F
	newKVN := body[0]
	if p1 != 0 {
		c.unregisterKey(kid, p1)
	}
	c.registerKey(kid, newKVN, []byte{0x88, 0x88})
}

// applyDeleteKeyToInventory parses a DELETE KEY body and removes
// matching entries. Body shape per GP §11.5:
//
//   - D0 LL KID  (delete all keys with this KID)
//   - D2 LL KVN  (delete all keys with this KVN)
//   - both       (delete the specific (KID, KVN) entry)
//
// At least one of D0 or D2 must be present per the library's
// deleteKeyCmd validation; we mirror that precondition by simply
// doing nothing if neither parses out (the APDU still records and
// returns 9000, matching idempotent real-card behavior).
//
// The p2 byte (0x00 = "more deletes pending", 0x01 = "final
// delete operation") is informational here; the inventory mutation
// applies to whatever the body specifies regardless of pending-
// state framing.
func (c *MockCard) applyDeleteKeyToInventory(_ byte, body []byte) {
	var kid, kvn byte
	hasKID, hasKVN := false, false

	// Walk D0/D2 TLVs out of the body. We don't use tlv.Decode
	// here because these are raw single-byte length encodings
	// without the BER context (D0/D2 are not BER-TLV constructed
	// tags in this body shape — they're application-defined
	// 1-byte tag + 1-byte length + 1-byte value units).
	off := 0
	for off+2 < len(body) {
		tag := body[off]
		length := body[off+1]
		if off+2+int(length) > len(body) {
			break
		}
		value := body[off+2 : off+2+int(length)]
		switch tag {
		case 0xD0:
			if len(value) == 1 {
				kid = value[0]
				hasKID = true
			}
		case 0xD2:
			if len(value) == 1 {
				kvn = value[0]
				hasKVN = true
			}
		}
		off += 2 + int(length)
	}

	switch {
	case hasKID && hasKVN:
		c.unregisterKey(kid, kvn)
	case hasKID:
		c.unregisterAllAtKID(kid)
	case hasKVN:
		c.unregisterAllAtKVN(kvn)
	default:
		// No D0/D2 in the body — nothing to delete from the
		// inventory. Real cards would reject with 6A80; we leave
		// the response side unchanged (still returns 9000) for
		// backward compat with tests that didn't model deletion
		// pre-conditions.
	}
}

// buildKeyInfoResponse marshals the current inventory into the
// Key Information Template wire shape per GP §11.3.3.1:
//
//	E0 LL
//	  C0 LL <KID> <KVN> <component_pairs...>
//	  C0 LL <KID> <KVN> <component_pairs...>
//	  ...
//
// Entries are sorted by (KID, KVN) so the response is deterministic
// across runs and across map iteration order. The library's
// parseKeyInformation walks C0 children in order; sd keys list
// further sorts on the host side, so the wire order doesn't affect
// CLI output, but a deterministic mock simplifies snapshot tests
// and trace comparisons.
//
// An empty inventory marshals to E0 00 (zero-length container).
// The library's parseKeyInformation handles that as "no keys
// installed" — sd keys list reports "no key entries" and exits
// successfully, mirroring what a freshly-erased card would show.
func (c *MockCard) buildKeyInfoResponse() []byte {
	if len(c.inventory) == 0 {
		return []byte{0xE0, 0x00}
	}
	// Sort keys deterministically.
	keys := make([]uint16, 0, len(c.inventory))
	for k := range c.inventory {
		keys = append(keys, k)
	}
	sortUint16s(keys)

	var inner []byte
	for _, k := range keys {
		e := c.inventory[k]
		body := append([]byte{e.KID, e.KVN}, e.Components...)
		inner = append(inner, tlv.Build(tlv.Tag(0xC0), body).Encode()...)
	}
	return tlv.Build(tlv.Tag(0xE0), inner).Encode()
}

// sortUint16s is a small uint16 sort. We don't import sort because
// the mock is on the hot path of every test that uses SCP03 and
// adding a stdlib package for one call site is wasteful; the inner
// loop here is O(n log n) on a list that's typically 1-5 entries
// long.
func sortUint16s(a []uint16) {
	// Insertion sort — fine for the small N we deal with here.
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}
