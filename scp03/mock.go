package scp03

import (
	"context"
	"crypto/rand"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
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

	// PlainHandler, if set, is invoked for every post-decrypt APDU
	// before the built-in switch. Returning ok=true short-circuits
	// dispatch with the supplied response; ok=false falls through
	// to the default handlers (SELECT, GET DATA, PUT KEY, etc.).
	//
	// Used by mockcard.SCP03Card to compose the rich GP dispatch
	// (INSTALL/LOAD/DELETE/GET STATUS) on top of this mock's SCP03
	// handshake and secure-messaging layer. Without this hook, the
	// GP dispatch and SCP03 handshake would have to be duplicated
	// between two mock types; with it, the composition is trivial.
	//
	// The hook receives the post-decrypt command and decides
	// whether to handle it. It is called BEFORE recorded-APDU
	// capture, so a handler return of ok=true bypasses the
	// recorded list — register-then-record yourself if you need
	// both.
	PlainHandler func(cmd *apdu.Command) (resp *apdu.Response, ok bool)

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

	// FailStoreDataSW, when non-zero, makes the mock return the
	// configured SW for any STORE DATA (INS=0xE2) reaching the
	// authenticated dispatch. Used to drive partial-success
	// recovery tests where PUT KEY succeeds and STORE DATA must
	// then fail on the same logical command. Default zero
	// preserves the historical record-and-9000 behavior.
	FailStoreDataSW uint16
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
		// data objects. Real YubiKeys permit several paths without
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
		//   - tag 0x00E0 (Key Information Template): YubiKey
		//     permits unauthenticated reads of the KIT so
		//     ykman/scpctl `sd keys list` and similar inventory
		//     commands work without prompting for SCP03 keys.
		//     Standard GP cards typically gate KIT behind the
		//     ISD authenticated state and answer 6982 here.
		//
		// Other GET DATA tags require secure messaging and get
		// SW=6982 here.
		if cmd.P1 == 0x00 && cmd.P2 == 0x66 {
			return c.doGetData(cmd.P1, cmd.P2, cmd.Data)
		}
		if cmd.P1 == 0x5F && cmd.P2 == 0xC1 {
			return c.doGetData(cmd.P1, cmd.P2, cmd.Data)
		}
		if cmd.P1 == 0x00 && cmd.P2 == 0xE0 {
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
	// Composition hook: let an embedding mock (mockcard.SCP03Card)
	// handle GP card-content management commands before the
	// SCP03-specific switch. Returning ok=true short-circuits.
	if c.PlainHandler != nil {
		cmd := &apdu.Command{INS: ins, P1: p1, P2: p2, Data: data}
		if resp, ok := c.PlainHandler(cmd); ok {
			return resp, nil
		}
	}
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
		if ins == 0xE2 && c.FailStoreDataSW != 0 {
			// Forced STORE DATA failure: drive partial-success
			// recovery tests where PUT KEY commits but STORE
			// DATA must then fail. Recording happens above so
			// tests can still assert the wire shape was right.
			return &apdu.Response{SW1: byte(c.FailStoreDataSW >> 8), SW2: byte(c.FailStoreDataSW)}, nil
		}
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
