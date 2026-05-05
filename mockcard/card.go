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
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// Card simulates a GP Security Domain with SCP11b support.
type Card struct {
	mu sync.Mutex

	// Variant controls the SCP11 mode the card responds to.
	// 0=SCP11b (default), 1=SCP11a, 2=SCP11c.
	Variant int

	// MockYubiKeyVersion is the 3-byte firmware version returned
	// for INS=0xFD CLA=0x00 (YubiKey GET VERSION). Set to e.g.
	// {0x05, 0x07, 0x02} to make the piv/profile probe identify
	// the mock as YubiKey 5.7.2 and select YubiKeyProfile (which
	// advertises Reset, attestation, ATTEST, etc.). Default nil
	// makes the mock advertise as standard PIV — appropriate for
	// tests that don't depend on YubiKey-specific profile bits.
	//
	// Independent of the legacy INS=0xFD echo behavior: the
	// echo path stays active when CLA=0x80 (or when this field
	// is nil), preserving every existing test fixture.
	MockYubiKeyVersion []byte

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

	// PIVMgmtKey, when non-nil, makes the mock implement crypto-correct
	// PIV management-key mutual authentication on GENERAL AUTHENTICATE
	// (INS 0x87, key ref 0x9B). Step 1 generates a witness, encrypts
	// under PIVMgmtKey, returns it; step 2 verifies the host's
	// decrypted witness matches what was generated, then encrypts the
	// host's challenge and returns it. PIVMgmtKeyAlgo selects the
	// cipher (one of the piv.AlgoMgmt* constants). When PIVMgmtKey is
	// nil the mock returns 6985 to GENERAL AUTHENTICATE — a
	// piv-provision smoke test that wants to exercise the auth flow
	// must configure both fields.
	PIVMgmtKey     []byte
	PIVMgmtKeyAlgo byte

	// Internal: witness generated in step 1, expected back from host
	// (decrypted) in step 2.
	pivMgmtAuthWitness []byte

	// Public key of the most recent successful GENERATE KEY (PIV
	// INS 0x47). Tests use this to construct an X.509 certificate
	// that matches the slot's key, so the cert-binding check in
	// piv-provision exercises the success path against the mock.
	// nil before the first GENERATE KEY.
	pivLastGenKey *ecdsa.PublicKey

	// PIVPresetKey, when non-nil, makes GENERATE KEY (PIV INS 0x47)
	// return this keypair's public key instead of generating a
	// fresh random one. Tests use this to build a matching X.509
	// cert before invoking piv-provision, so the cert-binding
	// check has a known-good cert to validate against. The mock
	// still doesn't know how to actually sign with this key (it's
	// just for shape), but the public part round-trips through
	// the GENERATE KEY response.
	PIVPresetKey *ecdsa.PrivateKey

	// PIV PIN/PUK state for piv-reset smoke testing. Counters start
	// at 3 (YubiKey default) and decrement on wrong PIN / wrong PUK;
	// at 0 the credential is blocked and VERIFY / RESET RETRY
	// COUNTER return 6983. PIV reset (INS 0xFB) succeeds only when
	// both counters are 0; success resets both to 3 and the stored
	// PIN/PUK to factory defaults, plus clears any provisioned
	// state (pivLastGenKey, pivMgmtAuthWitness, etc).
	//
	// Initialized by New() to factory state: PIN "123456" with 3
	// retries, PUK "12345678" with 3 retries.
	pivPIN        []byte
	pivPUK        []byte
	pivPINCounter int
	pivPUKCounter int

	// pivObjects is the in-memory PIV data object store, keyed by
	// the 3-byte object ID rendered as a hex string. PUT DATA
	// (INS=0xDB) writes here; GET DATA (INS=0xCB) reads from here.
	// Tests use this to verify round-trips through ReadObject /
	// WriteObject and through GetCertificate / DeleteCertificate.
	//
	// Stored values are the inner-payload bytes (the contents of
	// the 0x53 wrapper that PUT DATA receives). The wrapper is
	// stripped on write and reapplied on read so callers see the
	// same shape regardless of which path they took in.
	pivObjects map[string][]byte

	// RegistryISD, RegistryApps, RegistryLoadFiles back the GP
	// GET STATUS handler. Tests populate these to control what the
	// mock card claims is installed; an empty slice for any scope
	// makes that scope return SW=6A88 (referenced data not found),
	// matching real-card behavior on a barren registry.
	//
	// The SCP11b/SCP03 unwrap is unaffected — GET STATUS reaches the
	// dispatch only when a session is open, so tests must establish
	// authentication first.
	RegistryISD       []MockRegistryEntry
	RegistryApps      []MockRegistryEntry
	RegistryLoadFiles []MockRegistryEntry
}

// LastGeneratedPIVKey returns the public key from the most recent
// successful PIV GENERATE KEY against this mock, or nil if none
// has happened. Useful in tests that need to build a cert matching
// the slot's keypair.
func (c *Card) LastGeneratedPIVKey() *ecdsa.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pivLastGenKey
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

	return &Card{
		staticKey:     key,
		certDER:       der,
		pivPIN:        []byte("123456"),
		pivPUK:        []byte("12345678"),
		pivPINCounter: 3,
		pivPUKCounter: 3,
		pivObjects:    make(map[string][]byte),
	}, nil
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

	return c.dispatchINS(cmd, false /* underSM */)
}

// dispatchINS is the single source of truth for "which handler runs
// for which INS." It is called from two places:
//
//   - processAPDU, with underSM=false, for plaintext commands (either
//     pre-session, or the SELECT-only carve-out post-session enforced
//     above).
//   - processSecure, with underSM=true, after an SM-wrapped command's
//     MAC has been verified and its data decrypted.
//
// Adding a new command means adding one case here and (where relevant)
// gating it on underSM. The handshake commands (0x88, 0x82, 0x2A) are
// the canonical example: they only make sense pre-session, so under SM
// they refuse with 6985 rather than running a fresh handshake step
// inside the very channel that's wrapping them.
//
// This function exists because the mock previously had two parallel
// switches — one for the plaintext path and one for the post-decrypt
// path — and they drifted: GET DATA was in both, but the post-auth
// switch missed it for several months until #50 fixed the symptom.
// Collapsing them removes the duplication permanently.
func (c *Card) dispatchINS(cmd *apdu.Command, underSM bool) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4: // SELECT
		return c.doSelect(cmd, underSM)

	case 0xCA: // GET DATA
		return c.doGetData(cmd)

	case 0xF2: // GP §11.4.2 GET STATUS
		return c.doGetStatus(cmd)

	case 0x88: // INTERNAL AUTHENTICATE (SCP11b handshake)
		if underSM {
			return mkSW(0x6985), nil // conditions not satisfied
		}
		return c.doInternalAuth(cmd)

	case 0x82: // EXTERNAL AUTHENTICATE (SCP11a/c handshake)
		if underSM {
			return mkSW(0x6985), nil
		}
		return c.doInternalAuth(cmd)

	case 0x2A: // PERFORM SECURITY OPERATION (OCE cert upload, SCP11a/c)
		if underSM {
			return mkSW(0x6985), nil
		}
		return c.doPerformSecurityOp(cmd)

	case 0xFD:
		// INS=0xFD is overloaded:
		//   - CLA=0x00 + empty data: YubiKey-specific GET VERSION
		//     (firmware version triplet, 3 bytes). Used by the
		//     piv/profile probe to detect "this card is a YubiKey"
		//     and promote it from StandardPIVProfile to YubiKeyProfile.
		//     We respond when MockYubiKeyVersion is set; nil leaves
		//     the card looking like a non-YubiKey PIV implementation
		//     (standard-piv profile).
		//   - CLA=0x80 (or any non-zero CLA): legacy test echo. The
		//     mock has used INS=0xFD as an "echo back arbitrary data"
		//     loopback for years; existing tests rely on that.
		if cmd.CLA == 0x00 && len(cmd.Data) == 0 && c.MockYubiKeyVersion != nil {
			return &apdu.Response{Data: c.MockYubiKeyVersion, SW1: 0x90, SW2: 0x00}, nil
		}
		return &apdu.Response{Data: cmd.Data, SW1: 0x90, SW2: 0x00}, nil

	case 0x47: // PIV GENERATE KEY
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// If PIVPresetKey is set (tests use this), return that key's
		// public part instead of generating fresh material. Otherwise
		// generate a real on-curve P-256 keypair. The mock always
		// produces P-256 regardless of what the host requested in
		// the data TLV; if a future test needs RSA or P-384 from
		// the mock, branch here on the requested algorithm.
		// Pre-fix the mock returned 65 bytes of pure random data —
		// not an on-curve point and not in the spec-mandated TLV
		// envelope. ParseGeneratedPublicKey would correctly reject
		// it on both counts.
		var pub *ecdsa.PublicKey
		if c.PIVPresetKey != nil {
			pub = &c.PIVPresetKey.PublicKey
		} else {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return mkSW(0x6F00), nil
			}
			pub = &priv.PublicKey
		}
		c.pivLastGenKey = pub
		// Encode uncompressed point: 0x04 || X(32) || Y(32).
		point := make([]byte, 65)
		point[0] = 0x04
		pub.X.FillBytes(point[1:33])
		pub.Y.FillBytes(point[33:])
		// Wrap in 7F 49 LL { 86 LL <point> } per NIST SP 800-73-4
		// Part 2 §3.3.2.
		body := append([]byte{0x86, byte(len(point))}, point...)
		respData := append([]byte{0x7F, 0x49, byte(len(body))}, body...)
		return &apdu.Response{Data: respData, SW1: 0x90, SW2: 0x00}, nil

	case 0x20: // PIV VERIFY (PIN)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Counter-aware. PIN data is right-padded with 0xFF to 8
		// bytes per NIST SP 800-73-4 §3.2.1; strip trailing 0xFF
		// before comparing to the stored PIN value. Empty data is
		// a "query retries" call — return SW=63CX where X is the
		// retry counter (matches YubiKey behavior).
		if c.pivPINCounter == 0 {
			return mkSW(0x6983), nil
		}
		if len(cmd.Data) == 0 {
			return mkSW(0x6300 | uint16(c.pivPINCounter)), nil
		}
		if bytesEqualPadded(cmd.Data, c.pivPIN) {
			c.pivPINCounter = 3 // successful VERIFY restores counter
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		}
		c.pivPINCounter--
		if c.pivPINCounter == 0 {
			return mkSW(0x6983), nil
		}
		return mkSW(0x6300 | uint16(c.pivPINCounter)), nil

	case 0x2C: // PIV RESET RETRY COUNTER (PUK + new PIN)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		if cmd.P2 != 0x80 {
			// Only the PIN reference (0x80) is supported here.
			return mkSW(0x6A86), nil
		}
		if c.pivPUKCounter == 0 {
			return mkSW(0x6983), nil
		}
		// Data is PUK (8 bytes 0xFF-padded) || newPIN (8 bytes 0xFF-padded).
		if len(cmd.Data) != 16 {
			return mkSW(0x6A80), nil
		}
		puk := cmd.Data[:8]
		newPIN := cmd.Data[8:]
		if !bytesEqualPadded(puk, c.pivPUK) {
			c.pivPUKCounter--
			if c.pivPUKCounter == 0 {
				return mkSW(0x6983), nil
			}
			return mkSW(0x6300 | uint16(c.pivPUKCounter)), nil
		}
		// Right PUK: replace PIN with the supplied new PIN
		// (stripped of 0xFF padding) and reset PIN counter.
		c.pivPIN = stripPINPad(newPIN)
		c.pivPINCounter = 3
		c.pivPUKCounter = 3
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil

	case 0x24: // PIV CHANGE REFERENCE DATA (PIN or PUK)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Data: oldRef (8 bytes 0xFF-padded) || newRef (8 bytes
		// 0xFF-padded). P2 selects PIN (0x80) or PUK (0x81).
		if len(cmd.Data) != 16 {
			return mkSW(0x6A80), nil
		}
		oldRef := cmd.Data[:8]
		newRef := cmd.Data[8:]
		switch cmd.P2 {
		case 0x80: // PIN
			if c.pivPINCounter == 0 {
				return mkSW(0x6983), nil
			}
			if !bytesEqualPadded(oldRef, c.pivPIN) {
				c.pivPINCounter--
				if c.pivPINCounter == 0 {
					return mkSW(0x6983), nil
				}
				return mkSW(0x6300 | uint16(c.pivPINCounter)), nil
			}
			c.pivPIN = stripPINPad(newRef)
			c.pivPINCounter = 3
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		case 0x81: // PUK
			if c.pivPUKCounter == 0 {
				return mkSW(0x6983), nil
			}
			if !bytesEqualPadded(oldRef, c.pivPUK) {
				c.pivPUKCounter--
				if c.pivPUKCounter == 0 {
					return mkSW(0x6983), nil
				}
				return mkSW(0x6300 | uint16(c.pivPUKCounter)), nil
			}
			c.pivPUK = stripPINPad(newRef)
			c.pivPUKCounter = 3
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		default:
			return mkSW(0x6A86), nil
		}

	case 0xCB: // PIV GET DATA
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Data is a 0x5C-tagged object ID.
		nodes, err := tlv.Decode(cmd.Data)
		if err != nil {
			return mkSW(0x6A80), nil
		}
		idTag := tlv.Find(nodes, 0x5C)
		if idTag == nil || len(idTag.Value) == 0 {
			return mkSW(0x6A80), nil
		}
		key := hex.EncodeToString(idTag.Value)
		stored, ok := c.pivObjects[key]
		if !ok {
			return mkSW(0x6A82), nil // file not found
		}
		// Wrap stored payload in 0x53 for the response.
		wrapper := tlv.Build(tlv.Tag(0x53), stored)
		return &apdu.Response{
			Data: wrapper.Encode(),
			SW1:  0x90, SW2: 0x00,
		}, nil

	case 0xDB: // PIV PUT DATA (cert install on a slot, generic objects)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Data is 0x5C-tagged objectID followed by 0x53-tagged value.
		nodes, err := tlv.Decode(cmd.Data)
		if err != nil {
			// Fall back to the original lenient behavior: any PUT
			// DATA we cannot parse simply succeeds. Tests written
			// against the older mock used unstructured payloads.
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		}
		idTag := tlv.Find(nodes, 0x5C)
		valTag := tlv.Find(nodes, 0x53)
		if idTag == nil || valTag == nil {
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		}
		key := hex.EncodeToString(idTag.Value)
		c.pivObjects[key] = append([]byte{}, valTag.Value...)
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil

	case 0xFB: // YubiKey PIV RESET (Yubico extension)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Only succeeds when BOTH PIN and PUK are blocked. This
		// is the YubiKey's own foot-gun guard — you can't wipe a
		// slot just by sending the APDU; you have to first block
		// both credentials, which is something a casual operator
		// won't do by accident.
		if c.pivPINCounter > 0 || c.pivPUKCounter > 0 {
			return mkSW(0x6985), nil
		}
		// Reset everything PIV-related to factory state.
		c.pivPIN = []byte("123456")
		c.pivPUK = []byte("12345678")
		c.pivPINCounter = 3
		c.pivPUKCounter = 3
		c.pivLastGenKey = nil
		c.pivMgmtAuthWitness = nil
		// Note: we do NOT clear PIVMgmtKey/PIVMgmtKeyAlgo or
		// PIVPresetKey; those are test fixtures, not card state.
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil

	case 0xF9: // YubiKey ATTESTATION (Yubico extension)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		// Return a small synthetic blob that looks like cert data so
		// the host can decode "got a non-empty response." Not a real
		// attestation; the mock can't sign a meaningful one.
		return &apdu.Response{Data: []byte{0x30, 0x82, 0x01, 0x00}, SW1: 0x90, SW2: 0x00}, nil

	case 0x87: // PIV GENERAL AUTHENTICATE (mgmt-key mutual auth at P2=0x9B)
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		if cmd.P2 != 0x9B {
			// Other key refs use INS 0x87 too (PIV authentication via
			// the slot keypair) but this mock only implements the
			// mgmt-key flow. Return "function not supported" for the
			// rest so callers fail loudly.
			return mkSW(0x6A81), nil
		}
		if len(c.PIVMgmtKey) == 0 {
			// Mock not configured for mgmt-key auth — refuse rather
			// than silently ACK something that would mislead a smoke
			// test into believing auth happened.
			return mkSW(0x6985), nil
		}
		return c.handlePIVMgmtAuth(cmd)

	case 0xFF: // PIV SET MANAGEMENT KEY (YubiKey-specific extension to
		// SP 800-73-4 — 5.7+ accepts AES variants in addition to 3DES).
		// Wire format per piv/apdu/commands.go SetManagementKey:
		// CLA=00 INS=FF P1=FF P2=FF, data = algorithm-byte || TLV(0x9B, newKey).
		// The mock accepts any well-formed input and updates its own
		// in-memory PIVMgmtKey/PIVMgmtKeyAlgo so subsequent mgmt-auth
		// calls validate against the new key. The mock does not gate
		// on "currently authenticated" because the witness state is
		// per-handshake rather than per-session; the host side
		// (piv/session.requireMgmtAuth) is what enforces "must be
		// authenticated to rotate", and that path is tested
		// independently. The mock's job here is to model the wire
		// shape and the post-rotation card state (new key live,
		// prior auth invalidated), not the access-control policy.
		if !c.pivSelected {
			return mkSW(0x6985), nil
		}
		if len(cmd.Data) < 4 {
			return mkSW(0x6700), nil // wrong length
		}
		algo := cmd.Data[0]
		if cmd.Data[1] != 0x9B {
			return mkSW(0x6A80), nil // wrong data
		}
		// Skip the algorithm byte and TLV header (tag 0x9B at index 1,
		// length at index 2). Body starts at index 3 because all
		// management-key sizes (16/24/32 bytes) fit in single-byte
		// length encoding.
		bodyStart := 3
		keyLen := int(cmd.Data[2])
		if len(cmd.Data) < bodyStart+keyLen {
			return mkSW(0x6700), nil
		}
		c.PIVMgmtKey = append([]byte(nil), cmd.Data[bodyStart:bodyStart+keyLen]...)
		c.PIVMgmtKeyAlgo = algo
		// Post-rotation: any prior witness state is stale.
		c.pivMgmtAuthWitness = nil
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil

	default:
		return mkSW(0x6D00), nil // instruction not supported
	}
}

func (c *Card) doSelect(cmd *apdu.Command, underSM bool) (*apdu.Response, error) {
	// A plaintext SELECT signals a fresh handshake is about to
	// start (the host's pre-handshake reset), so any prior session
	// state is stale and must be cleared. A SELECT-under-SM is a
	// different beast — it's the ApplicationAID flow where the
	// host opens SCP on the SD and then switches applets while
	// keeping the session alive — so leave the session intact in
	// that path.
	if !underSM {
		c.session = nil
	}
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
	tag := uint16(cmd.P1)<<8 | uint16(cmd.P2)
	switch tag {
	case 0x0066:
		// Card Recognition Data — same synthetic blob the SCP03 mock
		// returns. Both mocks return identical CRD so a test that
		// drives either through the host CRD parser sees identical
		// shape and downstream tests don't have to special-case which
		// mock they used.
		return &apdu.Response{Data: append([]byte(nil), syntheticCRD...), SW1: 0x90, SW2: 0x00}, nil
	case 0x00E0:
		// Key Information Template. The mock advertises one entry
		// (KID=0x01, KVN=0xFF, AES-128) so host-side
		// GetKeyInformation produces a non-empty result.
		return &apdu.Response{Data: append([]byte(nil), syntheticKeyInfo...), SW1: 0x90, SW2: 0x00}, nil
	case 0xBF21:
		// Certificate store — the original behavior of this method.
		certNode := tlv.Build(tlv.TagCertificate, c.certDER)
		storeNode := tlv.BuildConstructed(tlv.TagCertStore, certNode)
		return &apdu.Response{Data: storeNode.Encode(), SW1: 0x90, SW2: 0x00}, nil
	default:
		return mkSW(0x6A88), nil // reference data not found
	}
}

// syntheticCRD is hand-assembled GP 2.3.1 / SCP03 i=0x65 Card
// Recognition Data, returned by GET DATA tag 0x0066. Same shape as
// the test fixture used elsewhere in the repo. See GP Card Spec
// §H.2 for the structure.
var syntheticCRD = []byte{
	0x66, 0x26,
	0x73, 0x24,
	0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
	0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
	0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x65,
}

// syntheticKeyInfo is a minimal Key Information Template returned
// by GET DATA tag 0x00E0. One C0 entry: KID=0x01, KVN=0xFF, AES-128
// marker. Decodes through securitydomain.parseKeyInformation to a
// single KeyInfo entry.
var syntheticKeyInfo = []byte{
	0xE0, 0x06,
	0xC0, 0x04, 0x01, 0xFF, 0x88, 0x10,
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
	// Lc encoding must match what channel.SecureChannel.Wrap puts in
	// the MAC input on the host side: extended length (3 bytes:
	// 0x00 || hi || lo) when len(data) > 0xFF, otherwise single
	// byte. Pre-fix the mock used byte(len(data)) unconditionally,
	// which silently truncated for any wrapped payload over 255 bytes
	// (cert installs, large STORE DATA chunks) and produced a MAC
	// mismatch the mock returned as 6982. piv-provision tripping on
	// PUT CERTIFICATE is what surfaced this.
	if len(data) > 0xFF {
		macInput = append(macInput, 0x00, byte(len(data)>>8), byte(len(data)))
	} else {
		macInput = append(macInput, byte(len(data)))
	}
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
	plainResp, err := c.dispatchINS(plainCmd, true /* underSM */)
	if err != nil {
		return nil, err
	}

	return sess.ch.WrapResponse(plainResp)
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
//	short:    CLA INS P1 P2 [Lc Data ...] [Le]
//	          Lc is 1 byte (1-255), Le is 1 byte (0 means 256).
//
//	extended: CLA INS P1 P2 [00 Lc_hi Lc_lo Data ...] [Le_hi Le_lo]
//	          Lc is 2 bytes after a 0x00 marker (1-65535).
//	          Le, when present, is the trailing 2 bytes (no marker
//	          since the extended marker was already consumed).
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

// bytesEqualPadded compares a 0xFF-right-padded PIN/PUK candidate
// against the stored unpadded value. Real PIV VERIFY data is always
// 8 bytes 0xFF-padded; the stored "correct" value is the unpadded
// form so the test fixture is readable.
func bytesEqualPadded(padded, unpadded []byte) bool {
	if len(padded) < len(unpadded) {
		return false
	}
	for i, b := range unpadded {
		if padded[i] != b {
			return false
		}
	}
	for _, b := range padded[len(unpadded):] {
		if b != 0xFF {
			return false
		}
	}
	return true
}

// stripPINPad removes trailing 0xFF bytes from a 0xFF-padded PIN.
func stripPINPad(padded []byte) []byte {
	for i := len(padded); i > 0; i-- {
		if padded[i-1] != 0xFF {
			return append([]byte{}, padded[:i]...)
		}
	}
	return nil
}

// TrustBoundary reports TrustBoundaryUnknown. The mock is a test
// fixture that has no notion of where the host running the
// program sits relative to anything; it does not represent a
// physical trust posture. Callers gating raw-mode operations on
// transport.TrustBoundaryLocalPCSC will refuse this transport,
// which is the right behavior: tests that need to exercise raw
// destructive paths against the mock do so by wrapping the
// transport in a test-only override that explicitly claims
// TrustBoundaryLocalPCSC and acknowledges the override in its
// type name.
func (t *MockTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
