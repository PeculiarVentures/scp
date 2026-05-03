package securitydomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	scp "github.com/PeculiarVentures/scp"
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/session"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// AIDSecurityDomain is the GlobalPlatform Issuer Security Domain AID.
var AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

// Status words used during reset lockout.
const (
	swAuthMethodBlocked    uint16 = 0x6983
	swSecurityNotSatisfied uint16 = 0x6982
	swIncorrectParameters  uint16 = 0x6A80
)

// Session provides typed management operations over an authenticated
// Security Domain channel.
//
// Two construction modes are supported:
//
//   - Authenticated: via Open, OpenSCP11, or OpenWithSession.
//     All management operations are available.
//
//   - Unauthenticated: via OpenUnauthenticated.
//     Only read-only introspection operations are available.
type Session struct {
	scpSession    scp.Session
	transport     transport.Transport
	authenticated bool

	// dek is the Data Encryption Key from the SCP03 key set used to
	// authenticate this session. Required for PUT KEY operations that
	// encrypt key material before transmission. Nil for SCP11 sessions.
	dek []byte
}

// Open establishes an authenticated Security Domain session using SCP03.
//
//	sd, err := securitydomain.Open(ctx, t, scp03.DefaultKeys, 0x00)
//	defer sd.Close()
func Open(ctx context.Context, t transport.Transport, keys scp03.StaticKeys, keyVersion byte) (*Session, error) {
	// Validate the static DEK at the API boundary so configuration
	// mistakes (all-zero key, wrong length) surface here rather than
	// at the first PUT KEY call. The same helper backs OpenWithSession
	// and requireDEK so all three paths agree on what a usable DEK
	// looks like.
	if err := validateDEK(keys.DEK); err != nil {
		return nil, fmt.Errorf("securitydomain: %w", err)
	}

	cfg := &scp03.Config{
		Keys:              keys,
		KeyVersion:        keyVersion,
		SelectAID:         AIDSecurityDomain,
		SecurityLevel:     channel.LevelFull,
	}

	scpSess, err := scp03.Open(ctx, t, cfg)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SCP03 session: %w", err)
	}

	// Store the DEK for use in PUT KEY operations.
	dek := make([]byte, len(keys.DEK))
	copy(dek, keys.DEK)

	return &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
		dek:           dek,
	}, nil
}

// OpenSCP11 establishes an authenticated Security Domain session using SCP11.
//
// The caller's cfg is not mutated: this function takes a shallow copy
// before forcing SelectAID = AIDSecurityDomain and ApplicationAID = nil,
// so configs reused across applets/sessions stay intact. Earlier
// versions modified cfg in place, which surprised callers reusing a
// shared config object.
func OpenSCP11(ctx context.Context, t transport.Transport, cfg *session.Config) (*Session, error) {
	var local session.Config
	if cfg != nil {
		local = *cfg
	} else {
		local = *session.DefaultConfig()
	}
	local.SelectAID = AIDSecurityDomain
	local.ApplicationAID = nil

	scpSess, err := session.Open(ctx, t, &local)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SCP11 session: %w", err)
	}

	return &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
	}, nil
}

// OpenWithSession wraps an existing authenticated scp.Session.
//
// If the session was established with SCP03 and the caller intends to
// perform PUT KEY operations, supply the static DEK so key material can
// be encrypted before transmission. The DEK is validated at construction
// time — an all-zero or oversized DEK is rejected immediately rather
// than at first use, so configuration mistakes surface at the API
// boundary.
//
// Pass dek=nil if the caller will not invoke PUT KEY (or is using
// SCP11, where there is no separate DEK). PUT KEY will then return
// ErrNotAuthenticated.
func OpenWithSession(scpSess scp.Session, t transport.Transport, dek []byte) (*Session, error) {
	if scpSess == nil {
		return nil, errors.New("securitydomain: scp.Session is required")
	}
	if t == nil {
		return nil, errors.New("securitydomain: transport is required")
	}
	s := &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
	}
	if len(dek) > 0 {
		if err := validateDEK(dek); err != nil {
			return nil, fmt.Errorf("securitydomain: %w", err)
		}
		s.dek = make([]byte, len(dek))
		copy(s.dek, dek)
	}
	return s, nil
}

// validateDEK enforces the structural and security requirements on a
// session DEK supplied at the API boundary. The same check is reapplied
// at use time by requireDEK to defend against later mutation, but
// catching it here means callers see the failure where they made it.
func validateDEK(dek []byte) error {
	switch len(dek) {
	case 16, 24, 32:
		// AES-128 / AES-192 / AES-256.
	default:
		return fmt.Errorf("DEK must be 16, 24, or 32 bytes; got %d", len(dek))
	}
	allZero := true
	for _, b := range dek {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return errors.New("DEK is all zero; refusing to use a known key")
	}
	return nil
}

// OpenUnauthenticated opens a read-only session to the Security Domain.
func OpenUnauthenticated(ctx context.Context, t transport.Transport) (*Session, error) {
	cmd := apdu.NewSelect(AIDSecurityDomain)
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: select SD: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: select SD: %w", resp.Error())
	}
	return &Session{transport: t, authenticated: false}, nil
}

// Close terminates the session and zeros key material.
func (s *Session) Close() {
	if s.scpSession != nil {
		s.scpSession.Close()
	}
	for i := range s.dek {
		s.dek[i] = 0
	}
}

// IsAuthenticated reports whether this session has a secure channel.
func (s *Session) IsAuthenticated() bool { return s.authenticated }

// Protocol returns the secure channel protocol in use, or "none".
func (s *Session) Protocol() string {
	if s.scpSession != nil {
		return s.scpSession.Protocol()
	}
	return "none"
}

// transmit sends a command through the appropriate channel.
func (s *Session) transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		return s.scpSession.Transmit(ctx, cmd)
	}
	return s.transport.Transmit(ctx, cmd)
}

// transmitRaw sends a command through the raw transport, bypassing
// secure messaging. Used during reset where the SCP session is being
// deliberately destroyed.
func (s *Session) transmitRaw(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return s.transport.Transmit(ctx, cmd)
}

// transmitCollectAll handles GET RESPONSE chaining through the secure
// channel when authenticated, or via the unauthenticated transport path
// otherwise. Both paths share the same iteration- and byte-count caps
// from the transport package — a hostile or buggy card cannot loop the
// host indefinitely or coerce unbounded memory growth, regardless of
// whether secure messaging is engaged.
func (s *Session) transmitCollectAll(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		resp, err := s.scpSession.Transmit(ctx, cmd)
		if err != nil {
			return nil, err
		}
		var allData []byte
		allData = append(allData, resp.Data...)
		for i := 0; resp.IsMoreData(); i++ {
			if i >= transport.MaxGetResponseIterations {
				return nil, fmt.Errorf("GET RESPONSE exceeded %d iterations", transport.MaxGetResponseIterations)
			}
			if len(allData) > transport.MaxCollectedResponseBytes {
				return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", transport.MaxCollectedResponseBytes)
			}
			getResp := apdu.NewGetResponse(resp.SW2)
			resp, err = s.scpSession.Transmit(ctx, getResp)
			if err != nil {
				return nil, err
			}
			allData = append(allData, resp.Data...)
		}
		return &apdu.Response{Data: allData, SW1: resp.SW1, SW2: resp.SW2}, nil
	}
	return transport.TransmitCollectAll(ctx, s.transport, cmd)
}

func (s *Session) requireAuth() error {
	if !s.authenticated {
		return ErrNotAuthenticated
	}
	return nil
}

func (s *Session) requireDEK() error {
	if len(s.dek) == 0 {
		return fmt.Errorf("%w: session DEK not available (SCP03 session required for PUT KEY)", ErrNotAuthenticated)
	}
	// Re-validate at use time. Construction-time validation in Open
	// and OpenWithSession should already have caught a bad DEK, but
	// running the same checks here means construction and use cannot
	// drift if validateDEK gets stricter in the future, and it
	// defends against any later mutation of s.dek.
	if err := validateDEK(s.dek); err != nil {
		return fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
	}
	return nil
}

// transmitWithChaining handles large payloads using ISO 7816-4 APDU
// chaining (CLA bit 5).
//
// For payloads ≤ chunkBudget bytes, transmits as-is. For larger
// payloads, splits into chained APDUs whose wrapped on-wire form stays
// within short-Lc (≤ 255 bytes):
//
//   - When authenticated through SCP, each chunk is sized to
//     secureWrapSafeBlock (223) so that AES-CBC padding + MAC still
//     fits in a short APDU after channel.Wrap.
//   - When unauthenticated, each chunk is sized to 255 bytes; nothing
//     inflates the wire size.
//
// STORE DATA is explicitly refused — it has its own application-level
// chaining protocol; callers must use transmitStoreDataChained.
func (s *Session) transmitWithChaining(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS == insStoreData {
		return nil, fmt.Errorf("transmitWithChaining must not be used for STORE DATA; use transmitStoreDataChained")
	}

	chunkBudget := 255
	if s.authenticated && s.scpSession != nil {
		chunkBudget = secureWrapSafeBlock
	}

	if len(cmd.Data) <= chunkBudget {
		return s.transmit(ctx, cmd)
	}

	cmds := chainCommandsAt(cmd, chunkBudget)
	var lastResp *apdu.Response
	for i, c := range cmds {
		resp, err := s.transmit(ctx, c)
		if err != nil {
			return nil, err
		}
		if i < len(cmds)-1 && !resp.IsSuccess() {
			return resp, resp.Error()
		}
		lastResp = resp
	}
	return lastResp, nil
}

// chainCommandsAt splits cmd.Data into ISO 7816-4 chained APDUs whose
// data fields are at most chunkSize bytes. Intermediate APDUs have
// CLA bit 5 set; the final APDU keeps the original CLA and Le.
func chainCommandsAt(cmd *apdu.Command, chunkSize int) []*apdu.Command {
	if chunkSize <= 0 {
		chunkSize = 255
	}
	if len(cmd.Data) <= chunkSize {
		return []*apdu.Command{cmd}
	}
	var cmds []*apdu.Command
	data := cmd.Data
	for len(data) > chunkSize {
		cmds = append(cmds, &apdu.Command{
			CLA:  cmd.CLA | 0x10, // chaining bit
			INS:  cmd.INS,
			P1:   cmd.P1,
			P2:   cmd.P2,
			Data: data[:chunkSize],
			Le:   -1,
		})
		data = data[chunkSize:]
	}
	cmds = append(cmds, &apdu.Command{
		CLA:  cmd.CLA,
		INS:  cmd.INS,
		P1:   cmd.P1,
		P2:   cmd.P2,
		Data: data,
		Le:   cmd.Le,
	})
	return cmds
}

// secureWrapSafeBlock is the largest plaintext payload that, after
// AES-CBC encryption with ISO/IEC 9797-1 method-2 padding plus a
// 16-byte C-MAC, still fits in a short-form APDU (Lc ≤ 255):
//
//	max wire bytes = ceil((N + 1) / 16) * 16 + macSize ≤ 255
//
// For macSize = 16 (S16, the worst case), the largest N that satisfies
// the inequality is 223: padded(223) = 224, plus 16-byte MAC = 240,
// which fits. For macSize = 8 the safe value is 239; we pick the
// universal-safe value so the chunk size is independent of the
// negotiated SCP mode and the on-wire APDU stays short even under
// full secure messaging.
//
// Cards without extended-length APDU support (e.g. older YubiKey
// firmware) accept short APDUs only, so honoring this bound is what
// keeps chained management commands portable across hardware.
const secureWrapSafeBlock = 223

// storeDataMaxBlock is the maximum plaintext per STORE DATA block.
// Set to secureWrapSafeBlock so the on-wire APDU stays ≤ 255 bytes
// after secure-messaging wrap.
const storeDataMaxBlock = secureWrapSafeBlock

// transmitStoreDataChained sends a STORE DATA payload that may exceed a
// single APDU using GP application-level chaining (§11.11). The payload
// is split into ≤255-byte blocks, each block is sent as an individual
// STORE DATA APDU with P2 = block number, P1 b8 = 0 for all but the last.
// Each block goes through secure messaging individually (no plaintext
// pre-splitting after wrapping).
func (s *Session) transmitStoreDataChained(ctx context.Context, payload []byte) (*apdu.Response, error) {
	if len(payload) == 0 {
		return s.transmit(ctx, storeDataCmd(nil))
	}
	if len(payload) <= storeDataMaxBlock {
		return s.transmit(ctx, storeDataCmd(payload))
	}

	totalBlocks := (len(payload) + storeDataMaxBlock - 1) / storeDataMaxBlock
	if totalBlocks > 256 {
		return nil, fmt.Errorf("STORE DATA payload requires %d blocks; P2 block number exceeds 0xFF", totalBlocks)
	}

	var lastResp *apdu.Response
	for i := 0; i < totalBlocks; i++ {
		start := i * storeDataMaxBlock
		end := start + storeDataMaxBlock
		if end > len(payload) {
			end = len(payload)
		}
		isLast := i == totalBlocks-1
		cmd := storeDataBlockCmd(byte(i), isLast, payload[start:end])
		resp, err := s.transmit(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("STORE DATA block %d/%d: %w", i, totalBlocks, err)
		}
		if !isLast && !resp.IsSuccess() {
			return resp, fmt.Errorf("STORE DATA block %d/%d: %w", i, totalBlocks, resp.Error())
		}
		lastResp = resp
	}
	return lastResp, nil
}

// --- Introspection ---

// GetKeyInformation retrieves information about all installed keys.
func (s *Session) GetKeyInformation(ctx context.Context) ([]KeyInfo, error) {
	cmd := getDataCmd(p1p2KeyInfo, nil)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get key information: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get key information: %w: %w", ErrCardStatus, resp.Error())
	}
	return parseKeyInformation(resp.Data)
}

// GetCardRecognitionData retrieves the card recognition data (GP §H.2).
func (s *Session) GetCardRecognitionData(ctx context.Context) ([]byte, error) {
	cmd := getDataCmd(p1p2CardData, nil)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get card recognition data: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get card recognition data: %w: %w", ErrCardStatus, resp.Error())
	}
	return resp.Data, nil
}

// GetSupportedCaIdentifiers retrieves CA identifiers (SKIs) configured
// on the Security Domain.
func (s *Session) GetSupportedCaIdentifiers(ctx context.Context, kloc, klcc bool) ([]CaIdentifier, error) {
	if !kloc && !klcc {
		kloc = true
		klcc = true
	}

	var result []CaIdentifier
	for _, entry := range []struct {
		fetch bool
		tag   uint16
	}{
		{kloc, p1p2CaKlocID},
		{klcc, p1p2CaKlccID},
	} {
		if !entry.fetch {
			continue
		}
		cmd := getDataCmd(entry.tag, nil)
		resp, err := s.transmitCollectAll(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: get CA identifiers: %w", err)
		}
		if !resp.IsSuccess() {
			// Reference data not found is not an error — just means
			// no identifiers of that type are configured.
			if resp.StatusWord() == 0x6A88 {
				continue
			}
			continue
		}
		ids, err := parseSupportedCaIdentifiers(resp.Data)
		if err != nil {
			return nil, err
		}
		result = append(result, ids...)
	}
	return result, nil
}

// --- SCP03 key management ---

// PutSCP03Key installs or replaces an SCP03 key set.
//
// Key material is encrypted with the session DEK before transmission.
// replaceKvn is the KVN to replace, or 0 for a new key set.
//
// Requires an SCP03-authenticated session (DEK must be available).
func (s *Session) PutSCP03Key(ctx context.Context, ref KeyReference, keys scp03.StaticKeys, replaceKvn byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if err := s.requireDEK(); err != nil {
		return err
	}

	cmd, expectedResponse, err := putKeySCP03Cmd(ref, keys.ENC, keys.MAC, keys.DEK, s.dek, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put SCP03 key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put SCP03 key: %w: %w", ErrCardStatus, resp.Error())
	}

	// Verify checksum: response should be KVN + KCV_enc + KCV_mac + KCV_dek.
	if !bytes.Equal(resp.Data, expectedResponse) {
		return fmt.Errorf("%w: response %X, expected %X", ErrChecksum, resp.Data, expectedResponse)
	}

	return nil
}

// --- SCP11 key management ---

// GenerateECKey generates a new NIST P-256 key pair on the device.
// The private key never leaves the device.
func (s *Session) GenerateECKey(ctx context.Context, ref KeyReference, replaceKvn byte) (*ecdsa.PublicKey, error) {
	if err := s.requireAuth(); err != nil {
		return nil, err
	}

	cmd := generateECKeyCmd(ref, replaceKvn)
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: generate EC key: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: generate EC key: %w: %w", ErrCardStatus, resp.Error())
	}

	return parseGeneratedPublicKey(resp.Data)
}

// PutECPrivateKey imports an EC private key (NIST P-256).
// The key is encrypted with the session DEK before transmission.
//
// Requires an SCP03-authenticated session (DEK must be available).
func (s *Session) PutECPrivateKey(ctx context.Context, ref KeyReference, key *ecdsa.PrivateKey, replaceKvn byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if err := s.requireDEK(); err != nil {
		return err
	}

	cmd, err := putKeyECPrivateCmd(ref, key, s.dek, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put EC private key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put EC private key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// PutECPublicKey imports an EC public key (NIST P-256).
// Typically used for OCE public keys in SCP11a/c.
// Public keys are not encrypted.
func (s *Session) PutECPublicKey(ctx context.Context, ref KeyReference, key *ecdsa.PublicKey, replaceKvn byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	cmd, err := putKeyECPublicCmd(ref, key, replaceKvn)
	if err != nil {
		return err
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: put EC public key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: put EC public key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Key deletion and reset ---

// DeleteKey deletes one or more keys matching the reference.
//
// SCP03 special case: SCP03 keys (KID 0x01, 0x02, 0x03) MUST be
// deleted by KVN only — yubikit's reference implementation rejects
// KID-bearing DELETE for SCP03 outright. Cards typically reject too.
// If ref.ID is an SCP03 KID, this method clears it before building
// the command so only the 0xD2 (KVN) tag is sent. ref.Version must
// be set in that case.
func (s *Session) DeleteKey(ctx context.Context, ref KeyReference, deleteLast bool) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	if isSCP03KeyID(ref.ID) {
		if ref.Version == 0 {
			return errors.New("securitydomain: SCP03 keys can only be deleted by KVN; set ref.Version to the key set version")
		}
		ref = NewKeyReference(0, ref.Version)
	}

	cmd, err := deleteKeyCmd(ref, deleteLast)
	if err != nil {
		return fmt.Errorf("securitydomain: delete key: %w", err)
	}

	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: delete key: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: delete key: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// isSCP03KeyID reports whether the given KID belongs to an SCP03
// static key set. GP defines KIDs 0x01, 0x02, 0x03 for the three
// SCP03 keys (ENC, MAC, DEK) within a key set; cards address the
// set as a whole by KVN.
func isSCP03KeyID(kid byte) bool {
	return kid == 0x01 || kid == 0x02 || kid == 0x03
}

// Reset performs a factory reset of the Security Domain by blocking
// all installed keys through repeated invalid authentication attempts.
//
// This removes all keys and associated data, restores default SCP03
// keys, and generates a new SCP11b key.
//
// WARNING: destructive operation. All custom material is permanently deleted.
//
// The session is invalid after Reset returns — close it and open a new
// one with default keys.
//
// Ref: Python SecurityDomainSession.reset(), C# SecurityDomainSession.Reset().
func (s *Session) Reset(ctx context.Context) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	// Get all installed keys.
	keys, err := s.GetKeyInformation(ctx)
	if err != nil {
		return fmt.Errorf("securitydomain: reset: get key info: %w", err)
	}

	// For each key, determine the appropriate INS and send 65 invalid
	// authentication attempts to trigger lockout.
	for _, ki := range keys {
		ins, shouldProcess := insForKeyReset(ki.Reference.ID)
		if !shouldProcess {
			continue
		}

		kvn := ki.Reference.Version
		kid := ki.Reference.ID

		// SCP03 special handling: use KID=0, KVN=0 to allow
		// deleting the default keys (which have KVN=0xFF).
		if ki.Reference.ID == KeyIDSCP03 {
			kvn = 0
			kid = 0
		}

		for attempt := 0; attempt < 65; attempt++ {
			cmd := resetLockoutCmd(ins, kvn, kid)
			resp, err := s.transmitRaw(ctx, cmd)
			if err != nil {
				// Transport errors during reset are not fatal —
				// the device may be resetting.
				break
			}
			sw := resp.StatusWord()
			if sw == swAuthMethodBlocked || sw == swSecurityNotSatisfied {
				break
			}
			// On INCORRECT_PARAMETERS or SUCCESS, continue attempting.
		}
	}

	return nil
}

// --- Certificate operations ---

// StoreCertificates stores X.509 certificates for the given key reference.
// Certificates should be in order with the leaf certificate last.
func (s *Session) StoreCertificates(ctx context.Context, ref KeyReference, certs []*x509.Certificate) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	var derCerts [][]byte
	for _, c := range certs {
		derCerts = append(derCerts, c.Raw)
	}

	payload := storeCertificatesData(ref, derCerts)
	resp, err := s.transmitStoreDataChained(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store certificates: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store certificates: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// GetCertificates retrieves the certificates for the given key reference.
// The leaf certificate is last in the returned slice.
func (s *Session) GetCertificates(ctx context.Context, ref KeyReference) ([]*x509.Certificate, error) {
	keyRefData := buildKeyRefTLV(ref)
	cmd := getDataCmd(p1p2CertStore, keyRefData)

	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get certificates: %w", err)
	}
	if !resp.IsSuccess() {
		// Reference data not found — no certificates stored.
		if resp.StatusWord() == 0x6A88 {
			return nil, nil
		}
		return nil, fmt.Errorf("securitydomain: get certificates: %w: %w", ErrCardStatus, resp.Error())
	}

	derCerts, err := parseCertificates(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// StoreCaIssuer stores the SKI for the CA associated with a key reference.
func (s *Session) StoreCaIssuer(ctx context.Context, ref KeyReference, ski []byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	payload := storeCaIssuerData(ref, ski)
	resp, err := s.transmitStoreDataChained(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store CA issuer: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store CA issuer: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Allowlist operations ---

// StoreAllowlist stores a certificate serial number allowlist.
// Serials are hex-encoded strings. Full replacement semantics.
func (s *Session) StoreAllowlist(ctx context.Context, ref KeyReference, serials []string) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	payload, err := storeAllowlistData(ref, serials)
	if err != nil {
		return err
	}

	resp, err := s.transmitStoreDataChained(ctx, payload)
	if err != nil {
		return fmt.Errorf("securitydomain: store allowlist: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store allowlist: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// ClearAllowlist removes the allowlist for the given key reference.
// Ref: C# ClearAllowList calls StoreAllowlist with empty list.
func (s *Session) ClearAllowlist(ctx context.Context, ref KeyReference) error {
	return s.StoreAllowlist(ctx, ref, nil)
}

// --- Raw data operations ---

// GetData sends a raw GET DATA command.
func (s *Session) GetData(ctx context.Context, tag uint16, data []byte) ([]byte, error) {
	cmd := getDataCmd(tag, data)
	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get data: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: get data: %w: %w", ErrCardStatus, resp.Error())
	}
	return resp.Data, nil
}

// StoreData sends a STORE DATA command, fragmenting the payload into
// blocks if it exceeds a single APDU.
func (s *Session) StoreData(ctx context.Context, data []byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	resp, err := s.transmitStoreDataChained(ctx, data)
	if err != nil {
		return fmt.Errorf("securitydomain: store data: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: store data: %w: %w", ErrCardStatus, resp.Error())
	}
	return nil
}

// --- Internal helpers ---

func buildKeyRefTLV(ref KeyReference) []byte {
	node := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)
	return node.Encode()
}
