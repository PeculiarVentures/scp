package securitydomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
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
	cfg := &scp03.Config{
		Keys:              keys,
		KeyVersion:        keyVersion,
		SecurityDomainAID: AIDSecurityDomain,
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
func OpenSCP11(ctx context.Context, t transport.Transport, cfg *session.Config) (*Session, error) {
	if cfg == nil {
		cfg = session.DefaultConfig()
	}
	cfg.SecurityDomainAID = AIDSecurityDomain
	cfg.ApplicationAID = nil

	scpSess, err := session.Open(ctx, t, cfg)
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
// If the session was established with SCP03, provide the static DEK
// so that PUT KEY operations can encrypt key material.
func OpenWithSession(scpSess scp.Session, t transport.Transport, dek []byte) *Session {
	s := &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
	}
	if len(dek) > 0 {
		s.dek = make([]byte, len(dek))
		copy(s.dek, dek)
	}
	return s
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

// transmitCollectAll handles GET RESPONSE chaining.
func (s *Session) transmitCollectAll(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		resp, err := s.scpSession.Transmit(ctx, cmd)
		if err != nil {
			return nil, err
		}
		var allData []byte
		allData = append(allData, resp.Data...)
		for resp.IsMoreData() {
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
	return nil
}

// transmitWithChaining handles command chaining for large payloads.
func (s *Session) transmitWithChaining(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if len(cmd.Data) <= 255 {
		return s.transmit(ctx, cmd)
	}
	cmds, err := apdu.ChainCommands(cmd)
	if err != nil {
		return nil, err
	}
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
// SCP03 keys can only be deleted by KVN.
func (s *Session) DeleteKey(ctx context.Context, ref KeyReference, deleteLast bool) error {
	if err := s.requireAuth(); err != nil {
		return err
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
	cmd := storeDataCmd(payload)

	resp, err := s.transmitWithChaining(ctx, cmd)
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
	cmd := storeDataCmd(payload)

	resp, err := s.transmit(ctx, cmd)
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

	cmd := storeDataCmd(payload)
	resp, err := s.transmit(ctx, cmd)
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

// StoreData sends a raw STORE DATA command. Requires authentication.
func (s *Session) StoreData(ctx context.Context, data []byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	cmd := storeDataCmd(data)
	resp, err := s.transmit(ctx, cmd)
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
