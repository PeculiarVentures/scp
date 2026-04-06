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
// This is the target applet for all Security Domain management operations.
var AIDSecurityDomain = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}

// Session provides typed management operations over an authenticated
// Security Domain channel. It wraps either an SCP03 or SCP11 secure
// session and exposes the complete Yubico Security Domain API surface.
//
// Two construction modes are supported:
//
//   - Authenticated: via Open, OpenSCP11, or OpenWithSession.
//     All management operations are available.
//
//   - Unauthenticated: via OpenUnauthenticated.
//     Only read-only introspection operations are available
//     (GetKeyInformation, GetCardRecognitionData).
type Session struct {
	scpSession    scp.Session
	transport     transport.Transport
	authenticated bool
}

// Open establishes an authenticated Security Domain session using SCP03.
// This is the most common entry point — it opens an SCP03 channel to
// the Security Domain and returns a Session ready for management operations.
//
//	sd, err := securitydomain.Open(ctx, t, scp03.DefaultKeys, 0x00)
//	if err != nil { ... }
//	defer sd.Close()
func Open(ctx context.Context, t transport.Transport, keys scp03.StaticKeys, keyVersion byte) (*Session, error) {
	cfg := &scp03.Config{
		Keys:              keys,
		KeyVersion:        keyVersion,
		SecurityDomainAID: AIDSecurityDomain,
		// No ApplicationAID — we stay on the Security Domain.
		SecurityLevel: channel.LevelFull,
	}

	scpSess, err := scp03.Open(ctx, t, cfg)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SCP03 session: %w", err)
	}

	return &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
	}, nil
}

// OpenSCP11 establishes an authenticated Security Domain session using SCP11.
// The cfg must be configured to target the Security Domain (no ApplicationAID).
func OpenSCP11(ctx context.Context, t transport.Transport, cfg *session.Config) (*Session, error) {
	if cfg == nil {
		cfg = session.DefaultConfig()
	}
	// Override: always target the Security Domain, never redirect to an app.
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

// OpenWithSession wraps an existing authenticated scp.Session that has
// already been established to the Security Domain. The caller is
// responsible for ensuring the session targets the Security Domain AID.
func OpenWithSession(scpSess scp.Session, t transport.Transport) *Session {
	return &Session{
		scpSession:    scpSess,
		transport:     t,
		authenticated: true,
	}
}

// OpenUnauthenticated opens a read-only session to the Security Domain
// without SCP authentication. Only limited introspection operations are
// available (GetKeyInformation, GetCardRecognitionData).
func OpenUnauthenticated(ctx context.Context, t transport.Transport) (*Session, error) {
	// SELECT the Security Domain.
	cmd := apdu.NewSelect(AIDSecurityDomain)
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: select SD: %w", err)
	}
	if !resp.IsSuccess() {
		return nil, fmt.Errorf("securitydomain: select SD: %w", resp.Error())
	}

	return &Session{
		transport:     t,
		authenticated: false,
	}, nil
}

// Close terminates the session and zeros key material.
func (s *Session) Close() {
	if s.scpSession != nil {
		s.scpSession.Close()
	}
}

// IsAuthenticated reports whether this session has an established
// secure channel.
func (s *Session) IsAuthenticated() bool {
	return s.authenticated
}

// Protocol returns the secure channel protocol in use, or "none"
// for unauthenticated sessions.
func (s *Session) Protocol() string {
	if s.scpSession != nil {
		return s.scpSession.Protocol()
	}
	return "none"
}

// transmit sends a command through the session. For authenticated sessions,
// the command is sent through the SCP secure channel. For unauthenticated
// sessions, the command is sent as plaintext directly to the transport.
func (s *Session) transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		return s.scpSession.Transmit(ctx, cmd)
	}
	return s.transport.Transmit(ctx, cmd)
}

// transmitCollectAll sends a command and collects the full response,
// handling GET RESPONSE chaining (61xx status).
func (s *Session) transmitCollectAll(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if s.authenticated && s.scpSession != nil {
		// For SCP-wrapped sessions, TransmitCollectAll needs to go
		// through the secure channel for each chained command.
		// The SCP session's Transmit handles wrapping, so we do
		// manual chaining here.
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

		return &apdu.Response{
			Data: allData,
			SW1:  resp.SW1,
			SW2:  resp.SW2,
		}, nil
	}

	return transport.TransmitCollectAll(ctx, s.transport, cmd)
}

// requireAuth returns ErrNotAuthenticated if the session is unauthenticated.
func (s *Session) requireAuth() error {
	if !s.authenticated {
		return ErrNotAuthenticated
	}
	return nil
}

// --- Introspection operations ---

// GetKeyInformation retrieves information about all keys installed
// on the Security Domain. This corresponds to GET DATA with tag E0.
//
// Available on both authenticated and unauthenticated sessions.
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

// GetCardRecognitionData retrieves the card recognition data from the
// device. This is a TLV-encoded structure containing information about
// the card per GP Card Spec v2.3.1 §H.2.
//
// Available on both authenticated and unauthenticated sessions.
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

// GetSupportedCaIdentifiers retrieves the CA identifiers (Subject Key
// Identifiers) configured on the Security Domain.
//
// kloc: retrieve Key Loading OCE Certificate identifiers
// klcc: retrieve Key Loading Card Certificate identifiers
//
// Available on both authenticated and unauthenticated sessions.
func (s *Session) GetSupportedCaIdentifiers(ctx context.Context, kloc, klcc bool) ([]CaIdentifier, error) {
	if !kloc && !klcc {
		return nil, fmt.Errorf("securitydomain: at least one of kloc or klcc must be true")
	}

	var result []CaIdentifier

	if kloc {
		cmd := getDataCmd(p1p2CaKlocID, nil)
		resp, err := s.transmitCollectAll(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: get CA KLOC identifiers: %w", err)
		}
		if resp.IsSuccess() {
			ids, err := parseSupportedCaIdentifiers(resp.Data)
			if err != nil {
				return nil, err
			}
			result = append(result, ids...)
		}
	}

	if klcc {
		cmd := getDataCmd(p1p2CaKlccID, nil)
		resp, err := s.transmitCollectAll(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: get CA KLCC identifiers: %w", err)
		}
		if resp.IsSuccess() {
			ids, err := parseSupportedCaIdentifiers(resp.Data)
			if err != nil {
				return nil, err
			}
			result = append(result, ids...)
		}
	}

	return result, nil
}

// --- SCP03 key management ---

// PutSCP03Key installs or replaces an SCP03 key set on the Security Domain.
//
// ref identifies where to store the key set (KID should be KeyIDSCP03).
// keys contains the three AES-128 keys (ENC, MAC, DEK).
// replaceKvn is the KVN of the key set to replace, or 0 for a new key set.
//
// When installing the first custom key set on a device with default keys,
// the default key set (KVN=0xFF) is automatically removed by the device.
//
// Requires an authenticated session.
func (s *Session) PutSCP03Key(ctx context.Context, ref KeyReference, keys scp03.StaticKeys, replaceKvn byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	cmd, expectedKCV, err := putKeySCP03Cmd(ref, keys.ENC, keys.MAC, keys.DEK, replaceKvn)
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

	// Verify the KCV returned by the card.
	if len(resp.Data) >= 4 && expectedKCV != nil {
		returnedKCV, err := parsePutKeyChecksum(resp.Data)
		if err != nil {
			return err
		}
		if !bytes.Equal(returnedKCV, expectedKCV) {
			return fmt.Errorf("%w: expected %X, got %X", ErrChecksum, expectedKCV, returnedKCV)
		}
	}

	return nil
}

// --- SCP11 key management ---

// GenerateECKey generates a new NIST P-256 key pair on the Security Domain
// for the given key reference. The private key never leaves the device.
//
// replaceKvn is the KVN of an existing key to replace, or 0 for a new key.
//
// This is a Yubico extension (there is no standard GP command to generate
// key pairs on-card).
//
// Requires an authenticated session.
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

// PutECPrivateKey imports an EC private key to the Security Domain.
// Only NIST P-256 keys are supported.
//
// replaceKvn is the KVN of an existing key to replace, or 0 for a new key.
//
// Requires an authenticated session.
func (s *Session) PutECPrivateKey(ctx context.Context, ref KeyReference, key *ecdsa.PrivateKey, replaceKvn byte) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	cmd, err := putKeyECPrivateCmd(ref, key, replaceKvn)
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

// PutECPublicKey imports an EC public key to the Security Domain.
// Typically used for importing OCE public keys for SCP11a/c.
// Only NIST P-256 keys are supported.
//
// replaceKvn is the KVN of an existing key to replace, or 0 for a new key.
//
// Requires an authenticated session.
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

// DeleteKey deletes one or more keys matching the specified reference.
//
// Keys are matched by KID and/or KVN where 0 acts as a wildcard.
// For SCP03 keys, deletion is by KVN only.
//
// deleteLast must be true if deleting the final key on the device,
// false otherwise.
//
// Requires an authenticated session.
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

// Reset performs a factory reset of the Security Domain. This removes
// all keys and associated data, restores the default SCP03 static keys,
// and generates a new (attestable) SCP11b key.
//
// WARNING: This is a destructive operation. All custom keys, certificates,
// allowlists, and CA issuer configurations will be permanently deleted.
//
// Requires an authenticated session.
func (s *Session) Reset(ctx context.Context) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	cmd := resetCmd()
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: reset: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: reset: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Certificate operations ---

// StoreCertificates stores a list of X.509 certificates associated with
// the given key reference using the GP STORE DATA command.
//
// Certificates are stored in the order provided. For SCP11 key pairs,
// the leaf certificate (containing the device's public key) should
// typically be last in the chain.
//
// Requires an authenticated session.
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

// GetCertificates retrieves the X.509 certificates associated with the
// given key reference. The leaf certificate is last in the returned slice,
// matching the Yubico SDK convention.
//
// Available on both authenticated and unauthenticated sessions.
func (s *Session) GetCertificates(ctx context.Context, ref KeyReference) ([]*x509.Certificate, error) {
	// Build key reference sub-TLV for the GET DATA command.
	keyRefData := buildKeyRefTLV(ref)
	cmd := getDataCmd(p1p2CertStore, keyRefData)

	resp, err := s.transmitCollectAll(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: get certificates: %w", err)
	}
	if !resp.IsSuccess() {
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

// StoreCaIssuer stores the Subject Key Identifier (SKI) for the CA
// associated with the given key reference. This is used in SCP11a/c
// for off-card entity verification.
//
// Requires an authenticated session.
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

// StoreAllowlist stores a certificate serial number allowlist for the
// given key reference. Serial numbers are hex-encoded strings.
//
// If an allowlist is stored, only certificates with matching serials
// will be accepted for SCP11a/c authentication. If no allowlist is
// stored, any certificate signed by the configured CA is accepted.
//
// This performs a full replacement — all existing serials for this
// key reference are replaced.
//
// Requires an authenticated session.
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

// ClearAllowlist removes the certificate serial number allowlist for
// the given key reference. After clearing, any certificate signed by
// the configured CA will be accepted.
//
// Requires an authenticated session.
func (s *Session) ClearAllowlist(ctx context.Context, ref KeyReference) error {
	if err := s.requireAuth(); err != nil {
		return err
	}

	// Clearing the allowlist is done by storing an empty allowlist.
	keyRefData := buildKeyRefTLV(ref)
	emptyList := (&tlv.Node{Tag: tagAllowList}).Encode()

	var payload []byte
	payload = append(payload, keyRefData...)
	payload = append(payload, emptyList...)

	cmd := storeDataCmd(payload)
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return fmt.Errorf("securitydomain: clear allowlist: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("securitydomain: clear allowlist: %w: %w", ErrCardStatus, resp.Error())
	}

	return nil
}

// --- Raw data operations ---

// GetData sends a raw GET DATA command with the given tag and optional
// request data. This is an escape hatch for operations not covered by
// typed methods.
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

// StoreData sends a raw STORE DATA command with the given BER-TLV
// encoded payload. This is an escape hatch for operations not covered
// by typed methods.
//
// Requires an authenticated session.
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

// buildKeyRefTLV builds the key reference sub-TLV used in GET DATA
// and STORE DATA commands: A6 { 83 { KID, KVN } }
func buildKeyRefTLV(ref KeyReference) []byte {
	node := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)
	return node.Encode()
}

// transmitWithChaining sends a command that may exceed 255 bytes by
// splitting it into chained APDUs via the secure channel.
func (s *Session) transmitWithChaining(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// If data fits in a single APDU, send directly.
	if len(cmd.Data) <= 255 {
		return s.transmit(ctx, cmd)
	}

	// Split into chained commands.
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
