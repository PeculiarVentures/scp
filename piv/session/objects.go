package session

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
	pivapdu "github.com/PeculiarVentures/scp/piv/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// Info is a snapshot of session state and active profile, suitable
// for diagnostic output and JSON reporting. It captures things the
// caller already knows about the session (the profile, the auth
// state) so a report can be assembled without poking at session
// internals through getters.
type Info struct {
	// ProfileName is the active profile's Name() value.
	ProfileName string

	// PINVerified is true when a successful VerifyPIN has happened
	// on this session and no operation has cleared the flag.
	PINVerified bool

	// MgmtKeyAuthenticated is true when a successful
	// AuthenticateManagementKey has happened on this session.
	MgmtKeyAuthenticated bool

	// LastGeneratedSlot, LastGeneratedPubKeySet and LastGeneratedPubKey
	// reflect the cached result of the most recent GenerateKey call.
	// LastGeneratedPubKey is nil when no key has been generated.
	LastGeneratedSlot      piv.Slot
	LastGeneratedPubKeySet bool
	LastGeneratedPubKey    crypto.PublicKey
}

// Info returns a snapshot of session state. It does not transmit
// any APDUs; everything reported is local to the session.
//
// For card-side information (firmware version, applet version,
// raw application property template), use piv/profile.Probe
// directly; that data lives on the ProbeResult, not the session.
func (s *Session) Info() Info {
	return Info{
		ProfileName:            s.profile.Name(),
		PINVerified:            s.pinVerified,
		MgmtKeyAuthenticated:   s.mgmtAuthed,
		LastGeneratedSlot:      s.lastGeneratedSlot,
		LastGeneratedPubKeySet: s.lastGeneratedSet,
		LastGeneratedPubKey:    s.lastGeneratedPubKey,
	}
}

// GetCertificate reads the certificate object from a PIV slot and
// parses it as an X.509 certificate.
//
// Returns (nil, nil) when the slot has no certificate installed
// (the card returns an empty 0x53 wrapper). Any other parse failure
// or non-success status word is returned as an error.
//
// No authentication is required to read a slot's certificate;
// PIV certificates are public objects.
func (s *Session) GetCertificate(ctx context.Context, slot piv.Slot) (*x509.Certificate, error) {
	caps := s.profile.Capabilities()
	if !caps.SupportsSlot(slot) {
		return nil, fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}
	cmd, err := pivapdu.GetCertificate(slot.Byte())
	if err != nil {
		return nil, fmt.Errorf("GET CERTIFICATE: build: %w", err)
	}
	resp, err := s.transmit(ctx, "GET CERTIFICATE", cmd)
	if err != nil {
		return nil, err
	}
	der, err := pivapdu.ParseCertificateFromObject(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("GET CERTIFICATE: parse: %w", err)
	}
	if der == nil {
		// Empty wrapper means no cert installed; not an error.
		return nil, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("GET CERTIFICATE: x509 parse: %w", err)
	}
	return cert, nil
}

// DeleteCertificate writes an empty certificate object to a PIV
// slot, which the card interprets as deletion.
//
// Preconditions:
//
//   - Slot must be in the profile's slot set.
//   - The session must be management-key-authenticated.
//
// On YubiKey, deleting the certificate object does not delete the
// slot's private key; that requires a separate vendor-specific
// instruction or a PIV reset. Standard PIV has no analog.
func (s *Session) DeleteCertificate(ctx context.Context, slot piv.Slot) error {
	caps := s.profile.Capabilities()
	if !caps.SupportsSlot(slot) {
		return fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}
	if err := s.requireMgmtAuth("DELETE CERTIFICATE"); err != nil {
		return err
	}
	cmd, err := pivapdu.DeleteCertificate(slot.Byte())
	if err != nil {
		return fmt.Errorf("DELETE CERTIFICATE: build: %w", err)
	}
	if _, err := s.transmit(ctx, "DELETE CERTIFICATE", cmd); err != nil {
		return err
	}
	return nil
}

// ReadObject fetches a PIV data object by ID. PIV data objects are
// public; no authentication is required to read them.
//
// The returned bytes are the raw PIV data object payload (the
// contents of the 0x53 wrapper, with the wrapper itself stripped).
// Standard objects (CHUID, CCC, security object, slot certs) plus
// vendor objects (YubiKey 5FC1xx extensions) are all reachable via
// this method.
//
// Returns (nil, nil) when the object is empty (the card returned a
// well-formed but value-less 0x53 wrapper, the way DeleteCertificate
// leaves a slot).
//
// Lenient TLV handling: if the response does not parse as TLV or
// does not contain a 0x53 wrapper, ReadObject returns the raw
// response bytes rather than an error. Some vendor objects deviate
// from the SP 800-73-4 envelope and a too-strict reader rejects
// cards in the field. Diagnostic and recovery callers want the raw
// bytes; provisioning and compliance callers want strict parsing,
// which is what ReadObjectStrict provides.
func (s *Session) ReadObject(ctx context.Context, object piv.ObjectID) ([]byte, error) {
	if len(object) == 0 {
		return nil, fmt.Errorf("READ OBJECT: %w: object ID is empty", errInvalidArg)
	}
	cmd, err := pivapdu.GetData([]byte(object))
	if err != nil {
		return nil, fmt.Errorf("READ OBJECT: build: %w", err)
	}
	resp, err := s.transmit(ctx, "READ OBJECT", cmd)
	if err != nil {
		return nil, err
	}
	// Strip the 0x53 wrapper from the response. PIV data objects
	// always come back wrapped in 0x53; callers want the inner
	// payload, since that is what they pass to WriteObject and
	// what they hand to a TLV decoder for objects with internal
	// structure (CHUID, CCC) or treat as opaque (vendor objects).
	nodes, err := tlv.Decode(resp.Data)
	if err != nil {
		// Object response that does not parse as TLV. Some
		// vendor-specific objects deviate; return raw bytes so the
		// caller can salvage them.
		return resp.Data, nil
	}
	wrapper := tlv.Find(nodes, 0x53)
	if wrapper == nil {
		// No 0x53 wrapper. Same fallback path: return raw.
		return resp.Data, nil
	}
	if len(wrapper.Value) == 0 {
		// Empty wrapper means the object exists but has been
		// emptied (the shape DeleteCertificate leaves behind).
		// Return (nil, nil) so the caller can distinguish absent
		// from empty.
		return nil, nil
	}
	return wrapper.Value, nil
}

// ReadObjectStrict is the strict counterpart to ReadObject. The card
// response must parse as BER-TLV and must contain a 0x53 wrapper;
// any deviation is an error rather than a fall-through to raw bytes.
//
// Use this for compliance, audit, and provisioning code where a
// silently-malformed card response is a bug, not a vendor quirk.
// Diagnostic code that needs to surface unparseable bytes to a
// human should keep using ReadObject.
func (s *Session) ReadObjectStrict(ctx context.Context, object piv.ObjectID) ([]byte, error) {
	if len(object) == 0 {
		return nil, fmt.Errorf("READ OBJECT (strict): %w: object ID is empty", errInvalidArg)
	}
	cmd, err := pivapdu.GetData([]byte(object))
	if err != nil {
		return nil, fmt.Errorf("READ OBJECT (strict): build: %w", err)
	}
	resp, err := s.transmit(ctx, "READ OBJECT (strict)", cmd)
	if err != nil {
		return nil, err
	}
	nodes, err := tlv.Decode(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("READ OBJECT (strict): response is not BER-TLV: %w", err)
	}
	wrapper := tlv.Find(nodes, 0x53)
	if wrapper == nil {
		return nil, fmt.Errorf("READ OBJECT (strict): response missing 0x53 envelope")
	}
	if len(wrapper.Value) == 0 {
		return nil, nil
	}
	return wrapper.Value, nil
}

// WriteObject stores a PIV data object. The data argument is the
// inner payload (the bytes that go inside the 0x53 wrapper);
// callers do not need to wrap before passing.
//
// Preconditions:
//
//   - The session must be management-key-authenticated.
//
// Object IDs in the slot-certificate range (5FC1xx) should normally
// be written via PutCertificate, which builds the full PIV cert
// object structure (0x70/0x71/0xFE inside 0x53). WriteObject is the
// escape hatch for non-cert objects (CHUID, CCC, vendor objects).
func (s *Session) WriteObject(ctx context.Context, object piv.ObjectID, data []byte) error {
	if len(object) == 0 {
		return fmt.Errorf("WRITE OBJECT: %w: object ID is empty", errInvalidArg)
	}
	if err := s.requireMgmtAuth("WRITE OBJECT"); err != nil {
		return err
	}
	cmd, err := pivapdu.PutData([]byte(object), data)
	if err != nil {
		return fmt.Errorf("WRITE OBJECT: build: %w", err)
	}
	if _, err := s.transmit(ctx, "WRITE OBJECT", cmd); err != nil {
		return err
	}
	return nil
}

// ImportKey installs a caller-supplied EC private key into a PIV
// slot. The current builder supports only NIST P-256 and P-384 EC
// keys (raw 32- or 48-byte scalars); RSA, Ed25519, and X25519
// import are not yet implemented in the apdu layer and are refused
// here with a clear error.
//
// Preconditions:
//
//   - The active profile must claim KeyImport (YubiKey only).
//   - Slot must be in the profile's slot set.
//   - Algorithm must be in the profile's algorithm set.
//   - The session must be management-key-authenticated.
//
// The imported key replaces any existing key in the slot. Any
// previously installed certificate in the slot is left in place;
// callers that intend to install both should follow ImportKey with
// PutCertificate using RequirePubKeyBinding+ExpectedPublicKey to
// guarantee the cert matches the imported key.
func (s *Session) ImportKey(ctx context.Context, slot piv.Slot, opts ImportKeyOptions) error {
	caps := s.profile.Capabilities()
	if !caps.KeyImport {
		return fmt.Errorf("%w: key import not supported by profile %s",
			piv.ErrUnsupportedByProfile, s.profile.Name())
	}
	if !caps.SupportsSlot(slot) {
		return fmt.Errorf("%w: slot %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, slot, s.profile.Name())
	}
	if !caps.SupportsAlgorithm(opts.Algorithm) {
		return fmt.Errorf("%w: algorithm %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, opts.Algorithm, s.profile.Name())
	}
	if err := s.requireMgmtAuth("IMPORT KEY"); err != nil {
		return err
	}
	if len(opts.RawPrivateKey) == 0 {
		return fmt.Errorf("IMPORT KEY: %w: RawPrivateKey is empty", errInvalidArg)
	}

	cmd, err := pivapdu.ImportKey(slot.Byte(), opts.Algorithm.Byte(), opts.RawPrivateKey)
	if err != nil {
		return fmt.Errorf("IMPORT KEY: build: %w", err)
	}
	if _, err := s.transmit(ctx, "IMPORT KEY", cmd); err != nil {
		return err
	}
	return nil
}

// ImportKeyOptions configures an ImportKey call.
type ImportKeyOptions struct {
	// Algorithm names the key type. Currently only AlgorithmECCP256
	// and AlgorithmECCP384 are supported by the underlying APDU
	// builder.
	Algorithm piv.Algorithm

	// RawPrivateKey is the raw EC private key scalar bytes.
	// 32 bytes for P-256, 48 bytes for P-384. The caller is
	// responsible for marshalling from a Go *ecdsa.PrivateKey if
	// that's where the key originated.
	RawPrivateKey []byte
}

// ChangeManagementKey replaces the card's PIV management key.
//
// Preconditions:
//
//   - The session must be authenticated to the current management
//     key (oldKey by definition; AuthenticateManagementKey must have
//     succeeded on this session before this call).
//   - newKey.Algorithm must be in the profile's MgmtKeyAlgs set.
//   - newKey.Validate() must pass (key length matches algorithm).
//
// The card's management-key authentication state is invalidated by
// the change; the session's mgmtAuthed flag is cleared on success.
// Callers that need to perform further mgmt-gated operations must
// re-authenticate with newKey.
func (s *Session) ChangeManagementKey(
	ctx context.Context,
	newKey piv.ManagementKey,
	opts ChangeManagementKeyOptions,
) error {
	caps := s.profile.Capabilities()
	if !caps.SupportsMgmtKeyAlg(newKey.Algorithm) {
		return fmt.Errorf("%w: management-key algorithm %s not supported by profile %s",
			piv.ErrUnsupportedByProfile, newKey.Algorithm, s.profile.Name())
	}
	if err := newKey.Validate(); err != nil {
		return fmt.Errorf("CHANGE MGMT KEY: %w", err)
	}
	if err := s.requireMgmtAuth("CHANGE MGMT KEY"); err != nil {
		return err
	}

	cmd, err := pivapdu.SetManagementKey(newKey.Algorithm.Byte(), newKey.Key)
	if err != nil {
		return fmt.Errorf("CHANGE MGMT KEY: build: %w", err)
	}
	// Touch-required management keys (YubiKey 5.7+ extended SET
	// MANAGEMENT KEY, encoded via P1) are not yet implemented in
	// the underlying APDU builder, which hardcodes the no-touch
	// byte. RequireTouch is rejected unconditionally rather than
	// silently dropped: a caller asking for touch enforcement must
	// not get success without it. This is intentionally stricter
	// than the prior behavior, which only rejected on profiles
	// that lacked TouchPolicy capability and silently accepted
	// otherwise. Lift this when pivapdu.SetManagementKeyWithPolicy
	// is added.
	if opts.RequireTouch {
		return fmt.Errorf("%w: RequireTouch on management key is not yet implemented (pivapdu.SetManagementKey hardcodes the no-touch byte)",
			piv.ErrUnsupportedByProfile)
	}

	if _, err := s.transmit(ctx, "CHANGE MGMT KEY", cmd); err != nil {
		return err
	}
	// Card invalidates the prior auth on key change.
	s.mgmtAuthed = false
	return nil
}

// ChangeManagementKeyOptions configures a ChangeManagementKey call.
type ChangeManagementKeyOptions struct {
	// RequireTouch sets the touch-required flag on the new key
	// (YubiKey 5.7+ extension). Refused under profiles that do not
	// claim TouchPolicy.
	RequireTouch bool
}

// Sentinel imports kept reachable.
var _ = errors.New
