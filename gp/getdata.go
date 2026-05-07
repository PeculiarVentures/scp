package gp

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp/cplc"
)

// Transmitter is the minimal APDU pipe the GET DATA helpers need.
// Satisfied by transport.Transport directly; defined here so this
// package does not depend on transport (which would pull in CGo
// build tags from the PC/SC backend).
type Transmitter interface {
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)
}

// errNotPresent is the sentinel returned by readOptionalGetData for
// SW=6A88 ("referenced data not found") and other "this card doesn't
// have that object" status words. Callers translate this into nil
// data + nil error so probe code can iterate optional reads without
// branching on each tag.
var errNotPresent = errors.New("gp: object not present")

// readOptionalGetData runs GET DATA at the given tag and returns the
// response data on 9000, nil on 6A88/6A82 (object not present), and
// a wrapped APDU error on any other SW. The 2-byte tag is split
// into P1/P2 in the natural big-endian way.
//
// The caller decides how to interpret 6A88 — most probe readers
// translate a nil result to "not present" rather than a hard error.
// readOptionalGetData itself returns errNotPresent so callers using
// errors.Is can distinguish the not-present case from a real failure.
func readOptionalGetData(ctx context.Context, t Transmitter, tag uint16) ([]byte, error) {
	if t == nil {
		return nil, errors.New("gp: nil transmitter")
	}
	cmd := apdu.NewGetData(0x80, tag)
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("gp: GET DATA tag 0x%04X: %w", tag, err)
	}
	switch resp.StatusWord() {
	case 0x9000:
		// Clone so callers can retain the slice independently of
		// any pooling the transport layer might do with the
		// response buffer.
		out := make([]byte, len(resp.Data))
		copy(out, resp.Data)
		return out, nil
	case 0x6A88, 0x6A82:
		return nil, errNotPresent
	default:
		return nil, fmt.Errorf("gp: GET DATA tag 0x%04X: SW=%04X", tag, resp.StatusWord())
	}
}

// IsNotPresent reports whether err signals that the card does not
// carry the requested GET DATA object. Callers use this to skip
// optional fields in probe reports without treating them as
// failures.
func IsNotPresent(err error) bool {
	return errors.Is(err, errNotPresent)
}

// ReadCPLC reads Card Production Life Cycle data via GET DATA tag
// 0x9F7F and parses the result into a cplc.Data. Returns
// (nil, nil) if the card does not carry CPLC (SW=6A88 or 6A82) so
// probe code can treat absence as informational rather than an
// error. Real cards in the wild differ: SafeNet eToken Fusion
// returns a fully populated CPLC, YubiKey 5.x returns CPLC with
// random per-card serial bytes in the date fields (the parser
// tolerates those — see gp/cplc), and some cards return 6A88
// because they treat CPLC as a personalization-only object.
//
// The returned bytes are the GET DATA response, which on most
// cards begins with the 9F 7F 2A tag/length header followed by
// the 42-byte payload. cplc.Parse accepts either the wrapped or
// the bare form.
func ReadCPLC(ctx context.Context, t Transmitter) (*cplc.Data, error) {
	raw, err := readOptionalGetData(ctx, t, 0x9F7F)
	if err != nil {
		if IsNotPresent(err) {
			return nil, nil
		}
		return nil, err
	}
	d, err := cplc.Parse(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("gp: parse CPLC: %w", err)
	}
	return d, nil
}

// ReadIIN reads the Issuer Identification Number via GET DATA tag
// 0x0042. Returns nil if the card does not carry IIN. The bytes
// are returned verbatim — no structure parsing — because IIN
// content is issuer-defined; most cards put an ISO/IEC 7812-style
// numeric IIN here, but some embed ASCII vendor names (the SafeNet
// eToken Fusion's IIN bytes decode to "GEMALTO " in ASCII).
//
// The returned bytes typically begin with tag 0x42 and a 1-byte
// length, followed by the IIN value. Callers wanting just the
// value strip the 2-byte header.
func ReadIIN(ctx context.Context, t Transmitter) ([]byte, error) {
	return readOptionalGetDataOrSkip(ctx, t, 0x0042)
}

// ReadCIN reads the Card Image Number via GET DATA tag 0x0045.
// Returns nil if the card does not carry CIN. CIN is a per-card
// unique identifier derived from CPLC fields plus the issuer
// identifier; format is GP §H.7. The bytes are returned verbatim;
// the response typically starts with tag 0x45 and a 1-byte length.
func ReadCIN(ctx context.Context, t Transmitter) ([]byte, error) {
	return readOptionalGetDataOrSkip(ctx, t, 0x0045)
}

// ReadKDD reads Key Diversification Data via GET DATA tag 0x00CF.
// Returns nil if the card does not carry KDD. KDD is opaque card-
// specific input used to diversify the issuer master keys into
// the card-specific keys used during SCP03 authentication. The
// bytes are returned verbatim because the structure is vendor-
// specific. Callers using KDD typically pass it through to a
// host-side key derivation function provided by the issuer.
func ReadKDD(ctx context.Context, t Transmitter) ([]byte, error) {
	return readOptionalGetDataOrSkip(ctx, t, 0x00CF)
}

// ReadSSC reads the Sequence Counter / Secure Channel Sequence
// Counter via GET DATA tag 0x00C1. Returns nil if the card does
// not carry SSC. SSC is informational — it tracks how many times
// the card has been authenticated to (or how many sessions have
// been established), useful for change-detection in deployment
// tracking. The bytes are returned verbatim; tag 0xC1 and a
// 1-byte length prefix are typical.
func ReadSSC(ctx context.Context, t Transmitter) ([]byte, error) {
	return readOptionalGetDataOrSkip(ctx, t, 0x00C1)
}

// ReadCardCapabilities reads Card Capability Information via GET
// DATA tag 0x0067. Returns nil if the card does not carry the
// object (most cards observed to date — SafeNet eToken Fusion and
// YubiKey 5.x both return SW=6A88 for this tag).
//
// The returned bytes are not parsed: GP Card Spec v2.3.1 §H.4
// defines the structure as BER-TLV with sub-tags enumerating SCP
// versions, supported algorithms, and key-management capabilities,
// but the sub-tag numbering and semantics drifted between GP 2.1.1,
// 2.2, and 2.3.1, and the inner OID values are sparsely documented
// outside the spec itself. Returning raw bytes preserves the data
// for the operator without committing to a specific schema. A
// structured parser lands when there's a card to validate it
// against; until then the hex view is honest and gives operators
// the same view gppro shows.
//
// The bytes typically begin with tag 0x67 and a 1-byte length,
// followed by the value field. Callers can split the outer
// header before display.
func ReadCardCapabilities(ctx context.Context, t Transmitter) ([]byte, error) {
	return readOptionalGetDataOrSkip(ctx, t, 0x0067)
}

// readOptionalGetDataOrSkip is readOptionalGetData with the
// IsNotPresent translation applied, so the four IIN/CIN/KDD/SSC
// helpers above all share the (data, err)/(nil, nil)/(nil, err)
// shape without each one re-doing the IsNotPresent check.
func readOptionalGetDataOrSkip(ctx context.Context, t Transmitter, tag uint16) ([]byte, error) {
	raw, err := readOptionalGetData(ctx, t, tag)
	if err != nil {
		if IsNotPresent(err) {
			return nil, nil
		}
		return nil, err
	}
	return raw, nil
}
