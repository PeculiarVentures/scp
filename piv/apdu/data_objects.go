package pivapdu

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/tlv"
)

// PIV PIN reference values for VERIFY / CHANGE REFERENCE DATA /
// RESET RETRY COUNTER (NIST SP 800-73-4 Part 2 Table 6).
//
// PINKeyRef and PUKKeyRef live in reset_retry.go because the original
// builder used them; PIV has only the application PIN (0x80) and the
// PUK (0x81) at the user level. The global PIN (0x00) is a separate
// reference defined by SP 800-73-4 but not in scope for this session
// API.

// ChangePIN builds the CHANGE REFERENCE DATA command for the
// application PIN (NIST SP 800-73-4 Part 2 §3.2.2). The card
// requires the current PIN to authorize replacement; the data field
// is oldPIN (8 bytes, 0xFF padded) || newPIN (8 bytes, 0xFF padded).
//
// Wrong oldPIN decrements the PIN retry counter the same way VERIFY
// does. The session method that wraps this call clears the
// PIN-verified flag on success because the card considers the prior
// VERIFY consumed when CHANGE REFERENCE DATA replaces the PIN.
func ChangePIN(oldPIN, newPIN []byte) (*apdu.Command, error) {
	if len(oldPIN) == 0 || len(oldPIN) > piv.MaxPINLength {
		return nil, fmt.Errorf("old PIN length %d outside [1, %d]", len(oldPIN), piv.MaxPINLength)
	}
	if len(newPIN) == 0 || len(newPIN) > piv.MaxPINLength {
		return nil, fmt.Errorf("new PIN length %d outside [1, %d]", len(newPIN), piv.MaxPINLength)
	}

	data := make([]byte, 0, 2*piv.MaxPINLength)
	data = append(data, padPIN(oldPIN)...)
	data = append(data, padPIN(newPIN)...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0x24, // CHANGE REFERENCE DATA
		P1:   0x00,
		P2:   PINKeyRef,
		Data: data,
		Le:   -1,
	}, nil
}

// ChangePUK builds the CHANGE REFERENCE DATA command for the PUK.
// Same wire shape as ChangePIN but P2=0x81 (PUK reference).
//
// Wrong oldPUK decrements the PUK retry counter; PUK blocking on a
// YubiKey-flavored card means the only path forward is the YubiKey
// PIV reset, and on a Standard PIV card the recovery is out of band.
func ChangePUK(oldPUK, newPUK []byte) (*apdu.Command, error) {
	if len(oldPUK) == 0 || len(oldPUK) > piv.MaxPINLength {
		return nil, fmt.Errorf("old PUK length %d outside [1, %d]", len(oldPUK), piv.MaxPINLength)
	}
	if len(newPUK) == 0 || len(newPUK) > piv.MaxPINLength {
		return nil, fmt.Errorf("new PUK length %d outside [1, %d]", len(newPUK), piv.MaxPINLength)
	}

	data := make([]byte, 0, 2*piv.MaxPINLength)
	data = append(data, padPIN(oldPUK)...)
	data = append(data, padPIN(newPUK)...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0x24,
		P1:   0x00,
		P2:   PUKKeyRef,
		Data: data,
		Le:   -1,
	}, nil
}

// GetData builds a GET DATA command for the given PIV data object
// tag (NIST SP 800-73-4 Part 2 §3.1.2). The 3-byte object ID goes
// into the data field as a TLV under tag 0x5C.
//
// Standard PIV objects use 5FC1xx tags (Table 3); the YubiKey 5FC10x
// extensions for cert metadata are also retrieved through this path.
func GetData(objectID []byte) (*apdu.Command, error) {
	if len(objectID) == 0 {
		return nil, errors.New("object ID cannot be empty")
	}
	tag := tlv.Build(tlv.Tag(0x5C), objectID)
	return &apdu.Command{
		CLA:  0x00,
		INS:  0xCB, // GET DATA
		P1:   0x3F,
		P2:   0xFF,
		Data: tag.Encode(),
		Le:   0,
	}, nil
}

// PutData builds a PUT DATA command for the given object ID and
// pre-encoded data value. The data argument is the value bytes that
// will be wrapped under tag 0x53 by this function; callers do not
// need to wrap before calling.
//
// Use PutCertificate (in commands.go) for slot certificate writes;
// PutData is the lower-level escape hatch for non-certificate
// objects (CHUID, CCC, security object, vendor objects, etc).
func PutData(objectID, value []byte) (*apdu.Command, error) {
	if len(objectID) == 0 {
		return nil, errors.New("object ID cannot be empty")
	}

	objIDTLV := tlv.Build(tlv.Tag(0x5C), objectID)
	dataTLV := tlv.Build(tlv.Tag(0x53), value)

	var data []byte
	data = append(data, objIDTLV.Encode()...)
	data = append(data, dataTLV.Encode()...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0xDB, // PUT DATA
		P1:   0x3F,
		P2:   0xFF,
		Data: data,
		Le:   -1,
	}, nil
}

// GetCertificate builds a GET DATA command for the certificate
// object in a PIV slot. Convenience wrapper around GetData using
// SlotToObjectID for the standard slot-to-object mapping.
func GetCertificate(slot byte) (*apdu.Command, error) {
	objID, err := SlotToObjectID(slot)
	if err != nil {
		return nil, err
	}
	return GetData(objID)
}

// DeleteCertificate builds a PUT DATA command that writes an empty
// certificate object to a slot, which the card interprets as
// deletion. The slot's keypair (if any) is unaffected.
//
// On YubiKey, deleting the certificate object does not delete the
// slot's private key; that requires a separate vendor-specific
// instruction (or a PIV reset).
func DeleteCertificate(slot byte) (*apdu.Command, error) {
	objID, err := SlotToObjectID(slot)
	if err != nil {
		return nil, err
	}

	objIDTLV := tlv.Build(tlv.Tag(0x5C), objID)
	emptyDataTLV := tlv.Build(tlv.Tag(0x53), nil)

	var data []byte
	data = append(data, objIDTLV.Encode()...)
	data = append(data, emptyDataTLV.Encode()...)

	return &apdu.Command{
		CLA:  0x00,
		INS:  0xDB,
		P1:   0x3F,
		P2:   0xFF,
		Data: data,
		Le:   -1,
	}, nil
}

// SlotToObjectID maps a PIV slot to its certificate data object ID
// (NIST SP 800-73-4 Part 1 Table 10). Exported so the session
// package can reach it for object-level operations without
// duplicating the table.
func SlotToObjectID(slot byte) ([]byte, error) {
	return slotToObjectID(slot)
}

// ParseCertificateFromObject extracts the DER-encoded certificate
// bytes from a PIV certificate data object (the response payload
// from GetCertificate). The object format is:
//
//	53 LL                      data object wrapper
//	  70 LL <cert DER>         certificate
//	  71 01 <CertInfo byte>    optional, 0x00 = uncompressed
//	  FE 00                    optional EDC (always empty)
//
// Returns the cert DER bytes for x509.ParseCertificate. Errors out
// if the response is empty or malformed. An empty 0x53 wrapper
// (which the card returns for a slot that has been deleted)
// produces a nil byte slice and no error so callers can distinguish
// "no cert" from a parse failure.
func ParseCertificateFromObject(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty certificate object response")
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode 0x53 wrapper: %w", err)
	}
	wrapper := tlv.Find(nodes, 0x53)
	if wrapper == nil {
		return nil, errors.New("certificate object missing 0x53 wrapper")
	}
	if len(wrapper.Value) == 0 {
		// Empty wrapper means the slot's certificate has been
		// deleted; not an error, just absence.
		return nil, nil
	}

	inner, err := tlv.Decode(wrapper.Value)
	if err != nil {
		return nil, fmt.Errorf("decode wrapper contents: %w", err)
	}
	cert := tlv.Find(inner, 0x70)
	if cert == nil {
		return nil, errors.New("certificate object missing 0x70 cert tag")
	}
	if len(cert.Value) == 0 {
		return nil, errors.New("certificate object 0x70 tag has empty value")
	}
	return cert.Value, nil
}
