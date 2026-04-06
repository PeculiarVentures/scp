package securitydomain

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// GlobalPlatform APDU instructions for Security Domain management.
const (
	insGetData    byte = 0xCA
	insStoreData  byte = 0xE2
	insPutKey     byte = 0xD8
	insDeleteKey  byte = 0xE4
	insGenAsymKey byte = 0xD8 // Same as PUT KEY, Yubico extension

	clsGP byte = 0x80 // GlobalPlatform class byte
)

// Tag constants for Security Domain TLV structures.
const (
	tagKeyInformation  tlv.Tag = 0xE0
	tagKeyInfoTemplate tlv.Tag = 0xC0
	tagKeyType         tlv.Tag = 0x80
	tagKeyLength       tlv.Tag = 0x81
	tagKeyData         tlv.Tag = 0xA6
	tagKeyCheck        tlv.Tag = 0x86 // not tlv.TagReceipt; same value, different context
	tagCertStore       tlv.Tag = 0xBF21
	tagCertificate     tlv.Tag = 0x7F21
	tagControlRef      tlv.Tag = 0xA6
	tagKeyID           tlv.Tag = 0x83

	// Tags for STORE DATA payloads.
	tagCaKlocID   tlv.Tag = 0x42 // CA-KLOC identifier (SKI)
	tagAllowList  tlv.Tag = 0x70 // Allow list container
	tagSerialNum  tlv.Tag = 0x93 // Certificate serial number

	// GET DATA P1P2 tags (2-byte tag encoded in P1-P2).
	p1p2KeyInfo     uint16 = 0x00E0
	p1p2CardData    uint16 = 0x0066
	p1p2CertStore   uint16 = 0xBF21
	p1p2CaKlocID    uint16 = 0x0042
	p1p2CaKlccID    uint16 = 0x1042
	p1p2AllowList   uint16 = 0x0070
)

// --- APDU construction ---

// getDataCmd builds a GET DATA command for the given P1-P2 tag,
// with optional TLV-encoded request data.
func getDataCmd(p1p2 uint16, data []byte) *apdu.Command {
	return &apdu.Command{
		CLA:  clsGP,
		INS:  insGetData,
		P1:   byte(p1p2 >> 8),
		P2:   byte(p1p2),
		Data: data,
		Le:   0,
	}
}

// storeDataCmd builds a STORE DATA command. The data must be BER-TLV
// encoded per GP Card Spec v2.3.1 §11.11.
//
// P1 encoding:
//
//	b8=1: last (or only) block
//	b5-b4=10: BER-TLV encoded data
//	b7-b6=00: no encryption
func storeDataCmd(data []byte) *apdu.Command {
	return &apdu.Command{
		CLA:  clsGP,
		INS:  insStoreData,
		P1:   0x90, // last block | BER-TLV
		P2:   0x00,
		Data: data,
	}
}

// putKeyCmd builds a PUT KEY command for SCP03 static keys.
// GP Card Spec v2.3.1 §11.8.
//
// P1 = version number of key being replaced (0 = new key)
// P2 = key ID | b8 set if more than one key in command
func putKeySCP03Cmd(ref KeyReference, encKey, macKey, dekKey []byte, replaceKvn byte) (*apdu.Command, []byte, error) {
	if len(encKey) != 16 || len(macKey) != 16 || len(dekKey) != 16 {
		return nil, nil, fmt.Errorf("%w: SCP03 keys must be 16 bytes (AES-128)", ErrInvalidKey)
	}

	// Each key component is encoded as:
	//   key type (1) | key length (1) | key data (16) | KCV length (1) | KCV (3)
	// Key type 0x88 = AES, length 0x10 = 16 bytes
	encodeKey := func(key []byte) []byte {
		kcv := computeAESKCV(key)
		var b []byte
		b = append(b, 0x88, 0x10) // AES, 16 bytes
		b = append(b, key...)
		b = append(b, 0x03) // KCV length
		b = append(b, kcv...)
		return b
	}

	var data []byte
	data = append(data, ref.Version) // new key version number
	data = append(data, encodeKey(encKey)...)
	data = append(data, encodeKey(macKey)...)
	data = append(data, encodeKey(dekKey)...)

	p2 := ref.ID | 0x80 // b8 set: multiple keys in command

	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  insPutKey,
		P1:   replaceKvn,
		P2:   p2,
		Data: data,
	}

	// Expected KCV for verification (ENC key's KCV).
	expectedKCV := computeAESKCV(encKey)
	return cmd, expectedKCV, nil
}

// putKeyECPrivateCmd builds a PUT KEY command for an EC private key.
// This is a Yubico extension to the GP PUT KEY command.
func putKeyECPrivateCmd(ref KeyReference, key *ecdsa.PrivateKey, replaceKvn byte) (*apdu.Command, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST P-256 keys are supported", ErrInvalidKey)
	}

	privBytes := key.D.Bytes()
	// Pad to 32 bytes if needed.
	for len(privBytes) < 32 {
		privBytes = append([]byte{0x00}, privBytes...)
	}

	var data []byte
	data = append(data, ref.Version)
	// EC private key: type 0xB1, length 0x20
	data = append(data, 0xB1, byte(len(privBytes)))
	data = append(data, privBytes...)
	data = append(data, 0x00) // no KCV for EC keys

	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  insPutKey,
		P1:   replaceKvn,
		P2:   ref.ID,
		Data: data,
	}
	return cmd, nil
}

// putKeyECPublicCmd builds a PUT KEY command for an EC public key.
// Used for importing OCE public keys.
func putKeyECPublicCmd(ref KeyReference, key *ecdsa.PublicKey, replaceKvn byte) (*apdu.Command, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST P-256 keys are supported", ErrInvalidKey)
	}

	pubBytes := elliptic.Marshal(key.Curve, key.X, key.Y)

	var data []byte
	data = append(data, ref.Version)
	// EC public key: type 0xB0, length = uncompressed point size
	data = append(data, 0xB0, byte(len(pubBytes)))
	data = append(data, pubBytes...)
	data = append(data, 0x00) // no KCV

	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  insPutKey,
		P1:   replaceKvn,
		P2:   ref.ID,
		Data: data,
	}
	return cmd, nil
}

// generateECKeyCmd builds the Yubico-specific GENERATE ASYMMETRIC KEY
// command, which reuses the PUT KEY INS with a marker key type.
func generateECKeyCmd(ref KeyReference, replaceKvn byte) *apdu.Command {
	var data []byte
	data = append(data, ref.Version)
	// Key type 0xB0 (EC public key placeholder), length 0
	// signals generation rather than import.
	data = append(data, 0xB0, 0x00)
	data = append(data, 0x00) // no KCV

	return &apdu.Command{
		CLA:  clsGP,
		INS:  insGenAsymKey,
		P1:   replaceKvn,
		P2:   ref.ID,
		Data: data,
	}
}

// deleteKeyCmd builds a DELETE KEY command.
// GP Card Spec v2.3.1 §11.5.
//
// The data field contains TLV-encoded key identifiers.
// Tag D0: key ID, Tag D2: key version number.
func deleteKeyCmd(ref KeyReference, deleteLast bool) (*apdu.Command, error) {
	if ref.ID == 0 && ref.Version == 0 {
		return nil, errors.New("at least one of KID or KVN must be non-zero")
	}

	var data []byte

	if ref.ID != 0 {
		data = append(data, 0xD0, 0x01, ref.ID)
	}
	if ref.Version != 0 {
		data = append(data, 0xD2, 0x01, ref.Version)
	}

	p2 := byte(0x00)
	if deleteLast {
		p2 = 0x01 // GP extension: acknowledge deleting last key
	}

	return &apdu.Command{
		CLA:  clsGP,
		INS:  insDeleteKey,
		P1:   0x00,
		P2:   p2,
		Data: data,
	}, nil
}

// resetCmd builds the Yubico Security Domain RESET command.
// This is a proprietary command that restores factory defaults.
func resetCmd() *apdu.Command {
	return &apdu.Command{
		CLA: clsGP,
		INS: insStoreData,
		P1:  0x9A, // reset indicator
		P2:  0xA0,
	}
}

// storeCertificatesData builds the STORE DATA payload for certificate storage.
// Certificates are wrapped in 7F21 tags inside a BF21 container,
// keyed by a control reference template with the key reference.
func storeCertificatesData(ref KeyReference, certsDER [][]byte) []byte {
	// Build key reference TLV: A6 { 83 { KID, KVN } }
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	// Build certificate entries: 7F21 { raw DER }
	var certNodes []*tlv.Node
	certNodes = append(certNodes, keyRefTLV)
	for _, der := range certsDER {
		certNodes = append(certNodes, tlv.Build(tagCertificate, der))
	}

	container := tlv.BuildConstructed(tagCertStore, certNodes...)
	return container.Encode()
}

// storeCaIssuerData builds the STORE DATA payload for CA issuer (SKI).
func storeCaIssuerData(ref KeyReference, ski []byte) []byte {
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)
	skiTLV := tlv.Build(tagCaKlocID, ski)

	var data []byte
	data = append(data, keyRefTLV.Encode()...)
	data = append(data, skiTLV.Encode()...)
	return data
}

// storeAllowlistData builds the STORE DATA payload for a certificate
// serial number allowlist.
func storeAllowlistData(ref KeyReference, serials []string) ([]byte, error) {
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	var serialNodes []*tlv.Node
	for _, s := range serials {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidSerial, s, err)
		}
		serialNodes = append(serialNodes, tlv.Build(tagSerialNum, b))
	}

	allowlistTLV := tlv.BuildConstructed(tagAllowList, serialNodes...)

	var data []byte
	data = append(data, keyRefTLV.Encode()...)
	data = append(data, allowlistTLV.Encode()...)
	return data, nil
}

// --- Response parsing ---

// parseKeyInformation parses a GET DATA [Key Information] response
// into a slice of KeyInfo records.
//
// Response format (GP Card Spec v2.3.1 §11.3.3):
//
//	E0 {
//	  C0 { KID(1) KVN(1) component-type(1) component-length(1) ... }
//	  C0 { ... }
//	}
func parseKeyInformation(data []byte) ([]KeyInfo, error) {
	if len(data) == 0 {
		return nil, nil
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: key information: %v", ErrInvalidResponse, err)
	}

	// Find E0 container.
	container := tlv.Find(nodes, tagKeyInformation)
	if container == nil {
		// Some cards return C0 entries directly without E0 wrapper.
		container = &tlv.Node{Children: nodes}
	}

	var infos []KeyInfo
	for _, child := range container.Children {
		if child.Tag != tagKeyInfoTemplate {
			continue
		}
		if len(child.Value) < 2 {
			continue
		}
		info := KeyInfo{
			Reference:  NewKeyReference(child.Value[0], child.Value[1]),
			Components: make(map[byte]byte),
		}
		// Remaining bytes are pairs: component-type, component-length
		rest := child.Value[2:]
		for len(rest) >= 2 {
			info.Components[rest[0]] = rest[1]
			rest = rest[2:]
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// parseCertificates parses a GET DATA [Certificate Store] response
// into a slice of raw DER-encoded certificates.
//
// Response format:
//
//	BF21 {
//	  7F21 { cert DER }
//	  7F21 { cert DER }
//	}
func parseCertificates(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		// Might be a single raw DER certificate.
		return [][]byte{data}, nil
	}

	// Find BF21 container.
	store := tlv.Find(nodes, tagCertStore)
	if store == nil {
		// Try to find 7F21 entries at top level.
		store = &tlv.Node{Children: nodes}
	}

	certNodes := tlv.FindAll(store.Children, tagCertificate)
	if len(certNodes) == 0 {
		// Single cert without wrapper.
		return [][]byte{data}, nil
	}

	var certs [][]byte
	for _, n := range certNodes {
		certs = append(certs, n.Value)
	}
	return certs, nil
}

// parseSupportedCaIdentifiers parses the GET DATA response for
// CA identifiers into a map of KeyReference -> SKI bytes.
func parseSupportedCaIdentifiers(data []byte) ([]CaIdentifier, error) {
	if len(data) == 0 {
		return nil, nil
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: CA identifiers: %v", ErrInvalidResponse, err)
	}

	var result []CaIdentifier
	for _, n := range nodes {
		if n.Tag == tagControlRef && len(n.Children) > 0 {
			// Look for key ID and SKI within the control ref template.
			kidNode := tlv.Find(n.Children, tagKeyID)
			skiNode := tlv.Find(n.Children, tagCaKlocID)
			if kidNode != nil && len(kidNode.Value) >= 2 && skiNode != nil {
				result = append(result, CaIdentifier{
					Reference: NewKeyReference(kidNode.Value[0], kidNode.Value[1]),
					SKI:       skiNode.Value,
				})
			}
		}
	}
	return result, nil
}

// parseGeneratedPublicKey extracts the EC public key from a
// GenerateEcKey response.
func parseGeneratedPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty generate key response", ErrInvalidResponse)
	}

	// Response may contain:
	// 1. Raw EC point (65 bytes, 0x04 prefix)
	// 2. TLV-wrapped EC point

	// Try raw point first.
	if len(data) >= 65 && data[0] == 0x04 {
		return unmarshalP256Point(data[:65])
	}

	// Try TLV decoding.
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: generate key response: %v", ErrInvalidResponse, err)
	}

	// Search for a 65-byte uncompressed point in any node.
	return findPublicKeyInNodes(nodes)
}

func findPublicKeyInNodes(nodes []*tlv.Node) (*ecdsa.PublicKey, error) {
	for _, n := range nodes {
		if len(n.Value) == 65 && n.Value[0] == 0x04 {
			return unmarshalP256Point(n.Value)
		}
		if len(n.Children) > 0 {
			if key, err := findPublicKeyInNodes(n.Children); err == nil {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no EC public key in response", ErrInvalidResponse)
}

func unmarshalP256Point(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, fmt.Errorf("%w: invalid P-256 point", ErrInvalidKey)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// parseAllowlist parses an allowlist response into hex-encoded serial strings.
func parseAllowlist(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: allowlist: %v", ErrInvalidResponse, err)
	}

	container := tlv.Find(nodes, tagAllowList)
	if container == nil {
		container = &tlv.Node{Children: nodes}
	}

	var serials []string
	for _, n := range container.Children {
		if n.Tag == tagSerialNum {
			serials = append(serials, hex.EncodeToString(n.Value))
		}
	}
	return serials, nil
}

// parsePutKeyChecksum extracts the KCV from a PUT KEY response.
func parsePutKeyChecksum(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Response is: KVN (1 byte) | KCV for each key component (3 bytes each)
	// Minimum: 1 + 3 = 4 bytes for a single key
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: PUT KEY response too short (%d bytes)", ErrInvalidResponse, len(data))
	}

	// Return the first KCV (3 bytes after the version byte).
	return data[1:4], nil
}

// --- Key check value computation ---

// computeAESKCV computes the Key Check Value for an AES key.
// KCV = first 3 bytes of AES-ECB(key, 0x00...00).
// GP Card Spec v2.3.1 §F.2.
func computeAESKCV(key []byte) []byte {
	if len(key) != 16 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, make([]byte, aes.BlockSize))
	return out[:3]
}

// parseSerialFromBigInt converts a *big.Int certificate serial to the
// hex string format expected by the allowlist APIs.
func SerialToHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}

// SerialFromHex converts a hex-encoded serial string to *big.Int.
func SerialFromHex(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrInvalidSerial, s, err)
	}
	return new(big.Int).SetBytes(b), nil
}
