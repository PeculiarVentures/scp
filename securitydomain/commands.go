package securitydomain

// APDU construction and response parsing for Security Domain management.
//
// Encoding has been validated against two Yubico reference implementations:
//   - Python: yubikey-manager/yubikit/securitydomain.py
//   - C#:    Yubico.NET.SDK SecurityDomainSession.cs

import (
	"crypto/aes"
	"crypto/cipher"
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
	insGetData     byte = 0xCA
	insStoreData   byte = 0xE2
	insPutKey      byte = 0xD8
	insDeleteKey   byte = 0xE4
	insGenerateKey byte = 0xF1 // Yubico extension — NOT 0xD8

	// Instructions used by the reset/lockout mechanism.
	insInitializeUpdate byte = 0x50
	insExtAuth          byte = 0x82
	insIntAuth          byte = 0x88
	insPerformSecOp     byte = 0x2A

	clsGP byte = 0x80 // GlobalPlatform class byte
)

// Key type constants for PUT KEY / GENERATE KEY TLV encoding.
const (
	keyTypeAES       byte = 0x88
	keyTypeECPublic  byte = 0xB0
	keyTypeECPrivate byte = 0xB1
	keyTypeECParams  byte = 0xF0
)

// Tag constants for Security Domain TLV structures.
const (
	tagKeyInformation  tlv.Tag = 0xE0
	tagKeyInfoTemplate tlv.Tag = 0xC0
	tagCertStore       tlv.Tag = 0xBF21
	tagControlRef      tlv.Tag = 0xA6
	tagKeyID           tlv.Tag = 0x83
	tagCaKlocID        tlv.Tag = 0x42 // CA-KLOC/KLCC SKI
	tagAllowList       tlv.Tag = 0x70
	tagSerialNum       tlv.Tag = 0x93

	// GET DATA P1P2 tags.
	p1p2KeyInfo   uint16 = 0x00E0
	p1p2CardData  uint16 = 0x0066
	p1p2CertStore uint16 = 0xBF21

	// CA identifier tags — ref: Python TAG_CA_KLOC_IDENTIFIERS / TAG_CA_KLCC_IDENTIFIERS
	p1p2CaKlocID uint16 = 0xFF33
	p1p2CaKlccID uint16 = 0xFF34
)

// --- APDU construction ---

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

func storeDataCmd(data []byte) *apdu.Command {
	return &apdu.Command{
		CLA:  clsGP,
		INS:  insStoreData,
		P1:   0x90, // last block | BER-TLV
		P2:   0x00,
		Data: data,
	}
}

// putKeySCP03Cmd builds a PUT KEY command for SCP03 static keys.
// GP Card Spec v2.3.1 §11.8.
//
// Key material is encrypted with the session DEK before transmission.
// KCV = AES-CBC(key, IV=zeros, data=ones)[:3]
//
// Ref: Python put_key (StaticKeys branch) and C# PutKey(StaticKeys).
func putKeySCP03Cmd(ref KeyReference, encKey, macKey, dekKey, sessionDEK []byte, replaceKvn byte) (*apdu.Command, []byte, error) {
	if len(encKey) != 16 || len(macKey) != 16 || len(dekKey) != 16 {
		return nil, nil, fmt.Errorf("%w: SCP03 keys must be 16 bytes (AES-128)", ErrInvalidKey)
	}
	if len(sessionDEK) != 16 {
		return nil, nil, fmt.Errorf("%w: session DEK must be 16 bytes", ErrInvalidKey)
	}

	var data []byte
	var expectedKCVs []byte

	data = append(data, ref.Version) // new key version number
	expectedKCVs = append(expectedKCVs, ref.Version)

	for _, key := range [][]byte{encKey, macKey, dekKey} {
		// Compute KCV: AES-CBC(key, IV=0x00*16, data=0x01*16)[:3]
		kcv := computeAESKCV(key)

		// Encrypt key with session DEK: AES-CBC(DEK, IV=0x00*16, key)
		encryptedKey := aesCBCEncrypt(sessionDEK, key)

		// Encode: Tlv(0x88, encrypted_key) + kcv_len(1) + kcv(3)
		keyTLV := tlv.Build(tlv.Tag(keyTypeAES), encryptedKey)
		data = append(data, keyTLV.Encode()...)
		data = append(data, byte(len(kcv)))
		data = append(data, kcv...)

		expectedKCVs = append(expectedKCVs, kcv...)
	}

	p2 := ref.ID | 0x80 // b8 set: multiple keys in command

	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  insPutKey,
		P1:   replaceKvn,
		P2:   p2,
		Data: data,
	}

	return cmd, expectedKCVs, nil
}

// putKeyECPrivateCmd builds a PUT KEY command for an EC private key.
// The private key bytes are encrypted with the session DEK.
//
// Ref: Python put_key (EllipticCurvePrivateKey branch), C# PutKey(ECPrivateKey).
func putKeyECPrivateCmd(ref KeyReference, key *ecdsa.PrivateKey, sessionDEK []byte, replaceKvn byte) (*apdu.Command, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST P-256 keys are supported", ErrInvalidKey)
	}
	if len(sessionDEK) != 16 {
		return nil, fmt.Errorf("%w: session DEK must be 16 bytes", ErrInvalidKey)
	}

	privBytes := key.D.Bytes()
	for len(privBytes) < 32 {
		privBytes = append([]byte{0x00}, privBytes...)
	}

	// Encrypt private key with session DEK.
	encryptedPriv := aesCBCEncrypt(sessionDEK, privBytes)

	var data []byte
	data = append(data, ref.Version)

	// B1 TLV with encrypted private key
	privTLV := tlv.Build(tlv.Tag(keyTypeECPrivate), encryptedPriv)
	data = append(data, privTLV.Encode()...)

	// F0 TLV: EC key params (0x00 = SECP256R1)
	paramsTLV := tlv.Build(tlv.Tag(keyTypeECParams), []byte{0x00})
	data = append(data, paramsTLV.Encode()...)

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

// putKeyECPublicCmd builds a PUT KEY command for an EC public key.
// Public keys are NOT encrypted (only private keys and symmetric keys are).
//
// Ref: Python put_key (EllipticCurvePublicKey branch), C# PutKey(ECPublicKey).
func putKeyECPublicCmd(ref KeyReference, key *ecdsa.PublicKey, replaceKvn byte) (*apdu.Command, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST P-256 keys are supported", ErrInvalidKey)
	}

	pubBytes := elliptic.Marshal(key.Curve, key.X, key.Y)

	var data []byte
	data = append(data, ref.Version)

	// B0 TLV with uncompressed public point
	pubTLV := tlv.Build(tlv.Tag(keyTypeECPublic), pubBytes)
	data = append(data, pubTLV.Encode()...)

	// F0 TLV: EC key params (0x00 = SECP256R1)
	paramsTLV := tlv.Build(tlv.Tag(keyTypeECParams), []byte{0x00})
	data = append(data, paramsTLV.Encode()...)

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

// generateECKeyCmd builds the Yubico-specific GENERATE KEY command.
// INS = 0xF1 (NOT 0xD8 PUT KEY). Data = KVN + Tlv(0xF0, [curve]).
//
// Ref: Python generate_ec_key, C# GenerateEcKey.
func generateECKeyCmd(ref KeyReference, replaceKvn byte) *apdu.Command {
	var data []byte
	data = append(data, ref.Version)

	// F0 TLV: EC key params (0x00 = SECP256R1)
	paramsTLV := tlv.Build(tlv.Tag(keyTypeECParams), []byte{0x00})
	data = append(data, paramsTLV.Encode()...)

	return &apdu.Command{
		CLA:  clsGP,
		INS:  insGenerateKey,
		P1:   replaceKvn,
		P2:   ref.ID,
		Data: data,
	}
}

// deleteKeyCmd builds a DELETE KEY command.
// GP Card Spec v2.3.1 §11.5.
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
		p2 = 0x01
	}

	return &apdu.Command{
		CLA:  clsGP,
		INS:  insDeleteKey,
		P1:   0x00,
		P2:   p2,
		Data: data,
	}, nil
}

// resetLockoutCmd builds a command used during the reset/lockout process.
// Reset works by sending invalid authentication data to each key 65 times
// until it blocks. The INS depends on the key type.
//
// Ref: Python reset(), C# Reset().
func resetLockoutCmd(ins byte, kvn, kid byte) *apdu.Command {
	return &apdu.Command{
		CLA:  clsGP,
		INS:  ins,
		P1:   kvn,
		P2:   kid,
		Data: make([]byte, 8), // 8 zero bytes as invalid auth data
	}
}

// insForKeyReset returns the authentication INS to use when locking out
// a key during reset, based on its KID.
//
// Ref: Python reset() switch, C# Reset() switch.
func insForKeyReset(kid byte) (byte, bool) {
	switch kid {
	case 0x01: // SCP03
		return insInitializeUpdate, true
	case 0x02, 0x03: // SCP03 sub-keys, skip
		return 0, false
	case 0x11, 0x15: // SCP11a, SCP11c
		return insExtAuth, true
	case 0x13: // SCP11b
		return insIntAuth, true
	default: // 0x10, 0x20-0x2F (OCE keys)
		return insPerformSecOp, true
	}
}

// --- STORE DATA payload construction ---

// storeCertificatesData builds the STORE DATA payload for certificate storage.
//
// Format: A6{83{KID,KVN}} + BF21{concat(cert_DER_bytes)}
// Note: certs are concatenated raw DER inside BF21, NOT individually 7F21-wrapped.
//
// Ref: Python store_certificate_bundle, C# StoreCertificates.
func storeCertificatesData(ref KeyReference, certsDER [][]byte) []byte {
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	// Concatenate raw DER certificates.
	var certConcat []byte
	for _, der := range certsDER {
		certConcat = append(certConcat, der...)
	}
	certStoreTLV := tlv.Build(tagCertStore, certConcat)

	var data []byte
	data = append(data, keyRefTLV.Encode()...)
	data = append(data, certStoreTLV.Encode()...)
	return data
}

// storeCaIssuerData builds the STORE DATA payload for CA issuer (SKI).
//
// Format: A6{ 80{klcc_flag} + 42{SKI} + 83{KID,KVN} }
// klcc_flag = 0x01 if key is KLCC (SCP11a/b/c), 0x00 if KLOC.
//
// Ref: Python store_ca_issuer, C# StoreCaIssuer.
func storeCaIssuerData(ref KeyReference, ski []byte) []byte {
	// Determine KLOC vs KLCC based on KID.
	klcc := ref.ID == KeyIDSCP11a || ref.ID == KeyIDSCP11b || ref.ID == KeyIDSCP11c
	var klccFlag byte
	if klcc {
		klccFlag = 0x01
	}

	caIssuerTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tlv.Tag(0x80), []byte{klccFlag}),
		tlv.Build(tagCaKlocID, ski),
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	return caIssuerTLV.Encode()
}

// storeAllowlistData builds the STORE DATA payload for a certificate
// serial number allowlist.
//
// Format: A6{83{KID,KVN}} + 70{93{serial1} + 93{serial2} + ...}
//
// Ref: Python store_allowlist, C# StoreAllowlist.
func storeAllowlistData(ref KeyReference, serials []string) ([]byte, error) {
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	var serialData []byte
	for _, s := range serials {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidSerial, s, err)
		}
		serialTLV := tlv.Build(tagSerialNum, b)
		serialData = append(serialData, serialTLV.Encode()...)
	}

	allowlistTLV := tlv.Build(tagAllowList, serialData)

	var data []byte
	data = append(data, keyRefTLV.Encode()...)
	data = append(data, allowlistTLV.Encode()...)
	return data, nil
}

// --- Response parsing ---

func parseKeyInformation(data []byte) ([]KeyInfo, error) {
	if len(data) == 0 {
		return nil, nil
	}
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: key information: %v", ErrInvalidResponse, err)
	}

	// Parse C0 entries, possibly inside E0 container.
	container := tlv.Find(nodes, tagKeyInformation)
	if container == nil {
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
		rest := child.Value[2:]
		for len(rest) >= 2 {
			info.Components[rest[0]] = rest[1]
			rest = rest[2:]
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// parseCertificates parses a GET DATA [Certificate Store] response.
// The response is a TLV list of raw DER certificates (not 7F21-wrapped).
//
// Ref: Python get_certificate_bundle uses Tlv.parse_list on the response.
func parseCertificates(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Try TLV parsing — each top-level TLV value is a DER certificate.
	nodes, err := tlv.Decode(data)
	if err != nil {
		// Might be a single raw DER certificate.
		return [][]byte{data}, nil
	}

	// If we have nodes, try to extract certificate data.
	// The response format varies — could be raw TLV list or BF21-wrapped.
	store := tlv.Find(nodes, tagCertStore)
	if store != nil {
		// Inside BF21, certificates may be raw DER or further TLV-wrapped.
		if len(store.Value) > 0 {
			return splitDERCertificates(store.Value)
		}
	}

	// Try each top-level node's value as a certificate.
	var certs [][]byte
	for _, n := range nodes {
		if len(n.Value) > 0 {
			certs = append(certs, n.Value)
		}
	}
	if len(certs) > 0 {
		return certs, nil
	}

	return [][]byte{data}, nil
}

// splitDERCertificates splits concatenated DER-encoded certificates.
// Each DER certificate starts with 0x30 (SEQUENCE tag).
func splitDERCertificates(data []byte) ([][]byte, error) {
	var certs [][]byte
	for len(data) > 0 {
		if data[0] != 0x30 {
			// Not a SEQUENCE tag — treat remainder as single cert.
			certs = append(certs, data)
			break
		}
		// Parse DER length to find end of this certificate.
		certLen, headerLen, err := parseDERLength(data[1:])
		if err != nil {
			certs = append(certs, data)
			break
		}
		total := 1 + headerLen + certLen
		if total > len(data) {
			certs = append(certs, data)
			break
		}
		certs = append(certs, data[:total])
		data = data[total:]
	}
	return certs, nil
}

// parseDERLength reads a DER length encoding and returns the length value
// and the number of bytes consumed by the length field.
func parseDERLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty DER length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, errors.New("invalid DER length encoding")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

func parseSupportedCaIdentifiers(data []byte) ([]CaIdentifier, error) {
	if len(data) == 0 {
		return nil, nil
	}
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: CA identifiers: %v", ErrInvalidResponse, err)
	}

	// Response is pairs of TLVs: key-ref followed by SKI.
	// Ref: Python parses as tlvs[i+1].value for key, tlvs[i].value for SKI.
	var result []CaIdentifier
	for i := 0; i+1 < len(nodes); i += 2 {
		skiNode := nodes[i]
		keyNode := nodes[i+1]
		if len(keyNode.Value) >= 2 {
			result = append(result, CaIdentifier{
				Reference: NewKeyReference(keyNode.Value[0], keyNode.Value[1]),
				SKI:       skiNode.Value,
			})
		}
	}
	return result, nil
}

// parseGeneratedPublicKey extracts the EC public key from a GenerateEcKey
// response. Response is Tlv(0xB0, uncompressed_point).
//
// Ref: Python uses Tlv.unpack(KeyType.ECC_PUBLIC_KEY, resp).
func parseGeneratedPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty generate key response", ErrInvalidResponse)
	}

	// Try TLV decoding — expect B0{point}.
	nodes, err := tlv.Decode(data)
	if err == nil {
		pubNode := tlv.Find(nodes, tlv.Tag(keyTypeECPublic))
		if pubNode != nil && len(pubNode.Value) == 65 {
			return unmarshalP256Point(pubNode.Value)
		}
		// Search recursively.
		if key, findErr := findPublicKeyInNodes(nodes); findErr == nil {
			return key, nil
		}
	}

	// Fallback: raw 65-byte uncompressed point.
	if len(data) >= 65 && data[0] == 0x04 {
		return unmarshalP256Point(data[:65])
	}

	return nil, fmt.Errorf("%w: no EC public key in generate response", ErrInvalidResponse)
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
	return nil, fmt.Errorf("%w: no EC point found", ErrInvalidResponse)
}

func unmarshalP256Point(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		return nil, fmt.Errorf("%w: invalid P-256 point", ErrInvalidKey)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

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

func parsePutKeyChecksum(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil // Full response for comparison
}

// --- Cryptographic helpers ---

// computeAESKCV computes the Key Check Value for an AES key.
// KCV = AES-CBC(key, IV=0x00*16, data=0x01*16)[:3]
//
// Ref: Python _encrypt_cbc(k, _DEFAULT_KCV_IV) where _DEFAULT_KCV_IV = b"\1" * 16
// Ref: C# kcvInput.Fill(1) then AesCbcEncrypt(key, kvcZeroIv, kcvInput)
func computeAESKCV(key []byte) []byte {
	if len(key) != 16 {
		return nil
	}
	onesBlock := make([]byte, 16)
	for i := range onesBlock {
		onesBlock[i] = 0x01
	}
	encrypted := aesCBCEncrypt(key, onesBlock)
	if encrypted == nil {
		return nil
	}
	return encrypted[:3]
}

// aesCBCEncrypt performs AES-CBC encryption with a zero IV.
// Used for KCV computation and key encryption in PUT KEY.
func aesCBCEncrypt(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	// Pad data to block size if needed.
	padded := pkcs7Pad(data, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(padded))
	enc.CryptBlocks(out, padded)
	return out
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
// If data is already a multiple, no padding is added.
func pkcs7Pad(data []byte, blockSize int) []byte {
	if len(data)%blockSize == 0 {
		return data
	}
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// --- Serial number conversion ---

func SerialToHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}

func SerialFromHex(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrInvalidSerial, s, err)
	}
	return new(big.Int).SetBytes(b), nil
}
