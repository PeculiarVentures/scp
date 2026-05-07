package securitydomain

// APDU construction and response parsing for Security Domain management.
//
// Encoding has been validated against two Yubico reference implementations:
//   - Python: yubikey-manager/yubikit/securitydomain.py
//   - C#:    Yubico.NET.SDK SecurityDomainSession.cs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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

// STORE DATA P1 reference control parameter (GP Card Spec v2.3.1
// §11.11.2.1).
//
// 0x90 = b8 (last/only block) | b5 (BER-TLV format). YubiKey only
// accepts STORE DATA as a single LOGICAL APDU; payloads larger
// than a short APDU are split at the SCP TRANSPORT layer via
// ISO 7816-4 §5.1.1 command chaining (CLA bit b5 = 0x10), not
// GP §11.11 application-level block chaining (which would require
// P2 to step through block numbers and P1 b8 to clear on non-
// final blocks). The SCP wrap (encrypt + MAC) is computed once
// over the whole logical command using the extended-format header
// for the MAC input when Lc > 255; the wrapped bytes are then
// chunked at the transport. See scp03.Session.sendPossiblyChained
// for the chunking and the hardware-driven rationale.
const storeDataP1Final byte = 0x90

// storeDataCmd builds a STORE DATA command as a single LOGICAL
// APDU. Transport-layer chaining inside scp03.Session.Transmit
// handles payloads that exceed a short-form APDU's capacity; the
// application layer always emits one logical command.
func storeDataCmd(data []byte) *apdu.Command {
	return &apdu.Command{
		CLA:  clsGP,
		INS:  insStoreData,
		P1:   storeDataP1Final,
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

	// Convert to crypto/ecdh and serialize: same SEC1 uncompressed
	// encoding as the deprecated elliptic.Marshal, with point-on-curve
	// validation built in.
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: convert ECDSA to ECDH: %w", ErrInvalidKey, err)
	}
	pubBytes := ecdhKey.Bytes()

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
// Each serial is encoded as an ASN.1-INTEGER-style minimal unsigned
// representation: big-endian bytes of the absolute value, with a
// leading 0x00 prepended when the high bit of the first byte is set
// (so that the value cannot be misread as a two's-complement
// negative). This matches yubikit-python's `_int2asn1` helper used
// by `store_allowlist`, which the YubiKey firmware compares
// against byte-exactly. A serial like 0xFF12345678 from
// x509.Certificate.SerialNumber.Bytes() is "FF 12 34 56 78"
// (5 bytes, high bit set) on the host side; we send "00 FF 12 34
// 56 78" (6 bytes) inside the 93 TLV so the card sees the same
// representation it stored when the matching cert was issued.
//
// Without the leading-zero rule, a serial whose first byte is
// >= 0x80 would not match its certificate's actual on-the-wire
// ASN.1 INTEGER serial bytes, and the card would silently
// disallow the cert on SCP11 verification — exactly the kind of
// false-negative that's hard to diagnose because nothing visible
// fails until the real authentication.
//
// Nil entries are rejected; the empty allowlist (len(serials) == 0)
// is permitted and produces the equivalent of ClearAllowlist.
//
// Ref: yubikit-python `_int2asn1` (yubikit/securitydomain.py),
// C# StoreAllowlist.
func storeAllowlistData(ref KeyReference, serials []*big.Int) ([]byte, error) {
	keyRefTLV := tlv.BuildConstructed(tagControlRef,
		tlv.Build(tagKeyID, []byte{ref.ID, ref.Version}),
	)

	var serialData []byte
	for i, n := range serials {
		if n == nil {
			return nil, fmt.Errorf("%w: serials[%d] is nil", ErrInvalidSerial, i)
		}
		// big.Int.Bytes() returns the unsigned big-endian
		// representation of the absolute value. Negative serials
		// are rejected — x509 serials are unsigned by spec
		// (RFC 5280 §4.1.2.2 says "non-negative integer"), and a
		// caller passing a negative value is almost certainly a
		// bug.
		if n.Sign() < 0 {
			return nil, fmt.Errorf("%w: serials[%d] is negative", ErrInvalidSerial, i)
		}
		serialTLV := tlv.Build(tagSerialNum, asn1IntegerBytes(n))
		serialData = append(serialData, serialTLV.Encode()...)
	}

	allowlistTLV := tlv.Build(tagAllowList, serialData)

	var data []byte
	data = append(data, keyRefTLV.Encode()...)
	data = append(data, allowlistTLV.Encode()...)
	return data, nil
}

// asn1IntegerBytes returns the ASN.1-INTEGER-style minimal unsigned
// encoding of a non-negative *big.Int: big-endian bytes of the
// absolute value, with a leading 0x00 prepended when the high bit
// of the first byte is set.
//
// Caller has already verified n.Sign() >= 0; this helper does not
// re-check, so passing a negative *big.Int produces wrong bytes.
//
//   - n = 0:           returns []byte{0x00}     (single zero byte)
//   - n = 0x7F:        returns []byte{0x7F}     (high bit clear, no prefix)
//   - n = 0x80:        returns []byte{0x00, 0x80} (high bit set, prefix)
//   - n = 0xFF...FF:   returns []byte{0x00, 0xFF, ...} (prefix)
//
// Matches yubikit-python's `_int2asn1` byte-for-byte for all
// non-negative inputs that yubikit accepts.
func asn1IntegerBytes(n *big.Int) []byte {
	bs := n.Bytes()
	if len(bs) == 0 {
		// big.Int.Bytes() returns empty for zero. ASN.1 INTEGER
		// representation of 0 is a single 0x00 byte; produce
		// that explicitly so a zero-valued serial doesn't yield
		// a zero-length TLV value (which the card would
		// interpret as malformed).
		return []byte{0x00}
	}
	if bs[0]&0x80 != 0 {
		out := make([]byte, len(bs)+1)
		out[0] = 0x00
		copy(out[1:], bs)
		return out
	}
	return bs
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
// Yubico yubikit emits this shape: GET DATA BF21 returns a top-level
// concatenation of complete DER X.509 certificates. Each cert is a
// SEQUENCE TLV (tag 0x30) and the full TLV bytes are the DER encoding
// the X.509 parser expects. We split on TLV boundaries via
// splitDERCertificates rather than handing back tlv.Node.Value (which
// would strip the outer SEQUENCE header and break x509.ParseCertificate).
//
// Ref: Python get_certificate_bundle uses Tlv.parse_list on the response.
func parseCertificates(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Top-level may already be a list of DER certs (yubikit shape).
	// splitDERCertificates walks 0x30-tagged TLVs without consuming
	// the outer headers, returning bytes the X.509 parser can use
	// directly.
	if data[0] == 0x30 {
		return splitDERCertificates(data)
	}

	// Otherwise the response may be wrapped in BF21 with the certs
	// inside. Two shapes seen in the wild:
	//
	//  GP-spec shape: BF21 { 7F21 { certDER } [ 7F21 { certDER } ... ] }
	//                 — used by GlobalPlatform-conformant mocks and
	//                 some real cards. Each 7F21's Value is bare DER.
	//
	//  YubiKit shape: BF21 { certDER || certDER || ... }
	//                 — concatenated DER directly inside BF21, no
	//                 inner 7F21 wrappers. Seen on retail YubiKey
	//                 5.7+ for the SCP11 SD chain.
	//
	// We try the GP-spec shape first (look for 7F21 children); if
	// none, we fall back to splitDERCertificates which walks
	// 0x30-prefixed concatenated DER.
	nodes, err := tlv.Decode(data)
	if err != nil {
		// Not BER-TLV — treat as a single raw DER cert.
		return [][]byte{data}, nil
	}
	if store := tlv.Find(nodes, tagCertStore); store != nil && len(store.Value) > 0 {
		// Look for inner 7F21 cert wrappers.
		var certs [][]byte
		var walk func([]*tlv.Node)
		walk = func(ns []*tlv.Node) {
			for _, n := range ns {
				if n.Tag == tlv.TagCertificate && len(n.Value) > 0 {
					certs = append(certs, append([]byte(nil), n.Value...))
				}
				if len(n.Children) > 0 {
					walk(n.Children)
				}
			}
		}
		walk(store.Children)
		if len(certs) > 0 {
			return certs, nil
		}
		// No 7F21 children — fall through to the yubikit shape.
		return splitDERCertificates(store.Value)
	}

	// Last resort: hand the whole buffer back as one cert. Callers
	// will surface the X.509 parse error if it isn't.
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
	// crypto/ecdh.NewPublicKey accepts the same SEC1 uncompressed
	// encoding as the deprecated elliptic.Unmarshal, but additionally
	// validates that the point is on the curve and not the identity.
	pub, err := ecdh.P256().NewPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid P-256 point: %w", ErrInvalidKey, err)
	}
	// Convert back to *ecdsa.PublicKey for the rest of the call sites
	// that still take that type. The bytes round-trip exactly: 0x04 ||
	// X (32 bytes) || Y (32 bytes).
	raw := pub.Bytes()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func parseAllowlist(data []byte) ([]*big.Int, error) {
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
	var serials []*big.Int
	for _, n := range container.Children {
		if n.Tag == tagSerialNum {
			serials = append(serials, new(big.Int).SetBytes(n.Value))
		}
	}
	return serials, nil
}

// --- Cryptographic helpers ---

// ComputeAESKCV is the public form of the package-internal
// computeAESKCV. Returns the 3-byte SCP03 Key Check Value for a
// 16-byte AES-128 key, or nil if the input is not exactly 16
// bytes. Operator surface: scpctl emits these in JSON during
// `sd keys import` so deployment audit logs capture the on-card
// commitment shape (which the library has already verified
// matches by raising ErrChecksum on PUT KEY response mismatch).
//
// KCV definition: AES-CBC(key, IV=0x00*16, data=0x01*16)[:3].
// This matches yubikit-python (_DEFAULT_KCV_IV) and the C# SDK
// (kvcZeroIv + kcvInput.Fill(1)) byte-for-byte.
func ComputeAESKCV(key []byte) []byte {
	return computeAESKCV(key)
}

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

// SerialToHex converts an x509 certificate serial (*big.Int) into a
// lowercase hex string. The encoding is the unsigned big-endian byte
// representation of the absolute value, hex-encoded with no leading
// "0x", no separators, and no padding to a fixed width.
//
// Provided as a convenience for callers that store or transport
// serials as text (configuration files, command-line arguments, log
// lines). StoreAllowlist takes []*big.Int directly, so neither this
// helper nor SerialFromHex is required when feeding x509-derived
// serials straight through.
//
// Round-trips with SerialFromHex.
func SerialToHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}

// SerialFromHex parses a hex-encoded certificate serial into a
// *big.Int. The input format matches SerialToHex's output: lowercase
// or uppercase hex, no "0x" prefix, no separators. Returns
// ErrInvalidSerial wrapped with the offending input on a parse
// failure.
//
// Provided as a convenience for callers building allowlists from
// serials originally captured as hex strings (configuration files,
// audit logs). StoreAllowlist takes []*big.Int directly.
func SerialFromHex(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrInvalidSerial, s, err)
	}
	return new(big.Int).SetBytes(b), nil
}
