package session

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/tlv"
)

// --- Certificate Parsing ---

// extractCardPublicKey parses the card's certificate from a GET DATA
// response, optionally validates the chain, and returns the ECDH public key.
func extractCardPublicKey(data []byte, trustAnchors *x509.CertPool) (*ecdh.PublicKey, error) {
	// The response is a BF21 (certificate store) containing one or more
	// 7F21 (certificate) entries.
	nodes, err := tlv.Decode(data)
	if err != nil {
		// Try parsing as raw DER certificate directly (some cards
		// return the certificate without the TLV wrapper).
		return parseRawCert(data, trustAnchors)
	}

	// Find certificate nodes.
	certNodes := tlv.FindAll(nodes, tlv.TagCertificate)
	if len(certNodes) == 0 {
		// Also check inside BF21 container.
		storeNode := tlv.Find(nodes, tlv.TagCertStore)
		if storeNode != nil && len(storeNode.Children) > 0 {
			certNodes = tlv.FindAll(storeNode.Children, tlv.TagCertificate)
		}
	}

	if len(certNodes) == 0 {
		// Last resort: try the raw data as a DER certificate.
		return parseRawCert(data, trustAnchors)
	}

	// Parse the leaf certificate (last in the chain).
	leafData := certNodes[len(certNodes)-1].Value
	return parseRawCert(leafData, trustAnchors)
}

func parseRawCert(data []byte, trustAnchors *x509.CertPool) (*ecdh.PublicKey, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		// Not an X.509 certificate. If trust anchors are configured,
		// we MUST NOT fall back to unvalidated key extraction — that
		// would bypass the chain validation the caller requested.
		if trustAnchors != nil {
			return nil, fmt.Errorf("card certificate is not valid X.509 and trust anchors are configured (cannot validate): %w", err)
		}

		// No trust anchors configured — try GP proprietary format.
		// GP SCP11 §6.1: GP certificate uses tag 7F21 containing
		// tag 7F49 with the raw EC public key point.
		key, gpErr := parseGPCertificate(data)
		if gpErr == nil {
			return key, nil
		}
		// Try extracting the public key directly from raw data.
		return extractECDHKeyFromSPKI(data)
	}

	// Validate if trust anchors are provided.
	if trustAnchors != nil {
		opts := x509.VerifyOptions{Roots: trustAnchors}
		if _, err := cert.Verify(opts); err != nil {
			return nil, fmt.Errorf("card certificate validation: %w", err)
		}
	}

	// Extract the ECDH public key from the certificate's ECDSA key.
	return ecdsaToECDH(cert.PublicKey)
}

// parseGPCertificate extracts the public key from a GlobalPlatform
// proprietary certificate. GP format (SCP11 §6.1, Table 6-1):
//
//	7F21 {
//	  93: Certificate Serial Number
//	  42: Card Issuer ID (CA-KLCC identifier)
//	  5F20: Subject ID
//	  95: Key Usage
//	  5F25: Effective Date
//	  5F24: Expiration Date
//	  53: Discretionary Data (optional)
//	  73: Discretionary Data Template (optional)
//	  BF20: Authorization Rules (optional, SCP11a/c)
//	  7F49: Public Key { 86: EC point }
//	  5F37: Signature
//	}
//
// We extract the EC point from tag 7F49.
// We only need to extract the EC point from tag 7F49.
func parseGPCertificate(data []byte) (*ecdh.PublicKey, error) {
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode GP certificate: %w", err)
	}

	// The data might be a bare 7F21 node, or the inner content of one.
	// Look for tag 7F49 (public key container) at any depth.
	pkContainer := tlv.Find(nodes, tlv.Tag(0x7F49))
	if pkContainer != nil {
		// Inside 7F49, tag 86 contains the EC point.
		ecPoint := tlv.Find(pkContainer.Children, tlv.Tag(0x86))
		if ecPoint != nil && len(ecPoint.Value) >= 33 {
			return ecdh.P256().NewPublicKey(ecPoint.Value)
		}
		// Some implementations put the point directly in 7F49 value.
		if len(pkContainer.Value) >= 33 {
			// Try parsing the entire value as nested TLV first.
			inner, innerErr := tlv.Decode(pkContainer.Value)
			if innerErr == nil {
				ecPointInner := tlv.Find(inner, tlv.Tag(0x86))
				if ecPointInner != nil && len(ecPointInner.Value) >= 33 {
					return ecdh.P256().NewPublicKey(ecPointInner.Value)
				}
			}
		}
	}

	// Fallback: look for any 65-byte uncompressed EC point (0x04 prefix)
	// at any level of the TLV tree.
	return findECPointInNodes(nodes)
}

func ecdsaToECDH(pub interface{}) (*ecdh.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported curve: %v", k.Curve.Params().Name)
		}
		return k.ECDH()
	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}

// findECPointInNodes recursively searches TLV nodes for a 65-byte
// uncompressed P-256 EC point (0x04 prefix).
func findECPointInNodes(nodes []*tlv.Node) (*ecdh.PublicKey, error) {
	for _, n := range nodes {
		if len(n.Value) == 65 && n.Value[0] == 0x04 {
			return ecdh.P256().NewPublicKey(n.Value)
		}
		if len(n.Children) > 0 {
			if key, err := findECPointInNodes(n.Children); err == nil {
				return key, nil
			}
		}
	}
	return nil, errors.New("no EC point found in TLV tree")
}

func extractECDHKeyFromSPKI(data []byte) (*ecdh.PublicKey, error) {
	// Check if this looks like an uncompressed EC point (0x04 prefix, 65 bytes for P-256).
	if len(data) == 65 && data[0] == 0x04 {
		return ecdh.P256().NewPublicKey(data)
	}

	// Try to find the public key within TLV structure.
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("cannot parse key data: %w", err)
	}

	// Look for tag 0x5F49 (ephemeral public key tag).
	pkNode := tlv.Find(nodes, tlv.TagEphPubKey)
	if pkNode != nil && len(pkNode.Value) == 65 {
		return ecdh.P256().NewPublicKey(pkNode.Value)
	}

	// Look for raw 86 tag (public key in some GP implementations).
	for _, n := range nodes {
		if len(n.Value) == 65 && n.Value[0] == 0x04 {
			return ecdh.P256().NewPublicKey(n.Value)
		}
	}

	return nil, errors.New("no EC public key found in data")
}

// parseKeyAgreementResponse extracts the card's ephemeral public key
// and optional receipt from the INTERNAL/MUTUAL AUTHENTICATE response.
func parseKeyAgreementResponse(data []byte) (ephPubKey []byte, receipt []byte, err error) {
	nodes, err := tlv.Decode(data)
	if err != nil {
		// Some cards return the public key directly without TLV.
		if len(data) >= 65 && data[0] == 0x04 {
			return data[:65], data[65:], nil
		}
		return nil, nil, fmt.Errorf("parse key agreement response: %w", err)
	}

	// Find the card's ephemeral public key (tag 0x5F49).
	pkNode := tlv.Find(nodes, tlv.TagEphPubKey)
	if pkNode == nil {
		return nil, nil, errors.New("card ephemeral public key not found in response")
	}
	ephPubKey = pkNode.Value

	// Find the receipt/cryptogram (tag 0x86), if present.
	receiptNode := tlv.Find(nodes, tlv.TagReceipt)
	if receiptNode != nil {
		receipt = receiptNode.Value
	}

	return ephPubKey, receipt, nil
}

// isZeroSecret checks if an ECDH shared secret is all zeros, which
// indicates the point at infinity. TR-03111 §4.3.1 requires this check.
func isZeroSecret(secret []byte) bool {
	if len(secret) == 0 {
		return true
	}
	var acc byte
	for _, b := range secret {
		acc |= b
	}
	return acc == 0
}

// parseCertsFromStore parses X.509 certificates from a GET DATA
// certificate store response. The response may contain:
//   - A BF21 container with 7F21-wrapped certificates
//   - A BF21 container with concatenated raw DER certificates
//   - A single raw DER certificate
//
// Returns certificates in the order they appear (leaf-last per
// Yubico convention).
func parseCertsFromStore(data []byte) ([]*x509.Certificate, error) {
	var derCerts [][]byte

	// Try TLV parsing first.
	nodes, err := tlv.Decode(data)
	if err == nil {
		// Look for BF21 container.
		store := tlv.Find(nodes, tlv.TagCertStore)
		if store != nil {
			// Check for 7F21-wrapped certs inside.
			certNodes := tlv.FindAll(store.Children, tlv.TagCertificate)
			if len(certNodes) > 0 {
				for _, n := range certNodes {
					derCerts = append(derCerts, n.Value)
				}
			} else if len(store.Value) > 0 {
				// Concatenated raw DER inside BF21.
				derCerts = splitDER(store.Value)
			}
		}

		// If no BF21, try 7F21 entries at top level.
		if len(derCerts) == 0 {
			certNodes := tlv.FindAll(nodes, tlv.TagCertificate)
			for _, n := range certNodes {
				derCerts = append(derCerts, n.Value)
			}
		}
	}

	// Fallback: try splitting as concatenated DER sequences.
	if len(derCerts) == 0 {
		derCerts = splitDER(data)
	}

	// Parse all DER blobs into x509.Certificate objects.
	var certs []*x509.Certificate
	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// Try GP proprietary format — not an X.509 cert,
			// skip it for chain validation purposes.
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// splitDER splits concatenated DER-encoded structures by parsing
// each SEQUENCE header to determine boundaries.
func splitDER(data []byte) [][]byte {
	var result [][]byte
	for len(data) > 0 {
		if data[0] != 0x30 { // Not a SEQUENCE
			result = append(result, data)
			break
		}
		// Parse DER length.
		total, ok := derElementLength(data)
		if !ok || total > len(data) {
			result = append(result, data)
			break
		}
		result = append(result, data[:total])
		data = data[total:]
	}
	return result
}

// derElementLength returns the total length of a DER element
// (tag + length field + value) starting at data[0].
func derElementLength(data []byte) (int, bool) {
	if len(data) < 2 {
		return 0, false
	}
	// Tag is 1 byte (0x30 for SEQUENCE).
	lenByte := data[1]
	if lenByte < 0x80 {
		return 2 + int(lenByte), true
	}
	numBytes := int(lenByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || len(data) < 2+numBytes {
		return 0, false
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	return 2 + numBytes + length, true
}
