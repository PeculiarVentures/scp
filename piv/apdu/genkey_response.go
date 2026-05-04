package pivapdu

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
)

// PIV GENERATE KEY response TLV tags (NIST SP 800-73-4 Part 2 §3.3.2
// for RSA / ECC; YubiKey PIV technical reference for Ed25519 / X25519).
const (
	tagGenKeyResponse byte = 0x49 // outer template tag, with class byte 0x7F
	tagECPoint        byte = 0x86 // ECC: uncompressed point. Edwards/Montgomery: 32-byte raw key.
	tagRSAModulus     byte = 0x81
	tagRSAExponent    byte = 0x82
)

// ParseGeneratedPublicKey decodes the public-key data field from a
// PIV GENERATE KEY response. The response shape is the constructed
// TLV `7F 49 LL { ... }` where the inner fields depend on the
// algorithm:
//
//   - RSA-2048: tag 0x81 = modulus (256 bytes), tag 0x82 = exponent.
//   - ECC P-256 / P-384: tag 0x86 = uncompressed point
//     `0x04 || X || Y` (65 bytes for P-256, 97 bytes for P-384).
//   - Ed25519 / X25519 (YubiKey 5.7+ extension): tag 0x86 = raw
//     32-byte public key (no 0x04 prefix; these curves don't use
//     uncompressed-point encoding).
//
// Returns the typed public key — *rsa.PublicKey, *ecdsa.PublicKey,
// or ed25519.PublicKey. X25519 is intentionally not returned as a
// crypto.PublicKey because X.509 does not bind X25519 keys; callers
// using X25519 should not be matching against a certificate. For
// X25519 the function returns a typed error so the cert-binding
// caller can produce a clean message.
//
// algorithm must be one of the AlgoRSA2048 / AlgoECCP256 / AlgoECCP384
// / AlgoEd25519 / AlgoX25519 constants. The algorithm tells the
// parser which inner shape to expect; passing the wrong algorithm
// for the response data will produce a length-mismatch error
// rather than silent misinterpretation.
func ParseGeneratedPublicKey(respData []byte, algorithm byte) (crypto.PublicKey, error) {
	// PIV uses class-byte TLV: outer tag is two bytes 0x7F 0x49.
	// findTLV (the ISO 7816-4 walker we wrote for mgmt-auth) handles
	// only single-byte tags, so we strip the 0x7F manually before
	// dispatching to the inner walker.
	body, err := stripGenKeyOuter(respData)
	if err != nil {
		return nil, err
	}

	switch algorithm {
	case AlgoRSA2048:
		modulus, err := findTLV(body, tagRSAModulus)
		if err != nil {
			return nil, fmt.Errorf("RSA modulus: %w", err)
		}
		exponent, err := findTLV(body, tagRSAExponent)
		if err != nil {
			return nil, fmt.Errorf("RSA exponent: %w", err)
		}
		if len(modulus) != 256 {
			return nil, fmt.Errorf("RSA-2048 modulus length %d != 256", len(modulus))
		}
		if len(exponent) == 0 || len(exponent) > 8 {
			return nil, fmt.Errorf("RSA exponent length %d outside [1, 8]", len(exponent))
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}, nil

	case AlgoECCP256, AlgoECCP384:
		point, err := findTLV(body, tagECPoint)
		if err != nil {
			return nil, fmt.Errorf("EC point: %w", err)
		}
		curve, coordBytes := ecCurveAndSize(algorithm)
		wantLen := 1 + 2*coordBytes // 0x04 prefix + X + Y
		if len(point) != wantLen {
			return nil, fmt.Errorf("EC point length %d != %d for %s", len(point), wantLen, ecCurveName(algorithm))
		}
		if point[0] != 0x04 {
			return nil, fmt.Errorf("EC point not uncompressed (first byte 0x%02X, want 0x04)", point[0])
		}
		x := new(big.Int).SetBytes(point[1 : 1+coordBytes])
		y := new(big.Int).SetBytes(point[1+coordBytes:])
		// Reject points that aren't on the curve. A real card
		// won't ship one of these, but a malformed mock or a
		// transport-corruption could; cleaner to fail here than
		// at first signature attempt.
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC point not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	case AlgoEd25519:
		raw, err := findTLV(body, tagECPoint)
		if err != nil {
			return nil, fmt.Errorf("Ed25519 key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 key length %d != %d", len(raw), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(raw), nil

	case AlgoX25519:
		// Intentionally not returning a crypto.PublicKey here —
		// X25519 doesn't fit cert-binding workflows. The caller
		// should branch on this error.
		return nil, errX25519NotForCertBinding

	default:
		return nil, fmt.Errorf("unsupported algorithm 0x%02X", algorithm)
	}
}

// errX25519NotForCertBinding is returned by ParseGeneratedPublicKey
// for AlgoX25519. Exported via ErrNoCertBinding for callers that
// want to handle X25519 specially.
var errX25519NotForCertBinding = errors.New("X25519 keys are not bound by X.509 certificates")

// ErrNoCertBinding lets callers detect the X25519-specific case
// without string-matching errors.
var ErrNoCertBinding = errX25519NotForCertBinding

// stripGenKeyOuter pulls the inner body out of the
// `7F 49 LL <body>` envelope. The 7F is a class-byte tag prefix in
// ISO 7816-4 BER-TLV; without stripping it our single-byte walker
// would mis-parse 0x7F as a tag and 0x49 as a length.
func stripGenKeyOuter(buf []byte) ([]byte, error) {
	if len(buf) < 3 {
		return nil, errors.New("GENERATE KEY response too short")
	}
	if buf[0] != 0x7F || buf[1] != tagGenKeyResponse {
		return nil, fmt.Errorf("expected GENERATE KEY outer tag 7F49, got %02X%02X", buf[0], buf[1])
	}
	i := 2
	var L int
	switch {
	case buf[i] < 0x80:
		L = int(buf[i])
		i++
	case buf[i] == 0x81:
		if i+1 >= len(buf) {
			return nil, errors.New("truncated outer length 0x81")
		}
		L = int(buf[i+1])
		i += 2
	case buf[i] == 0x82:
		if i+2 >= len(buf) {
			return nil, errors.New("truncated outer length 0x82")
		}
		L = int(buf[i+1])<<8 | int(buf[i+2])
		i += 3
	default:
		return nil, fmt.Errorf("unsupported outer length encoding 0x%02X", buf[i])
	}
	if i+L > len(buf) {
		return nil, fmt.Errorf("outer length %d runs past buffer (have %d)", L, len(buf)-i)
	}
	return buf[i : i+L], nil
}

func ecCurveAndSize(algorithm byte) (elliptic.Curve, int) {
	switch algorithm {
	case AlgoECCP256:
		return elliptic.P256(), 32
	case AlgoECCP384:
		return elliptic.P384(), 48
	default:
		return nil, 0
	}
}

func ecCurveName(algorithm byte) string {
	switch algorithm {
	case AlgoECCP256:
		return "P-256"
	case AlgoECCP384:
		return "P-384"
	default:
		return "?"
	}
}

// PublicKeysEqual compares two public keys for cryptographic
// equivalence. Returns true when they are the same algorithm and
// the same key material; false for any mismatch including
// different algorithms.
//
// This is the function the cert-binding check uses to verify a
// cert about to be installed in a PIV slot actually corresponds to
// the keypair the card just generated. Without this check, a
// caller can install a misleading cert (right shape, wrong key)
// and have the slot pass shape validation while attesting to the
// wrong identity.
//
// Equality semantics:
//
//   - *rsa.PublicKey: equal iff modulus N and exponent E match.
//   - *ecdsa.PublicKey: equal iff curve and (X, Y) match.
//   - ed25519.PublicKey: byte-equal.
//   - Mixed types: never equal.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return ak.N.Cmp(bk.N) == 0 && ak.E == bk.E
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		// elliptic.Curve has no .Equal; comparing Params().Name is
		// the standard way and is what crypto/x509 does internally.
		if ak.Curve.Params().Name != bk.Curve.Params().Name {
			return false
		}
		return ak.X.Cmp(bk.X) == 0 && ak.Y.Cmp(bk.Y) == 0
	case ed25519.PublicKey:
		bk, ok := b.(ed25519.PublicKey)
		if !ok {
			return false
		}
		if len(ak) != len(bk) {
			return false
		}
		// ed25519 public keys are public; constant-time isn't
		// strictly required, but it's also not harmful here.
		var diff byte
		for i := range ak {
			diff |= ak[i] ^ bk[i]
		}
		return diff == 0
	default:
		return false
	}
}
