package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

// TestParseGeneratedPublicKey_ECC_RoundTrip: generate a real
// ECDSA keypair, encode its public key the way a YubiKey would
// in response to GENERATE KEY, parse it back, and confirm the
// recovered key equals the original. Done for both P-256 and
// P-384 because those are the two ECC curves PIV supports.
func TestParseGeneratedPublicKey_ECC_RoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		algo  byte
		curve elliptic.Curve
	}{
		{"P-256", AlgoECCP256, elliptic.P256()},
		{"P-384", AlgoECCP384, elliptic.P384()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			resp := encodeECCResponse(t, &priv.PublicKey)

			got, err := ParseGeneratedPublicKey(resp, tc.algo)
			if err != nil {
				t.Fatalf("ParseGeneratedPublicKey: %v", err)
			}
			pub, ok := got.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("got type %T, want *ecdsa.PublicKey", got)
			}
			if !PublicKeysEqual(&priv.PublicKey, pub) {
				t.Errorf("recovered key not equal to generated key")
			}
		})
	}
}

// TestParseGeneratedPublicKey_RSA_RoundTrip: same but for RSA-2048.
// Tests the modulus/exponent decoding and confirms the recovered
// *rsa.PublicKey compares equal.
func TestParseGeneratedPublicKey_RSA_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	resp := encodeRSAResponse(t, &priv.PublicKey)

	got, err := ParseGeneratedPublicKey(resp, AlgoRSA2048)
	if err != nil {
		t.Fatalf("ParseGeneratedPublicKey: %v", err)
	}
	pub, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("got type %T, want *rsa.PublicKey", got)
	}
	if !PublicKeysEqual(&priv.PublicKey, pub) {
		t.Errorf("recovered RSA key not equal to generated key")
	}
}

// TestParseGeneratedPublicKey_Ed25519_RoundTrip: 32-byte raw key
// inside tag 0x86, no 0x04 prefix.
func TestParseGeneratedPublicKey_Ed25519_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	resp := encodeEd25519Response(t, pub)

	got, err := ParseGeneratedPublicKey(resp, AlgoEd25519)
	if err != nil {
		t.Fatalf("ParseGeneratedPublicKey: %v", err)
	}
	gotPub, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("got type %T, want ed25519.PublicKey", got)
	}
	if !PublicKeysEqual(pub, gotPub) {
		t.Errorf("recovered Ed25519 key not equal to generated")
	}
}

// TestParseGeneratedPublicKey_X25519_ReturnsTypedError: X25519
// keys aren't bound by X.509 certs, so the parser returns a
// recognizable error rather than producing a key.
func TestParseGeneratedPublicKey_X25519_ReturnsTypedError(t *testing.T) {
	// Synthetic 32-byte key in 7F49 envelope.
	resp := encodeRawTag86(t, bytes.Repeat([]byte{0x42}, 32))
	_, err := ParseGeneratedPublicKey(resp, AlgoX25519)
	if err == nil {
		t.Fatal("expected error for X25519")
	}
	if !errors.Is(err, ErrNoCertBinding) {
		t.Errorf("expected ErrNoCertBinding, got %v", err)
	}
}

// TestParseGeneratedPublicKey_AlgorithmDataMismatch: feed a P-384
// response into a P-256 parse. The length check catches it.
func TestParseGeneratedPublicKey_AlgorithmDataMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	respP384 := encodeECCResponse(t, &priv.PublicKey)
	_, err := ParseGeneratedPublicKey(respP384, AlgoECCP256)
	if err == nil {
		t.Fatal("expected length-mismatch error parsing P-384 data as P-256")
	}
}

// TestParseGeneratedPublicKey_RejectsBadOuterTag: wrong outer tag
// (not 7F 49) must fail before walking inside.
func TestParseGeneratedPublicKey_RejectsBadOuterTag(t *testing.T) {
	cases := [][]byte{
		{},
		{0x7F},
		{0x7F, 0x48, 0x00}, // wrong inner tag byte
		{0x30, 0x00},       // wrong class entirely
	}
	for i, c := range cases {
		t.Run("case_"+string(rune('0'+i)), func(t *testing.T) {
			_, err := ParseGeneratedPublicKey(c, AlgoECCP256)
			if err == nil {
				t.Errorf("expected error for input %X", c)
			}
		})
	}
}

// TestParseGeneratedPublicKey_RejectsOffCurvePoint: synthesize a
// response with an X,Y pair not on P-256. The IsOnCurve guard
// must reject it. Catches both transport corruption and a buggy
// card or mock.
func TestParseGeneratedPublicKey_RejectsOffCurvePoint(t *testing.T) {
	// All-ones X,Y is overwhelmingly unlikely to be on the curve.
	point := append([]byte{0x04}, bytes.Repeat([]byte{0xFF}, 64)...)
	resp := encodeRawTag86(t, point)
	_, err := ParseGeneratedPublicKey(resp, AlgoECCP256)
	if err == nil {
		t.Fatal("expected off-curve rejection")
	}
}

// TestPublicKeysEqual_CrossAlgorithmIsNotEqual: an RSA key and an
// ECDSA key with otherwise-similar bit patterns must compare
// unequal — type mismatch is enough.
func TestPublicKeysEqual_CrossAlgorithmIsNotEqual(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	eccPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if PublicKeysEqual(&rsaPriv.PublicKey, &eccPriv.PublicKey) {
		t.Error("RSA key reported equal to ECDSA key")
	}
	if PublicKeysEqual(&eccPriv.PublicKey, &rsaPriv.PublicKey) {
		t.Error("ECDSA key reported equal to RSA key (other order)")
	}
}

// TestPublicKeysEqual_ECDSA_DifferentCurvesNotEqual: two valid
// ECDSA keys on different curves must be unequal even if their
// X/Y happened to numerically match (which can't happen with
// random keys, but the curve check is still the right gate).
func TestPublicKeysEqual_ECDSA_DifferentCurvesNotEqual(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := &ecdsa.PublicKey{Curve: elliptic.P384(), X: a.X, Y: a.Y}
	if PublicKeysEqual(&a.PublicKey, b) {
		t.Error("keys on different curves reported equal")
	}
}

// TestPublicKeysEqual_NilSafeOnUnknownTypes: passing types the
// function doesn't know about must return false, not panic.
func TestPublicKeysEqual_NilSafeOnUnknownTypes(t *testing.T) {
	if PublicKeysEqual(nil, nil) {
		t.Error("nil == nil reported true (we want false-by-policy)")
	}
	if PublicKeysEqual("not a key", 42) {
		t.Error("two non-key types reported equal")
	}
}

// --- Test helpers: encode synthetic GENERATE KEY responses. ---

// encodeECCResponse packages an ECDSA pubkey the way a PIV card
// would in response to GENERATE KEY: 7F 49 LL { 86 LL <0x04 || X || Y> }.
func encodeECCResponse(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	coordBytes := (pub.Curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*coordBytes)
	point[0] = 0x04
	pub.X.FillBytes(point[1 : 1+coordBytes])
	pub.Y.FillBytes(point[1+coordBytes:])
	return encodeRawTag86(t, point)
}

// encodeRSAResponse packages an RSA pubkey: 7F 49 LL { 81 LL <N>, 82 LL <e> }.
func encodeRSAResponse(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	n := pub.N.Bytes()
	if len(n) != 256 {
		t.Fatalf("RSA modulus is %d bytes, expected 256", len(n))
	}
	e := big.NewInt(int64(pub.E)).Bytes()

	var inner []byte
	inner = append(inner, encodeShortTLV(tagRSAModulus, n)...)
	inner = append(inner, encodeShortTLV(tagRSAExponent, e)...)
	return encodeOuter7F49(inner)
}

// encodeEd25519Response packages an Ed25519 pubkey: 7F 49 LL { 86 0x20 <key> }.
func encodeEd25519Response(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	return encodeRawTag86(t, pub)
}

// encodeRawTag86 produces 7F 49 LL { 86 LL <value> }. Used for ECC
// uncompressed points, Ed25519 raw, and X25519 raw.
func encodeRawTag86(t *testing.T, value []byte) []byte {
	t.Helper()
	inner := encodeShortTLV(tagECPoint, value)
	return encodeOuter7F49(inner)
}

// encodeOuter7F49 wraps `body` in `7F 49 LL ...`, choosing the
// length encoding (short, 0x81, 0x82) based on body size.
func encodeOuter7F49(body []byte) []byte {
	out := []byte{0x7F, 0x49}
	switch {
	case len(body) < 0x80:
		out = append(out, byte(len(body)))
	case len(body) < 0x100:
		out = append(out, 0x81, byte(len(body)))
	default:
		out = append(out, 0x82, byte(len(body)>>8), byte(len(body)))
	}
	return append(out, body...)
}

// encodeShortTLV emits a single TLV with single-byte tag and
// minimal-form length encoding (short, 0x81, 0x82).
func encodeShortTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch {
	case len(value) < 0x80:
		out = append(out, byte(len(value)))
	case len(value) < 0x100:
		out = append(out, 0x81, byte(len(value)))
	default:
		out = append(out, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(out, value...)
}
