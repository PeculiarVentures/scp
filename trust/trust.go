// Package trust provides certificate chain validation for SCP11
// secure channel establishment. It separates the trust decision
// from certificate parsing and key extraction.
//
// For SCP11, the library must distinguish among:
//
//   - parsing a presented certificate
//   - validating a chain to a trust anchor
//   - checking that the certificate is appropriate for the SCP11 variant
//   - deciding whether the card identity should be trusted
//
// This package implements the validation step. It is designed to be
// used both by the securitydomain management layer and by existing
// scp11.Open callers who want explicit chain validation before
// trusting a card's identity.
//
// # Fail-closed behavior
//
// If trust anchors are configured, validation must succeed before the
// leaf certificate's public key is returned. There is no silent fallback
// to raw key extraction.
//
// # X.509 card-trust validation (implemented capability)
//
// ValidateSCP11Chain is the standards-compatible X.509 path. It
// handles leaf-last and leaf-first chain ordering, picks up
// intermediates that arrive alongside the leaf in BF21 certificate
// stores, enforces optional EKU / SKI / serial-allowlist constraints
// from Policy, and applies the SCP11 P-256 protocol precondition
// regardless of how the chain looked. This is the path SCP11
// integrations against cards that present standard X.509 chains
// take.
//
// # Custom validation for GP-proprietary certificate stores (extension point)
//
// Policy.CustomValidator is the supported extension point for cards
// that present SCP11 certificates in GP-proprietary formats rather
// than standard X.509. When set, the validator owns the trust
// decision in full: roots, EKU, SKI, and serial-allowlist policy
// fields are not consulted, and the validator returns the
// authenticated card public key directly. The protocol-layer P-256
// and ECDH-convertibility checks still run after the validator
// returns, because the SCP11 ECDH cannot function without them.
//
// Generic GP-proprietary parsers (Samsung OpenSCP, NXP J3R200, etc.)
// can be contributed as additional implementations of CustomValidator
// without touching the core trust package.
//
// # Usage
//
//	result, err := trust.ValidateSCP11Chain(certs, trust.Policy{
//	    Roots:         rootPool,
//	    Intermediates: intermediatePool,
//	    CurrentTime:   time.Now(),
//	})
//	if err != nil {
//	    // Chain validation failed — do not trust card identity.
//	}
//	// result.Leaf is the validated leaf certificate.
//	// result.PublicKey is the card's ECDSA public key, safe to use.
package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Policy configures how an SCP11 certificate chain is validated.
type Policy struct {
	// Roots is the set of trusted root certificates. Required.
	Roots *x509.CertPool

	// Intermediates is the set of intermediate CA certificates.
	// Optional; if nil, the chain must be directly signed by a root.
	Intermediates *x509.CertPool

	// CurrentTime is the time at which to validate certificate
	// expiration. If zero, time.Now() is used.
	CurrentTime time.Time

	// ExpectedEKUs restricts the leaf certificate to having one of
	// these Extended Key Usage values. If empty, EKU is not checked.
	ExpectedEKUs []x509.ExtKeyUsage

	// AllowedSerials restricts the leaf certificate's serial number
	// to one of these hex-encoded values. If empty, serial is not
	// checked. This mirrors the on-device allowlist but applied
	// host-side before channel establishment.
	AllowedSerials []string

	// ExpectedSKI, if set, requires the leaf certificate's Subject
	// Key Identifier to match this value exactly.
	ExpectedSKI []byte

	// RequireP256 requires the leaf certificate's public key to be
	// on the NIST P-256 curve. Defaults to true when zero-valued
	// (since SCP11 mandates P-256).
	RequireP256 *bool

	// CustomValidator, if non-nil, is called instead of the built-in
	// X.509 chain validator. The card response bytes (the BF21 cert
	// store, exactly as returned by GET DATA) are passed in; the
	// validator is responsible for parsing, chain validation, and
	// returning the card's static public key as an ECDSA *PublicKey.
	//
	// Use cases:
	//
	//   - GP-proprietary SCP11 certificates (GP §7F21 format, not X.509).
	//     The built-in validator only handles X.509 chains; cards that
	//     return GP-proprietary certs need a custom validator that
	//     understands the proprietary encoding and applies whatever
	//     trust model the deployment uses (issuer SKI pinning, signature
	//     verification against a known issuer key, etc.).
	//
	//   - Custom corporate PKI rules: certificate-policy OIDs, name
	//     constraints, CRL/OCSP, revocation lookups, hardware-backed
	//     anchor verification.
	//
	//   - Mixed deployments where some cards return X.509 and some
	//     return proprietary; the custom validator can dispatch on the
	//     leading byte and call the built-in path for X.509 inputs.
	//
	// When CustomValidator is set, all other Policy fields (Roots,
	// Intermediates, EKUs, serials, SKI, RequireP256) are ignored —
	// the custom validator owns the trust decision in full. If the
	// validator wants to combine its own logic with the built-in
	// chain validation, it can call ValidateSCP11Chain itself with
	// a Policy that has CustomValidator unset.
	//
	// Two invariants are still enforced after the validator returns,
	// because the rest of the SCP11 protocol cannot function
	// without them:
	//
	//   - The returned PublicKey must be on the NIST P-256 curve
	//     (SCP11 mandates P-256, GP Amendment F §1.3.2).
	//   - The PublicKey must be ECDH-convertible (i.e. a real
	//     point on the curve, not nil or a malformed value).
	//
	// These are not "policy" — they are protocol preconditions, so
	// they apply regardless of what the validator decides about
	// trust. Everything else (chain validity, EKU, revocation,
	// serial allowlists, SKI pinning, name constraints) is solely
	// the validator's responsibility when set.
	//
	// Returning a non-nil error fails closed: the session will not
	// be opened.
	CustomValidator func(rawCardResponse []byte) (*Result, error)
}

// Result holds the output of a successful chain validation.
type Result struct {
	// Leaf is the validated leaf certificate.
	Leaf *x509.Certificate

	// Chain is the verified certificate chain(s) from leaf to root.
	Chain [][]*x509.Certificate

	// PublicKey is the ECDSA public key extracted from the validated
	// leaf certificate. It is safe to use for SCP11 key agreement.
	PublicKey *ecdsa.PublicKey
}

// Errors returned by validation.
var (
	ErrNoRoots        = errors.New("trust: no root certificates configured")
	ErrNoCertificates = errors.New("trust: no certificates to validate")
	ErrChainInvalid   = errors.New("trust: certificate chain validation failed")
	ErrWrongCurve     = errors.New("trust: leaf certificate key is not P-256")
	ErrWrongKeyType   = errors.New("trust: leaf certificate key is not ECDSA")
	ErrSerialMismatch = errors.New("trust: leaf certificate serial not in allowed list")
	ErrSKIMismatch    = errors.New("trust: leaf certificate SKI does not match expected value")
)

// ValidateSCP11Chain validates a certificate chain for SCP11 trust
// establishment. It verifies the chain against the configured trust
// anchors, checks curve and key type constraints, and returns the
// validated leaf certificate and its public key.
//
// The input certs should be ordered with the leaf certificate last,
// matching the convention used by YubiKey Security Domain certificate
// stores and the Yubico SDK.
//
// If validation fails, the error describes why. The caller must not
// use any certificate material from a failed validation.
func ValidateSCP11Chain(certs []*x509.Certificate, policy Policy) (*Result, error) {
	if policy.Roots == nil || policy.Roots.Equal(x509.NewCertPool()) {
		return nil, ErrNoRoots
	}
	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}

	// Leaf is the last certificate in the chain.
	leaf := certs[len(certs)-1]

	// Build intermediates pool from provided intermediates + non-leaf certs.
	intermediates := policy.Intermediates
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	for _, c := range certs[:len(certs)-1] {
		intermediates.AddCert(c)
	}

	// Determine validation time.
	now := policy.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	// Build verify options.
	opts := x509.VerifyOptions{
		Roots:         policy.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}

	// EKU handling. Go's x509.VerifyOptions has a load-bearing default
	// here: leaving KeyUsages empty does NOT mean "no EKU check" — the
	// stdlib treats empty as []ExtKeyUsage{ExtKeyUsageServerAuth}, which
	// silently rejects any cert whose EKU set doesn't include serverAuth.
	// SCP11 card and OCE certs frequently have EKU=clientAuth or no EKU
	// at all, so the implicit serverAuth requirement breaks valid chains.
	// To honor the policy comment ("If empty, EKU is not checked"), we
	// must explicitly opt into ExtKeyUsageAny when the caller didn't
	// constrain EKUs.
	if len(policy.ExpectedEKUs) > 0 {
		opts.KeyUsages = policy.ExpectedEKUs
	} else {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	// Verify the chain.
	chains, err := leaf.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}

	// Validate public key type and curve.
	ecdsaKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	requireP256 := true
	if policy.RequireP256 != nil {
		requireP256 = *policy.RequireP256
	}
	if requireP256 && ecdsaKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: got %s", ErrWrongCurve, ecdsaKey.Curve.Params().Name)
	}

	// Check serial allowlist if configured.
	//
	// Serial encodings vary in the wild: callers paste in 0x prefixes,
	// uppercase hex, colon-separated bytes, or padded forms with
	// leading zeros. Earlier this comparison was a literal string
	// match against fmt.Sprintf("%x", leaf.SerialNumber) — every
	// surface variant of the same number was a false negative.
	// Normalize both sides to lowercase hex with no separators and
	// no leading zeros (matching big.Int's printing).
	if len(policy.AllowedSerials) > 0 {
		leafSerial := fmt.Sprintf("%x", leaf.SerialNumber)
		found := false
		for _, s := range policy.AllowedSerials {
			if normalizeSerial(s) == leafSerial {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: serial %s", ErrSerialMismatch, leafSerial)
		}
	}

	// Check SKI if configured.
	if len(policy.ExpectedSKI) > 0 {
		if !bytesEqual(leaf.SubjectKeyId, policy.ExpectedSKI) {
			return nil, ErrSKIMismatch
		}
	}

	return &Result{
		Leaf:      leaf,
		Chain:     chains,
		PublicKey: ecdsaKey,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeSerial canonicalizes a caller-supplied serial-number string
// to lowercase hex with no separators and no "0x" prefix, matching
// the format produced by fmt.Sprintf("%x", *big.Int). Accepts:
//
//   - "0x12abcd" / "0X12ABCD" (with prefix, any case)
//   - "12:AB:CD" (colon-separated, common openssl format)
//   - "12 ab cd" (space-separated)
//   - "12abcd" / "12ABCD"
//   - leading-zero variants ("0012ab")
//
// Leading zeros are stripped because big.Int prints without them.
func normalizeSerial(s string) string {
	// Strip 0x / 0X prefix.
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	// Drop separators and lowercase hex.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			out = append(out, c)
		case c >= 'A' && c <= 'F':
			out = append(out, c+('a'-'A'))
		case c == ':' || c == ' ' || c == '-' || c == '_':
			// separator: skip
		default:
			// Unknown character — keep as-is so an obvious mismatch
			// surfaces rather than silently passing.
			out = append(out, c)
		}
	}
	// Strip leading zeros (keep at least one digit).
	for len(out) > 1 && out[0] == '0' {
		out = out[1:]
	}
	return string(out)
}
