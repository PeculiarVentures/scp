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
// session.Open callers who want explicit chain validation before
// trusting a card's identity.
//
// # Fail-closed behavior
//
// If trust anchors are configured, validation must succeed before the
// leaf certificate's public key is returned. There is no silent fallback
// to raw key extraction.
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

	// If specific EKUs are required, set them.
	if len(policy.ExpectedEKUs) > 0 {
		opts.KeyUsages = policy.ExpectedEKUs
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
	if len(policy.AllowedSerials) > 0 {
		leafSerial := fmt.Sprintf("%x", leaf.SerialNumber)
		found := false
		for _, s := range policy.AllowedSerials {
			if s == leafSerial {
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
