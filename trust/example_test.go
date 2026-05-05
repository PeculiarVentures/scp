package trust_test

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/trust"
)

// ExamplePolicy_customValidator shows the extension point for cards
// that present SCP11 certificates in formats other than X.509, for
// corporate-PKI rules that go beyond what the standard X.509 path
// expresses, or for any deployment that needs to own the trust
// decision in full.
//
// When CustomValidator is set, all other Policy fields (Roots,
// Intermediates, ExpectedEKUs, AllowedSerials, ExpectedSKI,
// RequireP256) are ignored — the validator owns the trust decision
// in full. The protocol layer still enforces NIST P-256 and
// ECDH-convertibility on whatever public key the validator returns,
// because the SCP11 ECDH cannot function without them.
//
// Returning a non-nil error fails closed: the SCP11 session will
// not be opened. There is no fallback to the built-in X.509 path.
func ExamplePolicy_customValidator() {
	policy := &trust.Policy{
		CustomValidator: func(rawCardResponse []byte) (*trust.Result, error) {
			// Parse the card's certificate store in whatever format
			// it uses (GP-proprietary §7F21, vendor-specific TLV,
			// etc.) and apply your trust model: issuer SKI pinning,
			// signature verification against a known issuer key,
			// revocation lookup, and so on.
			pubKey, err := parseAndValidateProprietaryCertStore(rawCardResponse)
			if err != nil {
				return nil, fmt.Errorf("custom validator: %w", err)
			}
			return &trust.Result{PublicKey: pubKey}, nil
		},
	}
	_ = policy
	// Pass policy as scp11.Config.CardTrustPolicy when calling scp11.Open.
	// The SCP11 session layer will invoke CustomValidator with the raw
	// BF21 card response bytes and use the returned PublicKey for ECDH.
}

// parseAndValidateProprietaryCertStore is a stand-in for the
// caller-supplied parser that returns the card's authenticated
// SCP11 public key. A real implementation decodes the vendor-
// specific TLV structure, verifies signatures, and applies
// whatever trust constraints the deployment requires.
func parseAndValidateProprietaryCertStore([]byte) (*ecdsa.PublicKey, error) {
	return nil, errors.New("not implemented in this example")
}
