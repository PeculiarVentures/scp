package trust

import (
	"crypto/x509"
	"errors"
	"testing"
)

// TestPolicy_Validate_BuiltinModeNoConflict pins that a Policy
// with CustomValidator nil is always considered well-formed by
// Validate. (Whether Roots is set is checked separately by
// ValidateSCP11Chain at consumption time; Validate's only job is
// the mutual-exclusion check between the two operating modes.)
func TestPolicy_Validate_BuiltinModeNoConflict(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
	}{
		{"empty (Roots-missing surfaces later)", Policy{}},
		{"roots only", Policy{Roots: x509.NewCertPool()}},
		{"roots + intermediates", Policy{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
		}},
		{"roots + EKU + serials + SKI + RequireP256", Policy{
			Roots:          x509.NewCertPool(),
			ExpectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			AllowedSerials: []string{"01"},
			ExpectedSKI:    []byte{0xAB, 0xCD},
			RequireP256:    boolPtr(true),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); err != nil {
				t.Errorf("Validate: unexpected error %v", err)
			}
		})
	}
}

// TestPolicy_Validate_CustomModeNoConflict pins that a Policy
// with ONLY CustomValidator set (no other ignored fields) is
// well-formed. This is the canonical custom-mode shape.
func TestPolicy_Validate_CustomModeNoConflict(t *testing.T) {
	policy := Policy{
		CustomValidator: func(data []byte) (*Result, error) {
			return nil, nil
		},
	}
	if err := policy.Validate(); err != nil {
		t.Errorf("Validate: unexpected error %v", err)
	}
}

// TestPolicy_Validate_CustomModeWithConflicts pins that mixing
// CustomValidator with any of the ignored fields fails closed
// with ErrPolicyConfigConflict, naming the specific conflicting
// field(s) in the error message.
//
// This is the foot-gun ChatGPT's external review flagged: callers
// who set both Roots and CustomValidator expecting composition
// would silently get the CustomValidator path with Roots dropped.
// The fix is to refuse the configuration outright rather than
// silently drop fields the caller expected to be enforced.
func TestPolicy_Validate_CustomModeWithConflicts(t *testing.T) {
	cv := func(data []byte) (*Result, error) { return nil, nil }
	cases := []struct {
		name          string
		policy        Policy
		wantInMessage string
	}{
		{
			"Roots set",
			Policy{CustomValidator: cv, Roots: x509.NewCertPool()},
			"Roots",
		},
		{
			"Intermediates set",
			Policy{CustomValidator: cv, Intermediates: x509.NewCertPool()},
			"Intermediates",
		},
		{
			"ExpectedEKUs set",
			Policy{CustomValidator: cv, ExpectedEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			"ExpectedEKUs",
		},
		{
			"AllowedSerials set",
			Policy{CustomValidator: cv, AllowedSerials: []string{"01"}},
			"AllowedSerials",
		},
		{
			"ExpectedSKI set",
			Policy{CustomValidator: cv, ExpectedSKI: []byte{0xAB}},
			"ExpectedSKI",
		},
		{
			"RequireP256 set",
			Policy{CustomValidator: cv, RequireP256: boolPtr(true)},
			"RequireP256",
		},
		{
			"RejectUnparseableCertEntries set",
			Policy{CustomValidator: cv, RejectUnparseableCertEntries: true},
			"RejectUnparseableCertEntries",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if err == nil {
				t.Fatal("Validate: expected error, got nil")
			}
			if !errors.Is(err, ErrPolicyConfigConflict) {
				t.Errorf("Validate: error not ErrPolicyConfigConflict (errors.Is); got %v", err)
			}
			if !contains(err.Error(), tc.wantInMessage) {
				t.Errorf("Validate: error %q does not name the conflicting field %q",
					err.Error(), tc.wantInMessage)
			}
		})
	}
}

// TestPolicy_Validate_CustomModeMultipleConflicts pins that all
// conflicting fields appear in the error message, not just the
// first-detected one. Operators debugging a misconfigured policy
// need the full list to fix it in one round trip.
func TestPolicy_Validate_CustomModeMultipleConflicts(t *testing.T) {
	policy := Policy{
		CustomValidator: func(data []byte) (*Result, error) { return nil, nil },
		Roots:           x509.NewCertPool(),
		ExpectedEKUs:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExpectedSKI:     []byte{0xAB},
	}
	err := policy.Validate()
	if err == nil {
		t.Fatal("Validate: expected error, got nil")
	}
	for _, fld := range []string{"Roots", "ExpectedEKUs", "ExpectedSKI"} {
		if !contains(err.Error(), fld) {
			t.Errorf("Validate: error %q missing conflicting field %q", err.Error(), fld)
		}
	}
}

// TestValidateSCP11Chain_RejectsMisconfiguredPolicy pins that
// the entry point itself refuses to run when the policy fails
// Validate. This is the load-bearing assertion: a misconfigured
// Policy never reaches the chain-validation logic, so silently-
// ignored fields can't masquerade as validated.
func TestValidateSCP11Chain_RejectsMisconfiguredPolicy(t *testing.T) {
	// Policy is built-in mode (CustomValidator nil) so no
	// misconfiguration here; this test wraps a real failure.
	// We construct a custom-mode policy with Roots set, which
	// triggers the conflict.
	policy := Policy{
		CustomValidator: func(data []byte) (*Result, error) { return nil, nil },
		Roots:           x509.NewCertPool(),
	}
	_, err := ValidateSCP11Chain(nil, policy)
	if err == nil {
		t.Fatal("ValidateSCP11Chain: expected error from policy validation, got nil")
	}
	if !errors.Is(err, ErrPolicyConfigConflict) {
		t.Errorf("ValidateSCP11Chain: error not ErrPolicyConfigConflict; got %v", err)
	}
}

// boolPtr is a small helper for setting *bool fields in test
// fixtures.
func boolPtr(b bool) *bool { return &b }

// contains reports whether substr appears in s. Avoids importing
// strings just for this.
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
