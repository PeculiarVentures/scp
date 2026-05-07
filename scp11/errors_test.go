package scp11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/trust"
)

// TestErrInvalidConfig_NilConfig confirms passing a nil Config to
// scp11.Open returns an error that errors.Is matches as
// ErrInvalidConfig. Mirrors TestOpen_NilConfig_RejectsExplicitly but
// adds the sentinel-chain assertion.
func TestErrInvalidConfig_NilConfig(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	_, err = Open(context.Background(), mc.Transport(), nil)
	if err == nil {
		t.Fatal("expected error for nil Config; got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "Config is required") {
		t.Errorf("error should retain descriptive context; got: %v", err)
	}
}

// TestErrInvalidConfig_NilTransport confirms a missing transport is
// reported as ErrInvalidConfig.
func TestErrInvalidConfig_NilTransport(t *testing.T) {
	_, err := Open(context.Background(), nil, testYubiKeySCP11bConfig())
	if err == nil {
		t.Fatal("expected error for nil transport; got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestErrInvalidConfig_NoTrustPosture confirms that opening with no
// trust configuration set returns ErrInvalidConfig with the "trust
// posture" message preserved.
func TestErrInvalidConfig_NoTrustPosture(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := testYubiKeySCP11bConfig()
	// Deliberately leave CardTrustPolicy / CardTrustAnchors /
	// InsecureSkipCardAuthentication unset.
	_, err = Open(context.Background(), mc.Transport(), cfg)
	if err == nil {
		t.Fatal("expected error for missing trust posture; got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "trust posture") {
		t.Errorf("error should retain 'trust posture' context; got: %v", err)
	}
}

// TestErrInvalidConfig_HostIDRejected confirms that setting HostID
// (which is not yet wired through AUTHENTICATE) is reported as
// ErrInvalidConfig with the "HostID" message preserved.
func TestErrInvalidConfig_HostIDRejected(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cfg := testYubiKeySCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	cfg.HostID = []byte{0x01, 0x02, 0x03}
	_, err = Open(context.Background(), mc.Transport(), cfg)
	if err == nil {
		t.Fatal("expected error for HostID set; got nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "HostID") {
		t.Errorf("error should retain 'HostID' context; got: %v", err)
	}
}

// TestErrTrustValidation_CustomValidatorRejection confirms that when
// a custom validator returns a non-P-256 key, the error chain carries
// ErrTrustValidation. SCP11 mandates P-256 regardless of what the
// validator decides.
func TestErrTrustValidation_CustomValidatorRejection(t *testing.T) {
	// Generate a P-384 key — valid ECDSA, wrong curve for SCP11.
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pol := &trust.Policy{
		CustomValidator: func(raw []byte) (*trust.Result, error) {
			return &trust.Result{PublicKey: &priv.PublicKey}, nil
		},
	}
	sess := &Session{config: &Config{CardTrustPolicy: pol}}
	err = sess.validateCardCertChain([]byte("ignored"))
	if err == nil {
		t.Fatal("validateCardCertChain should have rejected non-P-256 key")
	}
	if !errors.Is(err, ErrTrustValidation) {
		t.Errorf("errors.Is(err, ErrTrustValidation) = false; err = %v", err)
	}
}

// TestErrTrustValidation_CustomValidatorNilKey confirms that a custom
// validator returning a nil PublicKey is reported as ErrTrustValidation.
func TestErrTrustValidation_CustomValidatorNilKey(t *testing.T) {
	pol := &trust.Policy{
		CustomValidator: func(raw []byte) (*trust.Result, error) {
			return &trust.Result{PublicKey: nil}, nil
		},
	}
	sess := &Session{config: &Config{CardTrustPolicy: pol}}
	err := sess.validateCardCertChain([]byte("ignored"))
	if err == nil {
		t.Fatal("validateCardCertChain should have rejected nil PublicKey")
	}
	if !errors.Is(err, ErrTrustValidation) {
		t.Errorf("errors.Is(err, ErrTrustValidation) = false; err = %v", err)
	}
}

// TestSentinelsAreDistinct guards against accidentally aliasing two
// sentinels to the same value.
func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrAuthFailed, ErrInvalidConfig, ErrInvalidResponse, ErrTrustValidation}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels at index %d and %d compare equal: %v == %v", i, j, a, b)
			}
		}
	}
}
