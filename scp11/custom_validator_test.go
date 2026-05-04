package scp11

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/trust"
)

// TestCustomValidator_Called confirms that when Policy.CustomValidator
// is set, it gets the raw card response bytes and its returned key is
// used. This is the hook for GP-proprietary cert support: the caller
// owns the parse + trust decision in full.
func TestCustomValidator_Called(t *testing.T) {
	// Generate a fresh P-256 key the validator will return.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	const cardBytes = "fake-bf21-bytes-from-card"
	var seenInput []byte

	pol := &trust.Policy{
		CustomValidator: func(raw []byte) (*trust.Result, error) {
			seenInput = append(seenInput[:0], raw...)
			return &trust.Result{PublicKey: &priv.PublicKey}, nil
		},
	}

	sess := &Session{
		config: &Config{CardTrustPolicy: pol},
	}
	if err := sess.validateCardCertChain([]byte(cardBytes)); err != nil {
		t.Fatalf("validateCardCertChain: %v", err)
	}
	if string(seenInput) != cardBytes {
		t.Errorf("validator received %q, want %q", seenInput, cardBytes)
	}
	if sess.cardStaticPubKey == nil {
		t.Fatal("cardStaticPubKey not set after custom validator success")
	}
	expected, _ := priv.PublicKey.ECDH()
	if !ecdhEqual(sess.cardStaticPubKey, expected) {
		t.Error("cardStaticPubKey does not match the validator's returned key")
	}
	if sess.state != StateCertRetrieved {
		t.Errorf("state = %v, want StateCertRetrieved", sess.state)
	}
}

// TestCustomValidator_ErrorPropagates confirms a custom validator
// rejection fails the session — no fallback to the X.509 path, no
// silent acceptance.
func TestCustomValidator_ErrorPropagates(t *testing.T) {
	wantErr := errors.New("revoked card")
	pol := &trust.Policy{
		CustomValidator: func(raw []byte) (*trust.Result, error) {
			return nil, wantErr
		},
	}
	sess := &Session{config: &Config{CardTrustPolicy: pol}}
	err := sess.validateCardCertChain([]byte("ignored"))
	if err == nil {
		t.Fatal("validateCardCertChain should have failed")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error chain doesn't include validator's error; got %v", err)
	}
}

// TestCustomValidator_NilResultRejected confirms a validator that
// returns (nil, nil) — perhaps a buggy caller — fails closed rather
// than dereferencing nil.
func TestCustomValidator_NilResultRejected(t *testing.T) {
	pol := &trust.Policy{
		CustomValidator: func(raw []byte) (*trust.Result, error) {
			return nil, nil
		},
	}
	sess := &Session{config: &Config{CardTrustPolicy: pol}}
	err := sess.validateCardCertChain([]byte("ignored"))
	if err == nil {
		t.Fatal("validateCardCertChain should have failed on nil result")
	}
}

func ecdhEqual(a, b *ecdh.PublicKey) bool {
	return a != nil && b != nil && string(a.Bytes()) == string(b.Bytes())
}
