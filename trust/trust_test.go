package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// --- Test helpers ---

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func generateTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, ski []byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		SubjectKeyId: ski,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func rootPool(ca *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// --- Tests ---

func TestValidateSCP11Chain_Success(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 42, nil)

	result, err := ValidateSCP11Chain(
		[]*x509.Certificate{ca, leaf},
		Policy{Roots: rootPool(ca)},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Leaf != leaf {
		t.Error("result.Leaf should be the leaf certificate")
	}
	if result.PublicKey == nil {
		t.Error("result.PublicKey should not be nil")
	}
	if len(result.Chain) == 0 {
		t.Error("result.Chain should not be empty")
	}
}

func TestValidateSCP11Chain_NoRoots(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 42, nil)

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{Roots: nil},
	)
	if err != ErrNoRoots {
		t.Fatalf("expected ErrNoRoots, got: %v", err)
	}
}

func TestValidateSCP11Chain_EmptyRoots(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 42, nil)

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{Roots: x509.NewCertPool()},
	)
	if err != ErrNoRoots {
		t.Fatalf("expected ErrNoRoots, got: %v", err)
	}
}

func TestValidateSCP11Chain_NoCertificates(t *testing.T) {
	ca, _ := generateTestCA(t)

	_, err := ValidateSCP11Chain(
		nil,
		Policy{Roots: rootPool(ca)},
	)
	if err != ErrNoCertificates {
		t.Fatalf("expected ErrNoCertificates, got: %v", err)
	}
}

func TestValidateSCP11Chain_WrongCA(t *testing.T) {
	ca1, _ := generateTestCA(t)
	ca2, ca2Key := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca2, ca2Key, 42, nil)

	// Validate against ca1 but leaf is signed by ca2.
	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{Roots: rootPool(ca1)},
	)
	if err == nil {
		t.Fatal("expected chain validation error")
	}
}

func TestValidateSCP11Chain_ExpiredLeaf(t *testing.T) {
	ca, caKey := generateTestCA(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Expired Leaf"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(der)

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{Roots: rootPool(ca)},
	)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
}

func TestValidateSCP11Chain_AllowedSerials_Match(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 0x2A, nil) // serial = 42 = 0x2a

	result, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{
			Roots:          rootPool(ca),
			AllowedSerials: []string{"2a"},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Leaf != leaf {
		t.Error("wrong leaf")
	}
}

func TestValidateSCP11Chain_AllowedSerials_Mismatch(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 0x2A, nil)

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{
			Roots:          rootPool(ca),
			AllowedSerials: []string{"ff"},
		},
	)
	if err == nil {
		t.Fatal("expected serial mismatch error")
	}
}

func TestValidateSCP11Chain_ExpectedSKI_Match(t *testing.T) {
	ca, caKey := generateTestCA(t)
	ski := []byte{0xAA, 0xBB, 0xCC}
	leaf, _ := generateTestLeaf(t, ca, caKey, 42, ski)

	result, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{
			Roots:       rootPool(ca),
			ExpectedSKI: ski,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PublicKey == nil {
		t.Error("expected public key")
	}
}

func TestValidateSCP11Chain_ExpectedSKI_Mismatch(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 42, []byte{0x01})

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{
			Roots:       rootPool(ca),
			ExpectedSKI: []byte{0xFF},
		},
	)
	if err != ErrSKIMismatch {
		t.Fatalf("expected ErrSKIMismatch, got: %v", err)
	}
}

func TestValidateSCP11Chain_LeafIsLastInSlice(t *testing.T) {
	// The Yubico convention is leaf-last. Verify we pick the right one.
	ca, caKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, ca, caKey, 99, nil)

	result, err := ValidateSCP11Chain(
		[]*x509.Certificate{ca, leaf}, // CA first, leaf last
		Policy{Roots: rootPool(ca)},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Leaf.SerialNumber.Int64() != 99 {
		t.Errorf("expected serial 99, got %v", result.Leaf.SerialNumber)
	}
}
