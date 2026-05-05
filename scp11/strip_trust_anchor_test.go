package scp11

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

// TestStripLeadingTrustAnchors_RemovesSelfSignedRoot is the headline
// invariant: a [self-signed CA, leaf-signed-by-CA] chain becomes
// [leaf] after stripping. This is the behavior that fixes
// scp11a-sd-read FAIL with "PSO cert 1/2: SW=6A80" against retail
// YubiKey 5.7.4.
func TestStripLeadingTrustAnchors_RemovesSelfSignedRoot(t *testing.T) {
	root, leaf := mkChainRootAndLeaf(t)
	chain := []*x509.Certificate{root, leaf}
	got := stripLeadingTrustAnchors(chain)
	if len(got) != 1 {
		t.Fatalf("got %d cert(s); want 1 (root stripped, leaf kept)", len(got))
	}
	if got[0].Subject.CommonName != "leaf" {
		t.Errorf("kept cert CN = %q; want leaf", got[0].Subject.CommonName)
	}
}

// TestStripLeadingTrustAnchors_KeepsLeafOnly: chain that already
// excludes the trust anchor passes through unchanged. Caller can
// pre-strip if they want and the function is idempotent.
func TestStripLeadingTrustAnchors_KeepsLeafOnly(t *testing.T) {
	_, leaf := mkChainRootAndLeaf(t)
	chain := []*x509.Certificate{leaf}
	got := stripLeadingTrustAnchors(chain)
	if len(got) != 1 || got[0] != leaf {
		t.Errorf("expected the leaf to pass through unchanged")
	}
}

// TestStripLeadingTrustAnchors_KeepsIntermediates: a [root, intermediate, leaf]
// chain becomes [intermediate, leaf] — the intermediate is below the
// trust anchor and must be sent so the card can build the path.
func TestStripLeadingTrustAnchors_KeepsIntermediates(t *testing.T) {
	root, intermediate, leaf := mkChainRootIntermediateLeaf(t)
	chain := []*x509.Certificate{root, intermediate, leaf}
	got := stripLeadingTrustAnchors(chain)
	if len(got) != 2 {
		t.Fatalf("got %d cert(s); want 2 (root stripped, intermediate + leaf kept)", len(got))
	}
	if got[0].Subject.CommonName != "intermediate" || got[1].Subject.CommonName != "leaf" {
		t.Errorf("kept CNs = [%s, %s]; want [intermediate, leaf]",
			got[0].Subject.CommonName, got[1].Subject.CommonName)
	}
}

// TestStripLeadingTrustAnchors_AllSelfSignedReturnsEmpty: pathological
// case of a chain consisting entirely of self-signed certs (e.g. only
// the trust anchor was supplied by mistake). Returns nil so the
// caller can surface a useful error.
func TestStripLeadingTrustAnchors_AllSelfSignedReturnsEmpty(t *testing.T) {
	root, _ := mkChainRootAndLeaf(t)
	got := stripLeadingTrustAnchors([]*x509.Certificate{root, root})
	if got != nil {
		t.Errorf("expected nil for all-self-signed chain; got %d cert(s)", len(got))
	}
}

// mkChainRootAndLeaf returns (root, leaf) where leaf is signed by root.
func mkChainRootAndLeaf(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return root, leaf
}

// mkChainRootIntermediateLeaf returns a 3-cert chain.
func mkChainRootIntermediateLeaf(t *testing.T) (*x509.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	root, _ := x509.ParseCertificate(rootDER)

	interPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, root, &interPriv.PublicKey, rootPriv)
	inter, _ := x509.ParseCertificate(interDER)

	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, inter, &leafPriv.PublicKey, interPriv)
	leaf, _ := x509.ParseCertificate(leafDER)
	return root, inter, leaf
}
