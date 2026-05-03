package session

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/channel"
)

// ============================================================
// Regression: trust anchor bypass via fallback parsing.
//
// Before the fix, if CardTrustAnchors was set but X.509 parsing
// failed, the code fell through to parseGPCertificate() or
// extractECDHKeyFromSPKI() which accept raw EC keys without any
// chain validation. After the fix, non-X.509 data is rejected
// when trust anchors are configured.
// ============================================================

func TestTrustAnchorBypass_RawKeyRejected(t *testing.T) {
	// Generate a raw uncompressed P-256 EC point (65 bytes, 0x04 prefix).
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rawPoint := privKey.PublicKey().Bytes() // 65 bytes, 0x04 || X || Y

	// Create a trust anchor pool (contents don't matter for this test —
	// the point is that trust anchors are configured at all).
	trustAnchors := x509.NewCertPool()

	// With trust anchors set, raw key data (not a valid X.509 cert)
	// should be rejected, NOT silently accepted.
	_, err = parseRawCert(rawPoint, trustAnchors)
	if err == nil {
		t.Fatal("raw EC point should be rejected when trust anchors are configured")
	}
	t.Logf("Correctly rejected raw key with trust anchors: %v", err)
}

func TestTrustAnchorBypass_RawKeyAcceptedWithoutAnchors(t *testing.T) {
	// Without trust anchors, raw key extraction should still work
	// (this is the SCP11b no-validation path).
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rawPoint := privKey.PublicKey().Bytes()

	key, err := parseRawCert(rawPoint, nil)
	if err != nil {
		t.Fatalf("raw key should be accepted without trust anchors: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	t.Log("Raw key correctly accepted without trust anchors")
}

func TestTrustAnchorBypass_ValidCertAccepted(t *testing.T) {
	// Generate a self-signed cert and add it as its own trust anchor.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	trustAnchors := x509.NewCertPool()
	caCert, _ := x509.ParseCertificate(certDER)
	trustAnchors.AddCert(caCert)

	// Valid X.509 cert with matching trust anchor should succeed.
	key, err := parseRawCert(certDER, trustAnchors)
	if err != nil {
		t.Fatalf("valid cert should be accepted: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	t.Log("Valid cert correctly accepted with trust anchors")
}

func TestTrustAnchorBypass_UntrustedCertRejected(t *testing.T) {
	// Generate a self-signed cert but DON'T add it to the trust pool.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Untrusted CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)

	// Use an empty trust pool — the cert should be rejected.
	trustAnchors := x509.NewCertPool()

	_, err := parseRawCert(certDER, trustAnchors)
	if err == nil {
		t.Fatal("untrusted cert should be rejected")
	}
	t.Logf("Correctly rejected untrusted cert: %v", err)
}

// ============================================================
// Regression: SCP11 SecurityLevel consistency.
//
// Since KeyUsage = 0x3C is hardcoded in the INTERNAL/MUTUAL
// AUTHENTICATE command, the card always negotiates full security.
// Config.SecurityLevel != LevelFull should be rejected.
// ============================================================

func TestSCP11_RejectsNonFullSecurityLevel(t *testing.T) {
	// We can't do a full Open() without a transport, but we can verify
	// that the validation fires before any network I/O.
	levels := []channel.SecurityLevel{
		channel.LevelCMAC,
		channel.LevelCMAC | channel.LevelCDEC,
		channel.LevelCMAC | channel.LevelRMAC,
	}
	for _, level := range levels {
		cfg := &Config{
			Variant:       SCP11b,
			SecurityLevel: level,
		}
		_, err := Open(context.Background(), nil, cfg)
		if err == nil {
			t.Errorf("SecurityLevel 0x%02X should be rejected", level)
		}
	}
	t.Log("Non-full security levels correctly rejected")
}

// ============================================================
// Regression: SCP11 must fail closed when no trust anchors and no
// explicit InsecureSkipCardAuthentication flag are configured.
//
// Before the fix, a nil CardTrustAnchors silently fell through to
// extractCardPublicKey which would accept raw EC points and GP
// proprietary encodings without any chain validation — turning
// SCP11b into "encrypted to whoever answered first." The fix in
// getCardCertificate must reject that path explicitly.
// ============================================================

func TestSCP11_FailsClosedWithoutTrustAnchorsOrOptIn(t *testing.T) {
	// Config that matches DefaultConfig() except for the trust fields:
	// no CardTrustAnchors, no CardTrustPolicy, no InsecureSkipCardAuthentication.
	cfg := DefaultConfig()
	// Construct a minimal session where getCardCertificate has already
	// retrieved data — we drive the legacy path directly.
	s := &Session{config: cfg}

	// Make a self-signed cert as plausible card response data. The
	// validation must reject the operation regardless of whether the
	// data parses, because no trust anchors are configured.
	cert := generateSelfSignedCert(t)

	err := s.legacyExtractAndStoreKey(cert.Raw)
	if err == nil {
		t.Fatal("expected error: SCP11 with no trust anchors and no opt-in must fail closed")
	}
	t.Logf("Correctly failed closed: %v", err)
}

func TestSCP11_OptInBypassWorks(t *testing.T) {
	// With InsecureSkipCardAuthentication = true, the legacy fallback
	// is permitted (intended only for tests/labs).
	cfg := DefaultConfig()
	cfg.InsecureSkipCardAuthentication = true
	s := &Session{config: cfg}

	cert := generateSelfSignedCert(t)
	if err := s.legacyExtractAndStoreKey(cert.Raw); err != nil {
		t.Fatalf("opt-in bypass should permit unauthenticated key extraction: %v", err)
	}
}

// --- parseCertsFromStore tests ---

func TestParseCertsFromStore_SingleDER(t *testing.T) {
	// Generate a self-signed cert and pass its raw DER.
	cert := generateSelfSignedCert(t)
	certs, err := parseCertsFromStore(cert.Raw)
	if err != nil {
		t.Fatalf("parseCertsFromStore: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("wrong cert: %q", certs[0].Subject.CommonName)
	}
}

func TestParseCertsFromStore_ConcatenatedDER(t *testing.T) {
	cert1 := generateSelfSignedCert(t)
	cert2 := generateSelfSignedCert(t)

	// Concatenate raw DER.
	concat := append(cert1.Raw, cert2.Raw...)
	certs, err := parseCertsFromStore(concat)
	if err != nil {
		t.Fatalf("parseCertsFromStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
}

func TestSplitDER(t *testing.T) {
	cert1 := generateSelfSignedCert(t)
	cert2 := generateSelfSignedCert(t)

	concat := append(cert1.Raw, cert2.Raw...)
	parts := splitDER(concat)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if len(parts[0]) != len(cert1.Raw) {
		t.Errorf("part 0 length: got %d, want %d", len(parts[0]), len(cert1.Raw))
	}
}

func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// ============================================================
// Regression: OCE private key must correspond to OCE certificate.
//
// Configuration mistakes where the private key and the certificate
// are unrelated would otherwise be caught only by the card during
// MUTUAL AUTHENTICATE — which is too late, and on a permissive card
// could complete a session under a fundamentally different identity
// than the host believes it is presenting.
// ============================================================

func TestVerifyOCEKeyMatchesCert_Match(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCE"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	if err := verifyOCEKeyMatchesCert(priv, cert); err != nil {
		t.Errorf("matching key/cert rejected: %v", err)
	}
}

func TestVerifyOCEKeyMatchesCert_Mismatch(t *testing.T) {
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCE"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
	// Cert holds keyA's public key; we pass keyB as the private key.
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &keyA.PublicKey, keyA)
	cert, _ := x509.ParseCertificate(der)

	if err := verifyOCEKeyMatchesCert(keyB, cert); err == nil {
		t.Error("mismatched key/cert should be rejected")
	}
}

func TestVerifyOCEKeyMatchesCert_NilInputs(t *testing.T) {
	if err := verifyOCEKeyMatchesCert(nil, nil); err == nil {
		t.Error("nil inputs should be rejected")
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyOCEKeyMatchesCert(priv, nil); err == nil {
		t.Error("nil cert should be rejected")
	}
}

func TestVerifyOCEKeyMatchesCert_CurveMismatch(t *testing.T) {
	// Private key on P-256, cert on P-384.
	privP256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCE"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caP384.PublicKey, caP384)
	cert, _ := x509.ParseCertificate(der)

	if err := verifyOCEKeyMatchesCert(privP256, cert); err == nil {
		t.Error("curve-mismatched key/cert should be rejected")
	}
}
