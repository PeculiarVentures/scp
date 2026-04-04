package session

import (
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
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		IsCA:         true,
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
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Untrusted CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
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
		_, err := Open(nil, nil, cfg)
		if err == nil {
			t.Errorf("SecurityLevel 0x%02X should be rejected", level)
		}
	}
	t.Log("Non-full security levels correctly rejected")
}
