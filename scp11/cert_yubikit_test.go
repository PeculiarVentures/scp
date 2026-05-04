package scp11

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
)

// TestExtractCardPublicKey_YubikitBundle verifies extractCardPublicKey
// handles the cert-store shape Yubico yubikit emits: a top-level
// concatenation of one or more DER X.509 certificates, with no GP
// 7F21 wrapper and no BF21 outer container. This was the failure mode
// reported as "no EC public key found in data" against a real
// YubiKey 5.7+ in scpctl smoke scp11b-sd-read.
//
// Reference: yubikit.securitydomain.get_certificate_bundle, which
// iterates top-level TLVs in the response and feeds each to
// load_der_x509_certificate. The leaf is last in the bundle.
func TestExtractCardPublicKey_YubikitBundle(t *testing.T) {
	leaf, leafPub := mustGenerateP256Cert(t, "leaf")
	intermediate, _ := mustGenerateP256Cert(t, "intermediate")

	// Yubikit shape: leaf-last concatenation. Each cert is a complete
	// DER SEQUENCE TLV; tlv.Decode yields one node per cert.
	bundle := append([]byte{}, intermediate...)
	bundle = append(bundle, leaf...)

	pub, err := extractCardPublicKey(bundle, nil)
	if err != nil {
		t.Fatalf("extractCardPublicKey on yubikit-shape bundle: %v", err)
	}
	if !pub.Equal(leafPub) {
		t.Errorf("returned public key is not the leaf's; the parser " +
			"selected the wrong cert from the bundle")
	}
}

// TestExtractCardPublicKey_YubikitSingleCert verifies the same path
// also works when the SD returns a single cert with no chain — the
// degenerate but valid case of a self-signed SCP11 card cert.
func TestExtractCardPublicKey_YubikitSingleCert(t *testing.T) {
	cert, certPub := mustGenerateP256Cert(t, "single")

	pub, err := extractCardPublicKey(cert, nil)
	if err != nil {
		t.Fatalf("extractCardPublicKey on single-cert bundle: %v", err)
	}
	if !pub.Equal(certPub) {
		t.Errorf("returned public key does not match the input cert")
	}
}

// TestDerCertList_RejectsTrailingJunk confirms derCertList does not
// silently accept buffers that have well-formed DER prefix but garbage
// after — the parser should return nil so extractCardPublicKey falls
// through to the existing fallback paths instead of treating the prefix
// as a valid bundle and ignoring the rest.
func TestDerCertList_RejectsTrailingJunk(t *testing.T) {
	cert, _ := mustGenerateP256Cert(t, "trail")
	junk := append(append([]byte{}, cert...), 0xFF, 0xFF, 0xFF)

	if got := derCertList(junk); got != nil {
		t.Errorf("derCertList returned %d cert(s) for buffer with trailing junk; want nil",
			len(got))
	}
}

// TestDerCertList_RejectsNonSequence confirms an empty buffer or a
// buffer whose first byte is not 0x30 (DER SEQUENCE) is treated as
// "not a yubikit cert list" so the parser doesn't misinterpret raw
// EC points or other shapes as cert bundles.
func TestDerCertList_RejectsNonSequence(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x04, 0x41, 0x00},     // looks like an EC point header
		{0x7F, 0x21, 0x05},     // GP 7F21 cert wrapper, not a SEQUENCE
		{0xBF, 0x21, 0x10, 0x30, 0x82, 0x00, 0x00}, // BF21-wrapped, not bare
	}
	for i, c := range cases {
		if got := derCertList(c); got != nil {
			t.Errorf("case %d: derCertList(%X) = %d cert(s); want nil", i, c, len(got))
		}
	}
}

// mustGenerateP256Cert returns (DER, ecdh public key) for a fresh
// self-signed P-256 certificate. The cert is a complete X.509 — what
// a real card would emit in its certificate store entry.
func mustGenerateP256Cert(t *testing.T, cn string) ([]byte, *ecdh.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert to ECDH: %v", err)
	}
	return der, ecdhPub
}
