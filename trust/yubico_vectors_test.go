package trust

// Test fixtures from the Yubico yubikey-manager Python SDK (BSD 2-clause licensed).
// Source: Yubico/yubikey-manager, tests/files/scp/
//
// Three-level ECDSA P-256 certificate chain for SCP11a OCE provisioning:
//   CA-KLOC root (self-signed) -> KA-KLOC intermediate -> OCE leaf
//
// PEM strings copied verbatim from the repository to avoid transcription errors.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func decodePEM(pemStr string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		panic("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

// CA-KLOC root: self-signed, CA:true, pathlen:1
const yubicoRootPEM = `-----BEGIN CERTIFICATE-----
MIIB2zCCAYGgAwIBAgIUSf59wIpCKOrNGNc5FMPTD9zDGVAwCgYIKoZIzj0EAwIw
KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
NDA1MjgwOTIyMDlaFw0yNDA2MjcwOTIyMDlaMCoxKDAmBgNVBAMMH0V4YW1wbGUg
T0NFIFJvb3QgQ0EgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASPrxfpSB/AvuvLKaCz1YTx68Xbtx8S9xAMfRGwzp5cXMdF8c7AWpUfeM3BQ26M
h0WPvyBJKhCdeK8iVCaHyr5Jo4GEMIGBMB0GA1UdDgQWBBQxqlVmn2Bn6B8z3P0E
/t5z5XGfPTASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjA8BgNV
HSABAf8EMjAwMA4GDCqGSIb8a2QACgIBFDAOBgwqhkiG/GtkAAoCASgwDgYMKoZI
hvxrZAAKAgEAMAoGCCqGSM49BAMCA0gAMEUCIHv8cgOzxq2n1uZktL9gCXSR85mk
TieYeSoKZn6MM4rOAiEA1S/+7ez/gxDl01ztKeoHiUiW4FbEG4JUCzIITaGxVvM=
-----END CERTIFICATE-----`

// KA-KLOC intermediate: CA:true, pathlen:0, signed by CA-KLOC
const yubicoIntermediatePEM = `-----BEGIN CERTIFICATE-----
MIIB8DCCAZegAwIBAgIUf0lxsK1R+EydqZKLLV/vXhaykgowCgYIKoZIzj0EAwIw
KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
NDA1MjgwOTIyMDlaFw0yNDA4MjYwOTIyMDlaMC8xLTArBgNVBAMMJEV4YW1wbGUg
T0NFIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABMXbjb+Y33+GP8qUznrdZSJX9b2qC0VUS1WDhuTlQUfg/RBNFXb2/qWt
h/a+Ag406fV7wZW2e4PPH+Le7EwS1nyjgZUwgZIwHQYDVR0OBBYEFJzdQCINVBES
R4yZBN2l5CXyzlWsMB8GA1UdIwQYMBaAFDGqVWafYGfoHzPc/QT+3nPlcZ89MBIG
A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMCwGA1UdIAEB/wQiMCAw
DgYMKoZIhvxrZAAKAgEoMA4GDCqGSIb8a2QACgIBADAKBggqhkjOPQQDAgNHADBE
AiBE5SpNEKDW3OehDhvTKT9g1cuuIyPdaXGLZ3iX0x0VcwIgdnIirhlKocOKGXf9
ijkE8e+9dTazSPLf24lSIf0IGC8=
-----END CERTIFICATE-----`

// OCE leaf: keyAgreement, signed by KA-KLOC
const yubicoLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBwjCCAWmgAwIBAgIUa5ACiACQn5/81kE0aTMkJ0j76a0wCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkRXhhbXBsZSBPQ0UgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRl
MB4XDTI0MDUyODA5MjIwOVoXDTI0MDgyNjA5MjIwOVowIjEgMB4GA1UEAwwXRXhh
bXBsZSBPQ0UgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASY
yRCUFDM7fb0iOwyaO4ayzp+vh7UhonFbCuzgYKMLHplN3r8cyQNuso0J5UqZUwVy
llE1EAF2Pu+RlJvtnYD2o3AwbjAdBgNVHQ4EFgQU6dH0CdJ18Nzbj3vamDW/rZl7
GvcwHwYDVR0jBBgwFoAUnN1AIg1UERJHjJkE3aXkJfLOVawwDgYDVR0PAQH/BAQD
AgMIMBwGA1UdIAEB/wQSMBAwDgYMKoZIhvxrZAAKAgEAMAoGCCqGSM49BAMCA0cA
MEQCIE2Fp0ybSmD5sZ6kvrpUJ14WAdHjUbUfFxXwLU4Dnn2tAiBmPMUa4DqpnnnN
Xfx/i/gUmwCTdA+dFrc1jWYZ8qVd6Q==
-----END CERTIFICATE-----`

func TestYubicoCertChain_Parse(t *testing.T) {
	root := decodePEM(yubicoRootPEM)
	if root.Subject.CommonName != "Example OCE Root CA Certificate" {
		t.Errorf("root CN: %q", root.Subject.CommonName)
	}
	if !root.IsCA {
		t.Error("root should be CA")
	}
	ecKey, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("root key should be ECDSA")
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("root key should be P-256")
	}

	inter := decodePEM(yubicoIntermediatePEM)
	if inter.Subject.CommonName != "Example OCE Intermediate Certificate" {
		t.Errorf("intermediate CN: %q", inter.Subject.CommonName)
	}
	if !inter.IsCA {
		t.Error("intermediate should be CA")
	}

	leaf := decodePEM(yubicoLeafPEM)
	if leaf.Subject.CommonName != "Example OCE Certificate" {
		t.Errorf("leaf CN: %q", leaf.Subject.CommonName)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Error("leaf key should be ECDSA")
	}

	// Verify the chain signatures are consistent.
	if err := inter.CheckSignatureFrom(root); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		t.Errorf("leaf not signed by intermediate: %v", err)
	}
}

func TestYubicoCertChain_ValidateWithIntermediate(t *testing.T) {
	root := decodePEM(yubicoRootPEM)
	inter := decodePEM(yubicoIntermediatePEM)
	leaf := decodePEM(yubicoLeafPEM)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// All certs valid on June 15, 2024 (root expires Jun 27, others Aug 26).
	validTime := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)

	// Chain: intermediate, leaf (leaf-last per Yubico convention).
	result, err := ValidateSCP11Chain(
		[]*x509.Certificate{inter, leaf},
		Policy{
			Roots:       roots,
			CurrentTime: validTime,
		},
	)
	if err != nil {
		t.Fatalf("validate chain: %v", err)
	}

	if result.PublicKey == nil {
		t.Fatal("expected non-nil public key")
	}
	if result.PublicKey.Curve != elliptic.P256() {
		t.Error("expected P-256 key")
	}
	if result.Leaf.Subject.CommonName != "Example OCE Certificate" {
		t.Errorf("wrong leaf: %q", result.Leaf.Subject.CommonName)
	}
	if len(result.Chain) == 0 {
		t.Error("expected non-empty chain")
	}
}

func TestYubicoCertChain_FailsClosed_Expired(t *testing.T) {
	root := decodePEM(yubicoRootPEM)
	leaf := decodePEM(yubicoLeafPEM)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Current time — all certs are expired.
	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{leaf},
		Policy{Roots: roots, CurrentTime: time.Now()},
	)
	if err == nil {
		t.Error("expected validation to fail with expired certs")
	}
}

func TestYubicoCertChain_FailsClosed_WrongRoot(t *testing.T) {
	wrongRoot, _ := generateTestCA(t)
	inter := decodePEM(yubicoIntermediatePEM)
	leaf := decodePEM(yubicoLeafPEM)

	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(wrongRoot)

	validTime := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)

	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{inter, leaf},
		Policy{Roots: wrongRoots, CurrentTime: validTime},
	)
	if err == nil {
		t.Error("expected validation to fail with wrong root")
	}
}

func TestYubicoCertChain_SerialAllowlist(t *testing.T) {
	root := decodePEM(yubicoRootPEM)
	inter := decodePEM(yubicoIntermediatePEM)
	leaf := decodePEM(yubicoLeafPEM)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	validTime := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)

	// Leaf serial: 6b90028800909f9ffcd641346933242748fbe9ad
	leafSerial := leaf.SerialNumber.Text(16)

	// Should pass with correct serial.
	_, err := ValidateSCP11Chain(
		[]*x509.Certificate{inter, leaf},
		Policy{
			Roots:          roots,
			CurrentTime:    validTime,
			AllowedSerials: []string{leafSerial},
		},
	)
	if err != nil {
		t.Fatalf("expected pass with matching serial: %v", err)
	}

	// Should fail with wrong serial.
	_, err = ValidateSCP11Chain(
		[]*x509.Certificate{inter, leaf},
		Policy{
			Roots:          roots,
			CurrentTime:    validTime,
			AllowedSerials: []string{"deadbeef"},
		},
	)
	if err == nil {
		t.Error("expected fail with non-matching serial")
	}
}
