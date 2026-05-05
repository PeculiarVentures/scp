package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestOceCAFromChain_PicksFirstNotLast confirms the helper returns
// chain[0] (the CA) and not chain[len-1] (the leaf). This is the
// linchpin invariant of the OCE installation fix: previous code
// installed chain[len-1] (leaf) at KID=0x10, which the card rejects
// during SCP11a PSO with SW=6A80 because KID=0x10 is the CA-KLOC
// reference per GP Amendment F §7.1.1, not a leaf-key slot.
func TestOceCAFromChain_PicksFirstNotLast(t *testing.T) {
	caCert, _, leafCert, _ := mkOCEChain(t, "test-ca", "test-leaf")

	gotCert, _, ski, err := oceCAFromChain([]*x509.Certificate{caCert, leafCert})
	if err != nil {
		t.Fatalf("oceCAFromChain: %v", err)
	}
	if gotCert.Subject.CommonName != "test-ca" {
		t.Errorf("got CN=%q; want test-ca (the CA, chain[0])", gotCert.Subject.CommonName)
	}
	if len(ski) == 0 {
		t.Error("SKI should be non-empty (extension or computed)")
	}
}

// TestOceCAFromChain_SKIExtensionUsedWhenPresent confirms an
// explicitly-set SubjectKeyId on the cert is preferred over the
// SHA-1(SPKI) fallback. Yubico's tooling propagates the extension
// SKI through fleet records; we should match.
func TestOceCAFromChain_SKIExtensionUsedWhenPresent(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	wantSKI := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "explicit SKI CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: wantSKI,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	_, _, gotSKI, err := oceCAFromChain([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("oceCAFromChain: %v", err)
	}
	if !bytes.Equal(gotSKI, wantSKI) {
		t.Errorf("SKI = %X; want %X (the extension value)", gotSKI, wantSKI)
	}
}

// TestOceCAFromChain_RejectsEmpty pins the empty-chain failure case.
func TestOceCAFromChain_RejectsEmpty(t *testing.T) {
	_, _, _, err := oceCAFromChain(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention 'empty'; got: %v", err)
	}
}

// TestBootstrapOCE_InstallsCANotLeaf is the headline regression
// fence. Builds a chain with distinct CA and leaf keys, runs
// bootstrap-oce, and confirms the recorded PUT KEY at KID=0x10
// installed the CA's public key — not the leaf's.
//
// The check works by extracting the EC public point from the
// recorded PUT KEY APDU's TLV-encoded value (B0 wrapper, 65-byte
// uncompressed SEC1 point) and comparing X/Y with both keys.
func TestBootstrapOCE_InstallsCANotLeaf(t *testing.T) {
	caCert, caPriv, leafCert, leafPriv := mkOCEChain(t, "regression-ca", "regression-leaf")
	chainPath := writeChainPEM(t, caCert, leafCert)
	leafKeyPath := writePrivPEM(t, leafPriv)

	mc := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	_ = leafKeyPath
	if err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", chainPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}

	// Find the PUT KEY APDU at P2=0x10 (OCE KID).
	var putKey *scp03.RecordedAPDU
	for i := range mc.Recorded() {
		r := mc.Recorded()[i]
		if r.INS == 0xD8 && r.P2 == 0x10 {
			putKey = &r
			break
		}
	}
	if putKey == nil {
		t.Fatal("no PUT KEY (INS=0xD8, P2=0x10) was recorded")
	}

	point, err := extractECPointFromPutKey(putKey.Data)
	if err != nil {
		t.Fatalf("extract point from recorded PUT KEY: %v", err)
	}
	pubX, pubY := elliptic.Unmarshal(elliptic.P256(), point) //nolint:staticcheck // SEC1 uncompressed parse
	if pubX == nil {
		t.Fatal("recorded PUT KEY data does not parse as P-256 uncompressed point")
	}
	if pubX.Cmp(caPriv.PublicKey.X) == 0 && pubY.Cmp(caPriv.PublicKey.Y) == 0 {
		// installed CA — expected
	} else if pubX.Cmp(leafPriv.PublicKey.X) == 0 && pubY.Cmp(leafPriv.PublicKey.Y) == 0 {
		t.Fatal("REGRESSION: bootstrap-oce installed the LEAF public key at KID=0x10. " +
			"Per GP Amendment F §7.1.1, KID=0x10 is PK.CA-KLOC.ECDSA — install chain[0] (the CA), not chain[len-1] (the leaf).")
	} else {
		t.Fatal("recorded PUT KEY public point matches neither the CA nor the leaf — bug elsewhere")
	}

	// And STORE CA-IDENTIFIER (INS=0xE2) should also have been issued.
	var sawStoreData bool
	for _, r := range mc.Recorded() {
		if r.INS == 0xE2 {
			sawStoreData = true
			break
		}
	}
	if !sawStoreData {
		t.Error("expected STORE DATA (INS=0xE2) for STORE CA-IDENTIFIER; not seen in recorded APDUs")
	}

	// Output text must reflect the new wording.
	output := buf.String()
	for _, want := range []string{
		"install OCE CA public key",
		"register CA SKI",
		"computed from chain[0]",
		`CN="regression-ca"`,
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, output)
		}
	}
}

// extractECPointFromPutKey parses the data payload of a PUT KEY
// command for an EC public key (matches putKeyECPublicCmd in the
// securitydomain package): KVN || B0 LL <point> || F0 LL <curve> || 00.
// Returns the 65-byte uncompressed SEC1 point.
func extractECPointFromPutKey(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, &usageError{msg: "PUT KEY data too short"}
	}
	// data[0] = new KVN. data[1] = 0xB0 (EC public key tag).
	// data[2] = length (0x41 for 65-byte point).
	if data[1] != 0xB0 {
		return nil, &usageError{msg: "expected B0 tag in PUT KEY data, got " + string(data[1])}
	}
	pointLen := int(data[2])
	if 3+pointLen > len(data) {
		return nil, &usageError{msg: "B0 length exceeds buffer"}
	}
	return data[3 : 3+pointLen], nil
}

// mkOCEChain builds (caCert, caPriv, leafCert, leafPriv) where
// leafCert is signed by caPriv. Both keys are P-256.
func mkOCEChain(t *testing.T, caCN, leafCN string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca priv: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf priv: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	return caCert, caPriv, leafCert, leafPriv
}

// writeChainPEM writes a leaf-last chain PEM file and returns the path.
func writeChainPEM(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	path := filepath.Join(t.TempDir(), "chain.pem")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write chain: %v", err)
	}
	return path
}

// writePrivPEM writes a P-256 EC private key PEM file and returns the path.
func writePrivPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	path := filepath.Join(t.TempDir(), "priv.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	return path
}
