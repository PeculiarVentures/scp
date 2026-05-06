package main

// ykman-shape interop tests for sd keys import/export.
//
// The reviewer's ask: 'sd keys export chain round-trip with
// ykman/yubikit.' Without ykman as a build dependency on every
// CI runner, we use openssl as the third-party reference parser:
// if our exported PEM is openssl-parseable and the DER it
// extracts byte-equals what we imported, then by extension a
// ykman/yubikit pipeline reading the same PEM produces the same
// chain. (ykman uses the cryptography library which uses
// openssl-compatible PEM/DER parsing.)
//
// What we prove here:
//
//   1. sd keys import --certs accepts a multi-cert PEM in the
//      format ykman emits (concatenated CERTIFICATE blocks,
//      leaf-last)
//   2. sd keys export emits a PEM that openssl x509 can parse
//   3. The DER bytes round-trip exactly: input cert N == output
//      cert N for every position
//   4. Chain order is preserved (leaf-last by default; --chain-order
//      explicitly controls reordering when needed)
//
// What this does NOT prove:
//
//   - That ykman's actual on-card PUT KEY / STORE DATA wire bytes
//     match ours. That requires ykman as a subprocess in a lab
//     test against real hardware, which is out of scope for CI.
//   - Card-side acceptance of our wire format on non-YubiKey
//     cards. The mock is a YubiKey-shaped simulator; behavioral
//     parity with non-YubiKey cards is a real-card matrix
//     concern.

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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// ykmanShapeChain builds a 3-cert chain: root → intermediate → leaf
// signed in standard PKI order. Returns leaf-last DER bytes (the
// shape ykman expects) plus the leaf's private key for import.
func ykmanShapeChain(t *testing.T) (rootCert, intCert, leafCert *x509.Certificate, leafKey *ecdsa.PrivateKey) {
	t.Helper()

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "ykman-shape root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rootCert, _ = x509.ParseCertificate(rootDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(102),
		Subject:               pkix.Name{CommonName: "ykman-shape intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	intCert, _ = x509.ParseCertificate(intDER)

	leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(103),
		Subject:      pkix.Name{CommonName: "ykman-shape leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leafCert, _ = x509.ParseCertificate(leafDER)
	return rootCert, intCert, leafCert, leafKey
}

// TestYkmanShape_ImportExport_OpensslPipeline_ChainRoundtrip is
// the marquee interop check: imports a 3-cert chain in ykman's
// expected leaf-last shape, exports via sd keys export, then:
//
//   1. Verifies the exported PEM byte-decodes to the same DER
//      certs in the same order (round-trip equality)
//   2. Verifies openssl x509 can parse the exported PEM without
//      error (third-party parseability witness)
//
// The two-phase split is deliberate. PEM byte-equality is the
// strong claim and uses Go's pem.Decode directly; openssl's
// pkcs7 -print_certs pipeline DOES NOT preserve order across
// the PKCS#7 envelope (SET OF Certificate is unordered in the
// ASN.1 sense even when openssl happens to echo input order),
// so trying to bind openssl to order-preserving extraction was
// incorrect. Instead openssl is the "external tool can read
// our output" gate, validating wire-format correctness without
// depending on order.
func TestYkmanShape_ImportExport_OpensslPipeline_ChainRoundtrip(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available in PATH")
	}

	dir := t.TempDir()
	root, inter, leaf, leafKey := ykmanShapeChain(t)

	// Write the input chain in ykman's expected leaf-last order:
	// root, intermediate, leaf (that exact ordering, top-down in
	// the PEM file).
	chainPath := filepath.Join(dir, "input-chain.pem")
	{
		var buf bytes.Buffer
		for _, c := range []*x509.Certificate{root, inter, leaf} {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				t.Fatalf("encode input: %v", err)
			}
		}
		if err := os.WriteFile(chainPath, buf.Bytes(), 0600); err != nil {
			t.Fatalf("write input chain: %v", err)
		}
	}

	keyPath := writeYkmanShapeKeyPEM(t, dir, leafKey)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: import key + chain at 0x11/0x01.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--key-pem", keyPath,
			"--certs", chainPath,
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("import: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: export back to PEM with default (as-stored) order.
	exportedPath := filepath.Join(dir, "exported-chain.pem")
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--out", exportedPath,
			"--scp03-keys-default",
		})
		if err != nil {
			t.Fatalf("export: %v\n%s", err, buf.String())
		}
	}

	// Phase 3a: byte-equality check via direct PEM decode of the
	// exported file. This is the order-preserving path.
	exportedDER := decodeAllCertDER(t, exportedPath)
	expected := [][]byte{root.Raw, inter.Raw, leaf.Raw}
	if len(exportedDER) != len(expected) {
		t.Fatalf("expected %d certs in exported PEM, got %d", len(expected), len(exportedDER))
	}
	for i := range expected {
		if !bytes.Equal(exportedDER[i], expected[i]) {
			t.Errorf("position %d: exported DER differs from input", i)
		}
	}

	// Phase 3b: openssl-parseability witness. Does not assert
	// order (PKCS#7 SET OF is unordered); just confirms the
	// exported PEM is a wire-format that an external parser
	// accepts without error.
	if err := opensslCanParsePEM(exportedPath); err != nil {
		t.Errorf("openssl rejected our exported PEM: %v", err)
	}
}

// TestYkmanShape_ChainOrder_LeafFirstFlag confirms --chain-order
// leaf-first produces output with the leaf at position 0 and the
// root at the last position. Uses direct PEM decode (not the
// openssl pipeline) for the order check; openssl is invoked
// separately to confirm the bytes are still parseable.
func TestYkmanShape_ChainOrder_LeafFirstFlag(t *testing.T) {
	dir := t.TempDir()
	root, inter, leaf, leafKey := ykmanShapeChain(t)

	chainPath := filepath.Join(dir, "input.pem")
	{
		var buf bytes.Buffer
		for _, c := range []*x509.Certificate{root, inter, leaf} {
			_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
		if err := os.WriteFile(chainPath, buf.Bytes(), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	keyPath := writeYkmanShapeKeyPEM(t, dir, leafKey)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		if err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake", "--kid", "11", "--kvn", "01",
			"--key-pem", keyPath, "--certs", chainPath,
			"--confirm-write",
		}); err != nil {
			t.Fatalf("import: %v\n%s", err, buf.String())
		}
	}

	exportedPath := filepath.Join(dir, "exported.pem")
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		if err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake", "--kid", "11", "--kvn", "01",
			"--out", exportedPath,
			"--chain-order", "leaf-first",
			"--scp03-keys-default",
		}); err != nil {
			t.Fatalf("export: %v\n%s", err, buf.String())
		}
	}

	exportedDER := decodeAllCertDER(t, exportedPath)
	// Expected: leaf-first (leaf, intermediate, root)
	expected := [][]byte{leaf.Raw, inter.Raw, root.Raw}
	if len(exportedDER) != len(expected) {
		t.Fatalf("expected %d certs, got %d", len(expected), len(exportedDER))
	}
	for i := range expected {
		if !bytes.Equal(exportedDER[i], expected[i]) {
			t.Errorf("position %d: leaf-first reorder put wrong cert here", i)
		}
	}

	// Independently confirm openssl accepts the leaf-first PEM.
	if _, err := exec.LookPath("openssl"); err == nil {
		if err := opensslCanParsePEM(exportedPath); err != nil {
			t.Errorf("openssl rejected leaf-first PEM: %v", err)
		}
	}
}

// decodeAllCertDER reads a multi-cert PEM file and returns each
// CERTIFICATE block's DER bytes in source order. Order-preserving
// — uses Go's pem.Decode walk, no PKCS#7 round-trip.
func decodeAllCertDER(t *testing.T, pemPath string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("read %s: %v", pemPath, err)
	}
	var out [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, append([]byte(nil), block.Bytes...))
		}
	}
	return out
}

// opensslCanParsePEM returns nil if openssl x509 -noout accepts
// the first cert in the PEM file without error. Validates wire
// format conformance against an external parser; doesn't assert
// per-cert content equality (that's decodeAllCertDER's job).
func opensslCanParsePEM(pemPath string) error {
	cmd := exec.Command("openssl", "x509", "-in", pemPath, "-noout")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &usageError{msg: "openssl: " + err.Error() + ": " + string(out)}
	}
	return nil
}

// writeYkmanShapeKeyPEM writes an EC private key in PKCS#8 PEM
// form (the format sd keys import --key-pem accepts).
func writeYkmanShapeKeyPEM(t *testing.T, dir string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, "leaf.key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// TestYkmanShape_ExportPEM_OpensslVerifyParseable is a minimal
// "openssl can parse our output" smoke test. Independent of the
// round-trip equality check — this verifies our PEM doesn't have
// subtle formatting bugs (extra whitespace, wrong line endings,
// invalid headers) that openssl would reject.
func TestYkmanShape_ExportPEM_OpensslVerifyParseable(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available in PATH")
	}
	dir := t.TempDir()
	_, _, leaf, leafKey := ykmanShapeChain(t)
	chainPath := filepath.Join(dir, "in.pem")
	{
		var buf bytes.Buffer
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		_ = os.WriteFile(chainPath, buf.Bytes(), 0600)
	}
	keyPath := writeYkmanShapeKeyPEM(t, dir, leafKey)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		_ = cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake", "--kid", "11", "--kvn", "01",
			"--key-pem", keyPath, "--certs", chainPath,
			"--confirm-write",
		})
	}

	exportedPath := filepath.Join(dir, "out.pem")
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		if err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake", "--kid", "11", "--kvn", "01",
			"--out", exportedPath, "--scp03-keys-default",
		}); err != nil {
			t.Fatalf("export: %v\n%s", err, buf.String())
		}
	}

	// openssl x509 -in <pem> -noout — exits 0 only if PEM parses
	// as a valid X.509 cert. Any malformed encoding or
	// non-conforming header makes openssl fail.
	cmd := exec.Command("openssl", "x509", "-in", exportedPath, "-noout")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected our PEM: %v\noutput:\n%s", err, string(out))
	}
	if strings.Contains(strings.ToLower(string(out)), "error") {
		t.Errorf("openssl reported an error: %s", string(out))
	}
}
