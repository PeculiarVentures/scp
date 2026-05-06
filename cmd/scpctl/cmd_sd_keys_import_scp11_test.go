package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/mockcard"
)

// --- fixture helpers ---

// genP256TestKey produces a fresh P-256 private key for fixtures.
// Each call is independent; tests that need a matching pair (key
// plus leaf cert) use writeTestKeyAndChain so the cert's SPKI
// matches the returned key.
func genP256TestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return priv
}

// writeKeyPEM serializes priv as PKCS#8 PEM (modern openssl genpkey
// default) and returns the file path. SEC1 ('EC PRIVATE KEY') is
// also accepted by the importer; testing both forms is in
// TestSDKeysImportSCP11SD_AcceptsBothPEMForms.
func writeKeyPEM(t *testing.T, dir string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	path := filepath.Join(dir, "key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key pem: %v", err)
	}
	return path
}

// writeKeyPEMSEC1 serializes priv as SEC1 ('EC PRIVATE KEY') for
// the form-compatibility test.
func writeKeyPEMSEC1(t *testing.T, dir string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	path := filepath.Join(dir, "key.sec1.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key pem (sec1): %v", err)
	}
	return path
}

// writeSelfSignedCert produces a self-signed X.509 leaf cert whose
// SubjectPublicKeyInfo matches priv. Returned file path contains a
// single CERTIFICATE PEM block.
func writeSelfSignedCert(t *testing.T, dir string, priv *ecdsa.PrivateKey, name string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, name+".crt.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write cert pem: %v", err)
	}
	return path
}

// --- dispatch + SCP11 SD slot validation ---

// TestSDKeysImportSCP11SD_DispatchedFromMain pins that KIDs 0x11 /
// 0x13 / 0x15 reach the SCP11 SD handler (not the not-yet-implemented
// stub). The handler then fails on missing --key-pem; that's the
// signal that the dispatch landed correctly.
func TestSDKeysImportSCP11SD_DispatchedFromMain(t *testing.T) {
	for _, kid := range []string{"11", "13", "15"} {
		t.Run("kid="+kid, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDKeysImport(context.Background(), env,
				[]string{"--reader", "fake", "--kid", kid, "--kvn", "01"})
			if err == nil {
				t.Fatalf("expected usageError (missing --key-pem); got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
			if !strings.Contains(err.Error(), "--key-pem") {
				t.Errorf("error should mention --key-pem (proves SCP11 SD handler was reached); got %v", err)
			}
			// And the message must NOT mention Phase 5b — that would
			// mean we hit the not-yet-implemented stub instead.
			if strings.Contains(err.Error(), "Phase 5b") {
				t.Errorf("dispatch hit the Phase-5b stub instead of the real handler: %v", err)
			}
		})
	}
}

// --- file parsing + validation ---

// TestSDKeysImportSCP11SD_RequiresKeyPEM verifies that --key-pem is
// mandatory and that the error message names the flag.
func TestSDKeysImportSCP11SD_RequiresKeyPEM(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportSCP11SD(context.Background(), env,
		[]string{"--reader", "fake", "--kid", "11", "--kvn", "01"})
	if err == nil {
		t.Fatal("expected usageError; got nil")
	}
	if !strings.Contains(err.Error(), "--key-pem") {
		t.Errorf("error should name --key-pem; got %v", err)
	}
}

// TestSDKeysImportSCP11SD_RejectsNonP256 pins the curve guard. SCP11
// requires P-256; passing a P-384 key (or any other curve) is a
// host-side usage error before any APDU goes out.
func TestSDKeysImportSCP11SD_RejectsNonP256(t *testing.T) {
	dir := t.TempDir()
	// Generate a P-384 key and write it.
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("P-384 GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	keyPath := filepath.Join(dir, "p384.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01", "--key-pem", keyPath,
	})
	if err == nil {
		t.Fatal("expected usageError for P-384 key; got nil")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should explain P-256 requirement; got %v", err)
	}
}

// TestSDKeysImportSCP11SD_AcceptsBothPEMForms verifies that both
// PKCS#8 and SEC1 PEM wrappings are accepted (modern openssl uses
// PKCS#8, older tooling and Yubico fixtures use SEC1). Reaching
// dry-run successfully proves the parse worked.
func TestSDKeysImportSCP11SD_AcceptsBothPEMForms(t *testing.T) {
	priv := genP256TestKey(t)
	dir := t.TempDir()

	cases := []struct {
		name string
		path string
	}{
		{"pkcs8", writeKeyPEM(t, dir, priv)},
		{"sec1", writeKeyPEMSEC1(t, dir, priv)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDKeysImportSCP11SD(context.Background(), env, []string{
				"--reader", "fake", "--kid", "11", "--kvn", "01",
				"--key-pem", tc.path,
			})
			if err != nil {
				t.Fatalf("dry-run for %s: %v", tc.name, err)
			}
		})
	}
}

// TestSDKeysImportSCP11SD_LeafMismatchRejected pins the anti-typo
// guard: when --certs is supplied, the leaf cert's public key must
// match the imported private key. A wrong pairing must be rejected
// before any APDU.
func TestSDKeysImportSCP11SD_LeafMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	keyA := genP256TestKey(t)
	keyB := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, keyA)
	// Cert signed by keyB but bound to keyB's public key, so the
	// leaf does NOT match keyA.
	certPath := writeSelfSignedCert(t, dir, keyB, "wrong-pair")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--key-pem", keyPath, "--certs", certPath,
	})
	if err == nil {
		t.Fatal("expected usageError for mismatched key/cert; got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should explain the mismatch; got %v", err)
	}
}

// TestSDKeysImportSCP11SD_LeafMatchAccepted dual-tests the guard:
// a matching leaf reaches dry-run cleanly.
func TestSDKeysImportSCP11SD_LeafMatchAccepted(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv)
	certPath := writeSelfSignedCert(t, dir, priv, "matching-pair")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--key-pem", keyPath, "--certs", certPath,
	})
	if err != nil {
		t.Fatalf("dry-run with matching pair: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"PUT KEY (SCP11 P-256 private)",
		"STORE DATA cert chain",
		"1 cert ready",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
}

// --- dry-run + JSON shape ---

// TestSDKeysImportSCP11SD_DryRunByDefault confirms the safety
// invariant for the SCP11 SD path: without --confirm-write,
// validates inputs, parses files, reports the planned action without
// opening SCP03 or transmitting any APDU.
//
// Critically: the imported private key bytes must NEVER appear in
// output. The test re-reads the key file's PEM, extracts a
// distinctive substring of the encoded bytes, and asserts that
// substring is absent from the report.
func TestSDKeysImportSCP11SD_DryRunByDefault(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv)

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	// Pick the middle 32 bytes of the PEM file as a distinctive
	// "private material" substring. Avoids false positives from
	// PEM headers/footers which appear in any PEM file.
	mid := len(keyPEM) / 2
	privSnippet := string(keyPEM[mid : mid+32])

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--key-pem", keyPath,
	}); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd keys import",
		"dry-run",
		"--confirm-write",
		"PUT KEY (SCP11 P-256 private)",
		"kid=0x11",
		"kvn=0x01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, privSnippet) {
		t.Errorf("dry-run output contains private-key bytes (snippet %q):\n%s", privSnippet, out)
	}
	// No SCP03 should have been opened.
	if strings.Contains(out, "open SCP03 session") {
		t.Errorf("dry-run output should not include SCP03 open; got:\n%s", out)
	}
}

// TestSDKeysImportSCP11SD_DryRunReplaceKVNWording: --replace-kvn
// flips dry-run text to flag the destructive shape, mirroring
// generate and import-SCP03.
func TestSDKeysImportSCP11SD_DryRunReplaceKVNWording(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv)

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--replace-kvn", "FF",
		"--key-pem", keyPath,
	}); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "REPLACING") {
		t.Errorf("--replace-kvn dry-run must flag destructive shape; got:\n%s", buf.String())
	}
}

// TestSDKeysImportSCP11SD_DryRunJSONShape pins the schema. Cert
// count is recorded; SPKI fingerprint stays empty in dry-run.
func TestSDKeysImportSCP11SD_DryRunJSONShape(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv)
	certPath := writeSelfSignedCert(t, dir, priv, "test")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--key-pem", keyPath, "--certs", certPath,
		"--json",
	}); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.Channel != "dry-run" {
		t.Errorf("channel = %q, want dry-run", report.Data.Channel)
	}
	if report.Data.Category != "scp11-sd-key" {
		t.Errorf("category = %q, want scp11-sd-key", report.Data.Category)
	}
	if report.Data.KIDHex != "0x11" {
		t.Errorf("kid_hex = %q, want 0x11", report.Data.KIDHex)
	}
	if report.Data.CertCount != 1 {
		t.Errorf("cert_count = %d, want 1", report.Data.CertCount)
	}
	if report.Data.SPKIFingerprintSHA256 != "" {
		t.Errorf("dry-run must not record an SPKI fingerprint; got %q",
			report.Data.SPKIFingerprintSHA256)
	}
}

// --- active path + safety guards ---

// TestSDKeysImportSCP11SD_ConfirmWrite_AuthFails: active path against
// the SCP03-unaware mock fails at 'open SCP03 session'. PUT KEY must
// NOT appear as PASS, AND private-key bytes must not appear in any
// failure output (the safety contract for asymmetric key imports).
func TestSDKeysImportSCP11SD_ConfirmWrite_AuthFails(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv)

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	mid := len(keyPEM) / 2
	privSnippet := string(keyPEM[mid : mid+32])

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportSCP11SD(context.Background(), env, []string{
		"--reader", "fake", "--kid", "11", "--kvn", "01",
		"--key-pem", keyPath,
		"--confirm-write",
	})
	if err == nil {
		t.Fatalf("expected SCP03 open failure; got success:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "open SCP03 session") {
		t.Errorf("expected 'open SCP03 session' check; got:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL; got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "PUT KEY SCP11") && strings.Contains(line, "PASS") {
			t.Errorf("PUT KEY recorded as PASS despite SCP03 open failure: %q", line)
		}
	}
	if strings.Contains(out, privSnippet) {
		t.Errorf("output leaked private-key bytes on failure path:\n%s", out)
	}
}

// --- helpers ---

// TestVerifyLeafMatchesPrivateKey directly exercises the SPKI
// comparison guard.
func TestVerifyLeafMatchesPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyA := genP256TestKey(t)
	keyB := genP256TestKey(t)
	leafA := mustParseCert(t, writeSelfSignedCert(t, dir, keyA, "a"))
	leafB := mustParseCert(t, writeSelfSignedCert(t, dir, keyB, "b"))

	if err := verifyLeafMatchesPrivateKey(keyA, leafA); err != nil {
		t.Errorf("matching pair (keyA, leafA) reported mismatch: %v", err)
	}
	if err := verifyLeafMatchesPrivateKey(keyA, leafB); err == nil {
		t.Errorf("mismatched pair (keyA, leafB) should have errored")
	}
}

// mustParseCert reads a PEM file and returns the first CERTIFICATE
// block parsed.
func mustParseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}
