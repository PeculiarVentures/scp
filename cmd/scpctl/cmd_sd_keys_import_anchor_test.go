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

// --- fixture helpers (anchor-specific) ---

// writeCertWithSKI builds a self-signed cert that DOES include an
// explicit SubjectKeyIdentifier extension. Tests the
// "cert-extension" SKI origin path.
func writeCertWithSKI(t *testing.T, dir string, priv *ecdsa.PrivateKey, ski []byte, name string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, name+".crt.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

// writeCertNoSKI builds a self-signed cert WITHOUT a
// SubjectKeyIdentifier extension. Tests the "computed-sha1-spki"
// fallback origin path.
func writeCertNoSKI(t *testing.T, dir string, priv *ecdsa.PrivateKey, name string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// No SubjectKeyId — exercise the SHA-1(SPKI) fallback.
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, name+".crt.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

// writePubKeyPEM serializes a bare public key as PKIX PEM
// (PUBLIC KEY block). Tests the bare-pubkey path that requires
// --ski explicitly.
func writePubKeyPEM(t *testing.T, dir string, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return path
}

// --- dispatch ---

// TestSDKeysImportTrustAnchor_DispatchedFromMain pins that 0x10 and
// the 0x20–0x2F range reach the real trust-anchor handler.
func TestSDKeysImportTrustAnchor_DispatchedFromMain(t *testing.T) {
	for _, kid := range []string{"10", "20", "2F"} {
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
				t.Errorf("error should mention --key-pem (proves trust-anchor handler was reached); got %v", err)
			}
			if strings.Contains(err.Error(), "Phase 5c") {
				t.Errorf("dispatch hit the Phase-5c stub instead of the real handler: %v", err)
			}
		})
	}
}

// --- input parsing + SKI derivation ---

// TestSDKeysImportTrustAnchor_RejectsCertsFlag pins the design rule
// that --certs is a usage error for trust-anchor imports. Trust
// anchors don't get chains stored on the card; the error must
// explain WHY (and point at the right destination if the operator
// confused trust-anchor with SCP11 SD).
func TestSDKeysImportTrustAnchor_RejectsCertsFlag(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeCertNoSKI(t, dir, priv, "anchor")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
		"--certs", keyPath, // even pointing at the same file: still rejected
	})
	if err == nil {
		t.Fatal("expected usageError for --certs on trust anchor; got nil")
	}
	if !strings.Contains(err.Error(), "--certs is rejected") {
		t.Errorf("error should explain --certs rejection; got %v", err)
	}
	// Must redirect operator to the correct alternative.
	if !strings.Contains(err.Error(), "11/13/15") {
		t.Errorf("error should redirect to SCP11 SD KIDs for chain imports; got %v", err)
	}
}

// TestSDKeysImportTrustAnchor_CertWithSKI_ExtensionPath: when the
// cert carries a SubjectKeyIdentifier extension, that value is used
// and the origin is "cert-extension".
func TestSDKeysImportTrustAnchor_CertWithSKI_ExtensionPath(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	skiBytes := []byte{0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11}
	keyPath := writeCertWithSKI(t, dir, priv, skiBytes, "anchor-with-ski")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
		"--json",
	})
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.SKIOrigin != "cert-extension" {
		t.Errorf("ski_origin = %q, want cert-extension", report.Data.SKIOrigin)
	}
	if report.Data.SKIHex != "ABCDEF0102030405060708090A0B0C0D0E0F1011" {
		t.Errorf("ski_hex = %q, want extension bytes verbatim", report.Data.SKIHex)
	}
}

// TestSDKeysImportTrustAnchor_CertNoSKI_FallbackPath: when the cert
// lacks the extension, the SKI is computed as SHA-1 of the SPKI per
// RFC 5280 §4.2.1.2 method 1. Origin is "computed-sha1-spki".
func TestSDKeysImportTrustAnchor_CertNoSKI_FallbackPath(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeCertNoSKI(t, dir, priv, "anchor-no-ski")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
		"--json",
	})
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.SKIOrigin != "computed-sha1-spki" {
		t.Errorf("ski_origin = %q, want computed-sha1-spki", report.Data.SKIOrigin)
	}
	// SHA-1 hex is 40 chars (20 bytes). Just sanity-check length.
	if len(report.Data.SKIHex) != 40 {
		t.Errorf("ski_hex length = %d, want 40 (SHA-1 hex)", len(report.Data.SKIHex))
	}
}

// TestSDKeysImportTrustAnchor_ExplicitSKIOverride: --ski wins over
// the cert's extension value. Origin is "explicit-override".
func TestSDKeysImportTrustAnchor_ExplicitSKIOverride(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	certEmbedded := []byte{0xAA, 0xBB, 0xCC}
	keyPath := writeCertWithSKI(t, dir, priv, certEmbedded, "anchor-override")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
		"--ski", "11:22:33", // colons accepted
		"--json",
	})
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.SKIOrigin != "explicit-override" {
		t.Errorf("ski_origin = %q, want explicit-override", report.Data.SKIOrigin)
	}
	if report.Data.SKIHex != "112233" {
		t.Errorf("ski_hex = %q, want 112233 (override wins, colons stripped)",
			report.Data.SKIHex)
	}
}

// TestSDKeysImportTrustAnchor_BarePubKey_RequiresSKI: when --key-pem
// is a PUBLIC KEY block (no cert wrapper), --ski is mandatory because
// auto-derivation needs the cert.
func TestSDKeysImportTrustAnchor_BarePubKey_RequiresSKI(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writePubKeyPEM(t, dir, &priv.PublicKey)

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
	})
	if err == nil {
		t.Fatal("expected usageError for bare PUBLIC KEY without --ski; got nil")
	}
	if !strings.Contains(err.Error(), "--ski is required") {
		t.Errorf("error should explain that --ski is required; got %v", err)
	}
}

// TestSDKeysImportTrustAnchor_BarePubKey_WithSKI: bare PUBLIC KEY
// + explicit --ski reaches dry-run cleanly with explicit-override
// origin.
func TestSDKeysImportTrustAnchor_BarePubKey_WithSKI(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writePubKeyPEM(t, dir, &priv.PublicKey)

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
		"--ski", "DEADBEEF",
		"--json",
	})
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	var report struct {
		Data sdKeysImportData `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if report.Data.SKIOrigin != "explicit-override" {
		t.Errorf("ski_origin = %q, want explicit-override", report.Data.SKIOrigin)
	}
	if report.Data.SKIHex != "DEADBEEF" {
		t.Errorf("ski_hex = %q, want DEADBEEF", report.Data.SKIHex)
	}
}

// TestSDKeysImportTrustAnchor_RejectsPrivateKey: a PRIVATE KEY block
// is a usage error — trust anchors take public keys only. The error
// must redirect the operator to SCP11 SD if they meant that instead.
func TestSDKeysImportTrustAnchor_RejectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeKeyPEM(t, dir, priv) // PRIVATE KEY block

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
	})
	if err == nil {
		t.Fatal("expected usageError for PRIVATE KEY block; got nil")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error should explain private/public-key category mismatch; got %v", err)
	}
	// Helpful redirect.
	if !strings.Contains(err.Error(), "11/13/15") {
		t.Errorf("error should suggest the SCP11 SD path for private keys; got %v", err)
	}
}

// TestSDKeysImportTrustAnchor_RejectsNonP256: a P-384 cert (or any
// non-P-256 curve) is rejected host-side.
func TestSDKeysImportTrustAnchor_RejectsNonP256(t *testing.T) {
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("P-384 GenerateKey: %v", err)
	}
	keyPath := writeCertNoSKI(t, dir, priv, "p384-anchor")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
	})
	if err == nil {
		t.Fatal("expected usageError for P-384 anchor; got nil")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should require P-256; got %v", err)
	}
}

// TestSDKeysImportTrustAnchor_DryRunByDefault confirms the safety
// invariant + JSON shape for the trust-anchor path.
func TestSDKeysImportTrustAnchor_DryRunByDefault(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeCertNoSKI(t, dir, priv, "anchor")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
		"--key-pem", keyPath,
	}); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"sd keys import",
		"dry-run",
		"--confirm-write",
		"PUT KEY (P-256 public, trust anchor)",
		"STORE CA-ISSUER SKI",
		"kid=0x10",
		"kvn=0x01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "open SCP03 session") {
		t.Errorf("dry-run output should not include SCP03 open; got:\n%s", out)
	}
}

// TestSDKeysImportTrustAnchor_ConfirmWrite_AuthFails: active path
// fails at SCP03 open; PUT KEY and STORE CA-ISSUER must NOT appear
// as PASS.
func TestSDKeysImportTrustAnchor_ConfirmWrite_AuthFails(t *testing.T) {
	dir := t.TempDir()
	priv := genP256TestKey(t)
	keyPath := writeCertNoSKI(t, dir, priv, "anchor")

	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysImportTrustAnchor(context.Background(), env, []string{
		"--reader", "fake", "--kid", "10", "--kvn", "01",
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
		if strings.Contains(line, "PUT KEY P-256 public") && strings.Contains(line, "PASS") {
			t.Errorf("PUT KEY recorded as PASS despite SCP03 open failure: %q", line)
		}
		if strings.Contains(line, "STORE CA-ISSUER SKI") && strings.Contains(line, "PASS") {
			t.Errorf("STORE CA-ISSUER recorded as PASS despite SCP03 open failure: %q", line)
		}
	}
}

// TestParseSKIHex pins the SKI input grammar.
func TestParseSKIHex(t *testing.T) {
	cases := []struct {
		in      string
		want    string // hex of expected result
		wantErr bool
	}{
		{"ABCDEF", "ABCDEF", false},
		{"abcdef", "ABCDEF", false},
		{"AB:CD:EF", "ABCDEF", false},
		{"AB CD EF", "ABCDEF", false},
		{"", "", true},
		{"::", "", true}, // collapses to empty
		{"GG", "", true},
		{"A", "", true}, // odd length
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSKIHex(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseSKIHex(%q) err = %v, wantErr = %v",
					tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && hexEncode(got) != tc.want {
				t.Errorf("parseSKIHex(%q) = %s, want %s",
					tc.in, hexEncode(got), tc.want)
			}
		})
	}
}

// TestIsCATrustAnchorKID pins the KID classifier.
func TestIsCATrustAnchorKID(t *testing.T) {
	cases := []struct {
		kid  byte
		want bool
	}{
		{0x01, false}, // scp03
		{0x10, true},  // OCE
		{0x11, false}, // SCP11a
		{0x13, false},
		{0x15, false},
		{0x1F, false}, // gap
		{0x20, true},  // KLCC range start
		{0x25, true},
		{0x2F, true}, // KLCC range end
		{0x30, false},
		{0xFF, false},
	}
	for _, tc := range cases {
		if got := isCATrustAnchorKID(tc.kid); got != tc.want {
			t.Errorf("isCATrustAnchorKID(0x%02X) = %v, want %v", tc.kid, got, tc.want)
		}
	}
}
