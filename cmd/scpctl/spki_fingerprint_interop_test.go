package main

// Cross-tool interop tests for the SPKI fingerprint format the
// sd-keys-cli verbs emit. The fingerprint is the projection that
// shows up in `sd keys list --json`, `sd keys export --json`,
// `sd keys generate --json`, and `sd keys import --json`. Operators
// compare these fingerprints against what openssl, Chrome's cert
// viewer, and Yubico's tools report — so the format MUST match.
//
// The format we commit to: hex SHA-256 over the DER-encoded
// SubjectPublicKeyInfo, uppercase, no separators. Same shape Chrome
// labels "Public Key SHA-256" in its cert viewer; same shape openssl
// produces from `openssl x509 -in cert -pubkey -noout |
// openssl pkey -pubin -outform der | sha256sum`.
//
// These tests cover both fingerprint helpers in scpctl:
//
//   - spkiFingerprint(*x509.Certificate) — used by sd keys list /
//     export, computes from cert.RawSubjectPublicKeyInfo
//   - publicKeySPKIFingerprint(*ecdsa.PublicKey) — used by sd keys
//     generate / import (SCP11 SD + trust anchor), computes from
//     x509.MarshalPKIXPublicKey(pub)
//
// Both must produce identical fingerprints for the same logical
// public key so JSON consumers comparing across verbs see the same
// identifier.
//
// openssl is required for this test; it skips if openssl is absent.
// On every developer machine and CI runner we care about, openssl
// is available.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireOpenssl skips the test if openssl is not on PATH. We don't
// want CI environments without openssl to fail; they just lose this
// one cross-tool measurement.
func requireOpenssl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH; cross-tool fingerprint comparison cannot be verified")
	}
}

// fingerprintViaOpenssl drives the same canonical chain Chrome's
// cert viewer and Yubico's tools use:
//
//	openssl x509 -in cert.pem -pubkey -noout
//	  | openssl pkey -pubin -outform der
//	  | sha256sum
//
// Combined into one openssl invocation pipeline driven from Go.
// Returns the uppercase hex SHA-256 of the SPKI DER, matching the
// spkiFingerprint helper's output format.
func fingerprintViaOpenssl(t *testing.T, certPath string) string {
	t.Helper()

	// Step 1: extract SPKI PEM from the certificate.
	cmd1 := exec.Command("openssl", "x509", "-in", certPath, "-pubkey", "-noout")
	pemPub, err := cmd1.Output()
	if err != nil {
		t.Fatalf("openssl x509 -pubkey: %v\nstderr: %s", err, cmdStderr(err))
	}

	// Step 2: convert PEM SPKI to DER. Pipe pemPub into openssl pkey.
	cmd2 := exec.Command("openssl", "pkey", "-pubin", "-outform", "der")
	cmd2.Stdin = bytes.NewReader(pemPub)
	derPub, err := cmd2.Output()
	if err != nil {
		t.Fatalf("openssl pkey -pubin -outform der: %v\nstderr: %s", err, cmdStderr(err))
	}

	// Step 3: sha256 the DER. Compute in-process rather than
	// pipelining sha256sum, so we don't depend on coreutils.
	sum := sha256.Sum256(derPub)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// cmdStderr extracts stderr from an exec.Error if present, for
// clearer test failure messages.
func cmdStderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return string(ee.Stderr)
	}
	return ""
}

// TestSPKIFingerprint_MatchesOpenssl_FromCertificate verifies that
// our spkiFingerprint helper produces the same digest openssl
// produces when both operate on the same certificate. This is the
// path sd keys list / export use.
func TestSPKIFingerprint_MatchesOpenssl_FromCertificate(t *testing.T) {
	requireOpenssl(t)
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spki-fingerprint-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	ours := spkiFingerprint(parsed)
	theirs := fingerprintViaOpenssl(t, certPath)

	if ours != theirs {
		t.Errorf("fingerprint mismatch:\n  scpctl spkiFingerprint(): %s\n  openssl x509-pubkey-sha256: %s",
			ours, theirs)
	}
	if !looksLikeSHA256Hex(ours) {
		t.Errorf("scpctl fingerprint not in expected uppercase-hex SHA-256 form: %q", ours)
	}
}

// TestSPKIFingerprint_MatchesOpenssl_FromPublicKey verifies the
// same property for the publicKeySPKIFingerprint helper, which
// works directly from an *ecdsa.PublicKey (no cert wrapper).
// This is the path sd keys generate / import (SCP11 SD + trust
// anchor) use.
func TestSPKIFingerprint_MatchesOpenssl_FromPublicKey(t *testing.T) {
	requireOpenssl(t)
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Build a cert just so we have a file path for openssl. The
	// fingerprint we compare comes from the public key alone via
	// publicKeySPKIFingerprint, NOT cert.RawSubjectPublicKeyInfo.
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spki-fingerprint-test-pk"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	ours, err := publicKeySPKIFingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeySPKIFingerprint: %v", err)
	}
	theirs := fingerprintViaOpenssl(t, certPath)

	if ours != theirs {
		t.Errorf("fingerprint mismatch:\n  scpctl publicKeySPKIFingerprint(): %s\n  openssl x509-pubkey-sha256:        %s",
			ours, theirs)
	}
}

// TestSPKIFingerprint_Helpers_Agree verifies the two helpers
// produce identical fingerprints for the same logical key. This
// matters because JSON consumers compare fingerprints across the
// list/export verbs (which use spkiFingerprint) and the
// generate/import verbs (which use publicKeySPKIFingerprint) —
// any divergence in the format would fragment the cross-verb
// identity contract.
func TestSPKIFingerprint_Helpers_Agree(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agree-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	fromCert := spkiFingerprint(parsed)
	fromKey, err := publicKeySPKIFingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeySPKIFingerprint: %v", err)
	}
	if fromCert != fromKey {
		t.Errorf("fingerprint helpers disagree on the same key:\n"+
			"  spkiFingerprint(cert):           %s\n"+
			"  publicKeySPKIFingerprint(pk):    %s\n"+
			"They MUST agree because sd keys list/export and sd keys generate/import "+
			"both write into the same JSON field (spki_fingerprint_sha256) and operators "+
			"compare across verbs.", fromCert, fromKey)
	}
}

// TestSPKIFingerprint_Format pins the surface contract: uppercase
// hex, exactly 64 characters (256 bits / 4 bits per char), no
// separators. JSON consumers of sd keys * commands rely on this
// shape for direct string comparison.
func TestSPKIFingerprint_Format(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fp, err := publicKeySPKIFingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeySPKIFingerprint: %v", err)
	}
	if !looksLikeSHA256Hex(fp) {
		t.Errorf("fingerprint %q does not match expected format (64 uppercase hex chars, no separators)", fp)
	}
}

// looksLikeSHA256Hex reports whether s is exactly 64 characters of
// uppercase hex (the format produced by hexEncode on a 32-byte
// digest).
func looksLikeSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// TestSPKIFingerprint_AppearsInGenerateOutput confirms that the
// sd keys generate verb emits this fingerprint shape via its JSON
// output. Drives the verb against the SCP03 mock with --json and
// parses the data block. Pins the JSON contract: a `data` block
// with a `spki_fingerprint_sha256` field carrying the right format.
//
// Combined with TestSPKIFingerprint_Helpers_Agree and
// TestSPKIFingerprint_MatchesOpenssl_*, this proves the operator-
// facing fingerprint emitted by sd keys generate is byte-equal to
// what openssl would compute over the same SPKI.
func TestSPKIFingerprint_AppearsInGenerateOutput(t *testing.T) {
	env, buf, _ := envForSCP03Mock(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "spki.pem")
	if err := cmdSDKeysGenerate(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", outPath,
		"--confirm-write",
		"--json",
	}); err != nil {
		t.Fatalf("cmdSDKeysGenerate: %v\n%s", err, buf.String())
	}

	// Pull the fingerprint string out of the JSON output without
	// importing encoding/json — keep this test independent of the
	// data struct's evolving shape.
	out := buf.String()
	const key = `"spki_fingerprint_sha256"`
	idx := strings.Index(out, key)
	if idx < 0 {
		t.Fatalf("JSON output missing %s field:\n%s", key, out)
	}
	colon := strings.Index(out[idx:], ":")
	if colon < 0 {
		t.Fatalf("malformed JSON near %s:\n%s", key, out)
	}
	rest := out[idx+colon+1:]
	q1 := strings.Index(rest, `"`)
	if q1 < 0 {
		t.Fatalf("malformed JSON; couldn't find opening quote of fingerprint value:\n%s", out)
	}
	q2 := strings.Index(rest[q1+1:], `"`)
	if q2 < 0 {
		t.Fatalf("malformed JSON; couldn't find closing quote of fingerprint value:\n%s", out)
	}
	fp := rest[q1+1 : q1+1+q2]
	if !looksLikeSHA256Hex(fp) {
		t.Errorf("emitted fingerprint %q does not match the SHA-256 hex contract", fp)
	}

	// The fingerprint in the JSON must also match what we would
	// compute by reading the --out file and digesting its DER.
	pemBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read --out: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("--out is not PEM:\n%s", pemBytes)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX pub: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("--out is not ECDSA: %T", pub)
	}
	expected, err := publicKeySPKIFingerprint(ecPub)
	if err != nil {
		t.Fatalf("publicKeySPKIFingerprint: %v", err)
	}
	if fp != expected {
		t.Errorf("JSON fingerprint != fingerprint of --out file:\n  json: %s\n  file: %s",
			fp, expected)
	}
}
