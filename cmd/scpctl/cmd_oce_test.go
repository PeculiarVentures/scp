package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 method 1 known-answer
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper: synthetic root + leaf where leaf is signed by root.
// Returns parsed certs (Raw is set).
func mkOCEFixtureValid(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSKI := computeSKI(&rootKey.PublicKey)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          rootSKI,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSKI := computeSKI(&leafKey.PublicKey)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(22),
		Subject:        pkix.Name{CommonName: "test leaf"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageKeyAgreement,
		SubjectKeyId:   leafSKI,
		AuthorityKeyId: rootSKI,
		// Explicit BasicConstraints cA=FALSE — required by YubiKey 5.7+
		// SCP11 firmware. The happy-path fixture should pass strict
		// verification; cert profiles missing this extension belong in
		// negative tests below.
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return root, leaf, leafKey
}

// helper: leaf signed by a DIFFERENT root than the one returned.
// Models Ryan's failure mode: chain[0] doesn't actually issue
// chain[1].
func mkOCEFixtureMismatched(t *testing.T) (rootInChain, leaf *x509.Certificate) {
	t.Helper()

	// rootInChain is what we put in the chain at position 0.
	rootInChainKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootInChainSKI := computeSKI(&rootInChainKey.PublicKey)
	rootInChainTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(31),
		Subject:               pkix.Name{CommonName: "claimed root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          rootInChainSKI,
	}
	rootInChainDER, err := x509.CreateCertificate(rand.Reader, rootInChainTmpl, rootInChainTmpl,
		&rootInChainKey.PublicKey, rootInChainKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rootInChain, _ = x509.ParseCertificate(rootInChainDER)

	// realSigner is a DIFFERENT root that actually signs the leaf.
	// Same subject DN as rootInChain so the cert parser doesn't even
	// catch the mismatch via DN — only the signature check does.
	realSignerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	realSignerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(32),
		Subject:               pkix.Name{CommonName: "claimed root"}, // same DN, different key
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	realSignerDER, err := x509.CreateCertificate(rand.Reader, realSignerTmpl, realSignerTmpl,
		&realSignerKey.PublicKey, realSignerKey)
	if err != nil {
		t.Fatalf("real signer: %v", err)
	}
	realSigner, _ := x509.ParseCertificate(realSignerDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(33),
		Subject:      pkix.Name{CommonName: "victim leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
		// AKI deliberately points at the rootInChain SKI to make the
		// chain LOOK consistent on a casual inspection.
		AuthorityKeyId: rootInChainSKI,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, realSigner,
		&leafKey.PublicKey, realSignerKey) // signed by realSigner, NOT rootInChain
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	return rootInChain, leaf
}

// TestOCEVerify_HappyPath asserts a clean root+leaf chain produces
// all PASS results and the command exits without error. This pins
// the expected output shape and the per-step naming so future
// changes notice if they break the user-visible report.
func TestOCEVerify_HappyPath(t *testing.T) {
	root, leaf, _ := mkOCEFixtureValid(t)
	chainPath := writeChainPEM(t, root, leaf)

	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	if err := cmdOCEVerify(context.Background(), env, []string{
		"--chain", chainPath,
	}); err != nil {
		t.Fatalf("verify: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"chain[0] key algorithm",
		"chain[0] self-signature",
		"chain[1] signature",
		"verifies against chain[0] public key",
		"leaf KeyUsage",
		"keyAgreement",
		"leaf AuthorityKeyIdentifier",
		"matches chain[0] SKI",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("clean chain should not have FAILs\n--- output ---\n%s", out)
	}
}

// TestOCEVerify_MismatchedSigner is the critical regression test:
// chain[0] is NOT the signer of chain[1], even though the DN
// claims it is. This is Ryan's likely failure mode — the off-card
// equivalent of PSO SW=6A80. The verify command must catch this
// off-card before any APDU goes on the wire.
func TestOCEVerify_MismatchedSigner(t *testing.T) {
	rootInChain, leaf := mkOCEFixtureMismatched(t)
	chainPath := writeChainPEM(t, rootInChain, leaf)

	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	err := cmdOCEVerify(context.Background(), env, []string{
		"--chain", chainPath,
	})
	if err == nil {
		t.Fatalf("expected verify error on mismatched chain\n--- output ---\n%s", buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"chain[1] signature",
		"FAIL",
		"does NOT verify against chain[0]",
		"PSO SW=6A80",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestOCEVerify_NotSelfSigned catches the case where chain[0] is
// not self-signed — i.e. the chain is rooted somewhere we can't
// see. SCP11a installation needs chain[0] to BE the trust anchor
// because that's what gets installed at KID=0x10.
func TestOCEVerify_NotSelfSigned(t *testing.T) {

	// Build root + intermediate, then drop root and use intermediate
	// as chain[0]. The leaf is signed by intermediate, so its
	// signature verifies; but intermediate isn't self-signed.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSKI := computeSKI(&rootKey.PublicKey)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(41),
		Subject:               pkix.Name{CommonName: "hidden root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          rootSKI,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intSKI := computeSKI(&intKey.PublicKey)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          intSKI,
		AuthorityKeyId:        rootSKI,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(43),
		Subject:        pkix.Name{CommonName: "leaf"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageKeyAgreement,
		AuthorityKeyId: intSKI,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	chainPath := writeChainPEM(t, intCert, leaf) // intermediate as chain[0]

	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	err := cmdOCEVerify(context.Background(), env, []string{
		"--chain", chainPath,
	})
	if err == nil {
		t.Fatalf("expected verify error when chain[0] is not self-signed\n--- output ---\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "chain[0] self-signed") || !strings.Contains(out, "FAIL") {
		t.Errorf("expected self-signed FAIL in output\n--- output ---\n%s", out)
	}
}

// TestOCEVerify_RequiresChainFlag pins the usage error.
func TestOCEVerify_RequiresChainFlag(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	err := cmdOCEVerify(context.Background(), env, []string{})
	if err == nil {
		t.Fatal("expected usage error without --chain")
	}
	if !strings.Contains(err.Error(), "--chain") {
		t.Errorf("error should mention --chain: %v", err)
	}
}

// TestOCEGen_HappyPath: gen produces a chain that scpctl oce verify
// then accepts. This is the round-trip integration check — it
// proves the generator emits chains that the verifier considers
// well-formed, which is the whole point of having both commands
// in the same toolkit.
func TestOCEGen_HappyPath(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	if err := cmdOCEGen(context.Background(), env, []string{
		"--out-dir", dir,
		"--root-cn", "Test Root CA",
		"--leaf-cn", "Test Leaf",
		"--valid-days", "30",
	}); err != nil {
		t.Fatalf("gen: %v\n--- output ---\n%s", err, buf.String())
	}

	for _, name := range []string{
		"oce-root.key.pem", "oce-root.cert.pem",
		"oce-leaf.key.pem", "oce-leaf.cert.pem",
		"oce-chain-leaf-last.pem",
	} {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("%s: empty file", name)
		}
		if strings.HasSuffix(name, ".key.pem") && st.Mode().Perm() != 0o600 {
			t.Errorf("%s: expected 0600 mode for private key, got %o", name, st.Mode().Perm())
		}
	}

	// Round-trip: feed the generated chain into verify and confirm
	// it's accepted as clean.
	var verifyBuf bytes.Buffer
	verifyEnv := &runEnv{out: &verifyBuf, errOut: &verifyBuf}
	chainPath := filepath.Join(dir, "oce-chain-leaf-last.pem")
	if err := cmdOCEVerify(context.Background(), verifyEnv, []string{
		"--chain", chainPath,
	}); err != nil {
		t.Fatalf("generated chain failed verify: %v\n--- output ---\n%s", err, verifyBuf.String())
	}
	out := verifyBuf.String()
	if strings.Contains(out, "FAIL") {
		t.Errorf("gen-then-verify round-trip should be clean\n--- output ---\n%s", out)
	}
}

// TestOCEGen_RequiresOutDir pins the usage error.
func TestOCEGen_RequiresOutDir(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	err := cmdOCEGen(context.Background(), env, []string{})
	if err == nil {
		t.Fatal("expected usage error without --out-dir")
	}
	if !strings.Contains(err.Error(), "--out-dir") {
		t.Errorf("error should mention --out-dir: %v", err)
	}
}

// TestComputeSKI_Method1 pins RFC 5280 §4.2.1.2 method 1 SKI
// computation: SHA-1 of the BIT STRING value of subjectPublicKey
// (the SEC1 uncompressed point for an EC key), NOT SHA-1 of the
// full SubjectPublicKeyInfo.
//
// The earlier revision hashed the full SPKI, which produced
// values that didn't match what cards and standards-compliant
// tooling expect. The bug was subtle because EVERY chain
// produced by a single tool would have a self-consistent
// (wrong) SKI, only revealing the discrepancy when comparing
// against extension SKIs from other generators.
//
// This test pins the contract by:
//
//  1. Generating an EC key with a known seed.
//  2. Computing computeSKI(pub).
//  3. Independently extracting the SEC1 uncompressed point and
//     hashing it via stdlib.
//  4. Asserting equality.
//
// If a future change makes computeSKI hash something other than
// the SEC1 point, this test fails.
func TestComputeSKI_Method1(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got := computeSKI(&priv.PublicKey)

	// Independently compute via crypto/ecdh, which yields the
	// same SEC1 uncompressed encoding (0x04 || X || Y) without
	// going through ASN.1.
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ECDH conv: %v", err)
	}
	point := ecdhPub.Bytes()
	if len(point) != 65 || point[0] != 0x04 {
		t.Fatalf("expected 65-byte uncompressed point starting with 0x04; got len=%d, first=0x%02X",
			len(point), point[0])
	}
	wantSum := sha1.Sum(point) //nolint:gosec // RFC 5280 method 1
	if !bytes.Equal(got, wantSum[:]) {
		t.Errorf("computeSKI mismatch:\n  got:  %X\n  want: %X (sha1 of SEC1 uncompressed point)",
			got, wantSum[:])
	}

	// Also assert it does NOT equal SHA-1 of the full SPKI,
	// which is the wrong-answer that an earlier revision
	// produced. This pin makes regressions loud.
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	wrongSum := sha1.Sum(spki) //nolint:gosec
	if bytes.Equal(got, wrongSum[:]) {
		t.Errorf("computeSKI matches SHA-1(SPKI) — that is the WRONG implementation per RFC 5280 method 1")
	}
}

// TestOCEVerify_SKIExtensionMatchesComputed_ForGeneratedChain is
// the real-world cousin of TestComputeSKI_Method1: chains produced
// by 'scpctl oce gen' should have their extension SKI EQUAL to the
// RFC 5280 method 1 computation, because that's what computeSKI
// puts in the cert template. Verify must report them as matching.
//
// This is the regression that catches the prior bug where verify
// would say "extension SKI does not match computed" on chains we
// produced ourselves.
func TestOCEVerify_SKIExtensionMatchesComputed_ForGeneratedChain(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	if err := cmdOCEGen(context.Background(), env, []string{
		"--out-dir", dir, "--valid-days", "30",
	}); err != nil {
		t.Fatalf("gen: %v", err)
	}

	var verifyBuf bytes.Buffer
	verifyEnv := &runEnv{out: &verifyBuf, errOut: &verifyBuf}
	if err := cmdOCEVerify(context.Background(), verifyEnv, []string{
		"--chain", filepath.Join(dir, "oce-chain-leaf-last.pem"),
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	out := verifyBuf.String()
	// The "extension vs computed" line is a SKIP that only
	// appears when the two values disagree. Generated chains
	// must NOT produce it.
	if strings.Contains(out, "extension SKI does not match RFC 5280 method 1") {
		t.Errorf("generated chain should have extension SKI == RFC 5280 method 1 SKI;\n--- output ---\n%s", out)
	}
}

// TestOCEVerify_LeafMissingBasicConstraints_FailsLoudly is the
// regression pin for the SCP11a PSO SW=6A80 root cause we tracked
// down on retail YubiKey 5.7.4: leaf OCE certs without an explicit
// BasicConstraints extension are rejected by the card's PSO
// ['Verify Certificate'] verifier. RFC 5280 makes the extension
// OPTIONAL on end-entity certs, so naive openssl chains and earlier
// scpctl gen output don't include it; the YubiKey is stricter.
//
// The verify command must FAIL (not SKIP) on a leaf without
// BasicConstraints, with an error message that names the symptom
// (PSO SW=6A80) and the fix (regenerate the chain), so an operator
// running 'scpctl oce verify' before bootstrap-scp11a sees the
// problem and the fix in one place.
func TestOCEVerify_LeafMissingBasicConstraints_FailsLoudly(t *testing.T) {
	// Build a chain with a leaf that has the legacy "minimal" profile:
	// KeyUsage + SKI + AKI but NO BasicConstraints. This is what
	// scpctl emitted before the fix in this commit, and what
	// hand-rolled openssl 'minimal' profiles produce.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSKI := computeSKI(&rootKey.PublicKey)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          rootSKI,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSKI := computeSKI(&leafKey.PublicKey)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(22),
		Subject:        pkix.Name{CommonName: "test leaf"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageKeyAgreement,
		SubjectKeyId:   leafSKI,
		AuthorityKeyId: rootSKI,
		// Deliberately NO BasicConstraintsValid: this is the bug
		// shape we're testing the verifier surfaces.
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	chainPath := writeChainPEM(t, root, leaf)

	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	err := cmdOCEVerify(context.Background(), env, []string{"--chain", chainPath})
	if err == nil {
		t.Fatalf("verify on leaf-without-BasicConstraints should error\n--- output ---\n%s",
			buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "leaf BasicConstraints") {
		t.Errorf("expected a 'leaf BasicConstraints' line\n--- output ---\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL on the BasicConstraints check\n--- output ---\n%s", out)
	}
	// Pin the diagnostic content so the operator-facing message
	// can't quietly drift away from the actionable fix.
	for _, want := range []string{
		"6A80",                  // names the on-card symptom
		"YubiKey 5.7+",          // names the affected firmware class
		"Regenerate the chain",  // names the fix
	} {
		if !strings.Contains(out, want) {
			t.Errorf("BasicConstraints diagnostic missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestOCEGen_LeafHasBasicConstraintsCAFalse is the positive twin:
// 'scpctl oce gen' must produce a chain whose leaf includes
// BasicConstraints cA=FALSE. If a future refactor drops this
// extension, hardware bootstrap → scp11a-sd-read silently
// regresses to PSO SW=6A80; this test catches it in CI.
func TestOCEGen_LeafHasBasicConstraintsCAFalse(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf}
	if err := cmdOCEGen(context.Background(), env, []string{
		"--out-dir", dir,
		"--root-cn", "test root",
		"--leaf-cn", "test leaf",
		"--valid-days", "30",
	}); err != nil {
		t.Fatalf("gen: %v\n--- output ---\n%s", err, buf.String())
	}

	leafPEM, err := os.ReadFile(filepath.Join(dir, "oce-leaf.cert.pem"))
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("no PEM block in oce-leaf.cert.pem")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	if !leaf.BasicConstraintsValid {
		t.Fatal("leaf must have BasicConstraints extension; YubiKey 5.7+ SCP11 " +
			"firmware rejects PSO ['Verify Certificate'] with SW=6A80 on chains " +
			"that omit it. Do not remove this without re-validating against retail " +
			"hardware.")
	}
	if leaf.IsCA {
		t.Error("leaf BasicConstraints cA must be FALSE")
	}
}
