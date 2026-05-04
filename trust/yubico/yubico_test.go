package yubico_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/trust/yubico"
)

// TestPEM_NonEmptyAndPrintable confirms the embedded bundle has
// content and is printable PEM. The "BEGIN CERTIFICATE" prefix is
// the simplest "did the embed actually happen" check that doesn't
// depend on parsing.
func TestPEM_NonEmptyAndPrintable(t *testing.T) {
	raw := yubico.PEM()
	if len(raw) == 0 {
		t.Fatal("PEM() returned empty buffer; embed directive failed?")
	}
	if !strings.Contains(string(raw), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("PEM bundle does not contain a CERTIFICATE block")
	}
}

// TestPEM_ReturnsCopy verifies callers can't mutate the embedded
// bundle through the PEM() return value. A misbehaving caller that
// writes into it must not affect a subsequent caller's view.
func TestPEM_ReturnsCopy(t *testing.T) {
	a := yubico.PEM()
	if len(a) > 0 {
		a[0] = 0xFF
	}
	b := yubico.PEM()
	if len(b) > 0 && b[0] == 0xFF {
		t.Errorf("PEM() returns a shared buffer; mutating one call affected another")
	}
}

// TestCerts_AllParse confirms every CERTIFICATE block in the bundle
// parses as a valid X.509 certificate. As of 2026-05-04 the bundle
// contains 5 certs.
func TestCerts_AllParse(t *testing.T) {
	certs, err := yubico.Certs()
	if err != nil {
		t.Fatalf("Certs() failed: %v", err)
	}
	if len(certs) < 5 {
		t.Errorf("Certs() returned %d certs; want at least 5", len(certs))
	}

	// Cross-check: the count from Certs() must match the count of
	// PEM blocks in the raw file. If they diverge, either the
	// parser is dropping certs silently or the bundle has malformed
	// blocks the parser is tolerating.
	pemCount := 0
	rest := yubico.PEM()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pemCount++
		}
	}
	if pemCount != len(certs) {
		t.Errorf("PEM has %d CERTIFICATE blocks but Certs() returned %d",
			pemCount, len(certs))
	}
}

// TestCerts_IncludesUnified2025Root confirms the unified 2025 Yubico
// Attestation Root — the one that signs YubiKey 5.7.4+ attestations,
// including SCP11 — is present in the bundle. This is the headline
// requirement: SCP11b-on-PIV against retail 5.7.4+ hardware needs
// this root in the trust pool to validate the card's CERT.SD.ECKA.
func TestCerts_IncludesUnified2025Root(t *testing.T) {
	certs, err := yubico.Certs()
	if err != nil {
		t.Fatalf("Certs(): %v", err)
	}
	for _, c := range certs {
		if c.Subject.CommonName == "Yubico Attestation Root 1" {
			return
		}
	}
	var got []string
	for _, c := range certs {
		got = append(got, c.Subject.CommonName)
	}
	t.Errorf("'Yubico Attestation Root 1' not found in bundle. Present: %v", got)
}

// TestRoots_NonEmptyPool verifies the *x509.CertPool actually has
// subjects loaded — Subjects() returns the DER-encoded subject of
// every cert in the pool, so a non-empty result is a positive signal
// that AddCert succeeded for every cert.
func TestRoots_NonEmptyPool(t *testing.T) {
	pool, err := yubico.Roots()
	if err != nil {
		t.Fatalf("Roots(): %v", err)
	}
	if pool == nil {
		t.Fatal("Roots() returned nil pool")
	}
	subjects := pool.Subjects() //nolint:staticcheck // SA1019 — Subjects is fine for tests
	if len(subjects) == 0 {
		t.Error("CertPool has no subjects loaded")
	}
}

// TestIntermediatesPEM_NonEmptyAndPrintable confirms the
// intermediates bundle was actually embedded.
func TestIntermediatesPEM_NonEmptyAndPrintable(t *testing.T) {
	raw := yubico.IntermediatesPEM()
	if len(raw) == 0 {
		t.Fatal("IntermediatesPEM() returned empty buffer; embed directive failed?")
	}
	if !strings.Contains(string(raw), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("intermediates bundle does not contain a CERTIFICATE block")
	}
}

// TestIntermediatesPEM_ReturnsCopy verifies callers can't mutate
// the embedded intermediates bundle through the public API.
func TestIntermediatesPEM_ReturnsCopy(t *testing.T) {
	a := yubico.IntermediatesPEM()
	if len(a) > 0 {
		a[0] = 0xFF
	}
	b := yubico.IntermediatesPEM()
	if len(b) > 0 && b[0] == 0xFF {
		t.Errorf("IntermediatesPEM() returns a shared buffer; mutating one call affected another")
	}
}

// TestIntermediateCerts_AllParse confirms every CERTIFICATE block in
// the intermediates bundle parses as valid X.509. As of 2026-05-04
// the bundle contains 10 intermediates.
func TestIntermediateCerts_AllParse(t *testing.T) {
	certs, err := yubico.IntermediateCerts()
	if err != nil {
		t.Fatalf("IntermediateCerts(): %v", err)
	}
	if len(certs) < 10 {
		t.Errorf("got %d intermediates; want at least 10", len(certs))
	}
}

// TestIntermediateCerts_IncludesSDAttestationB1 is the headline
// regression assertion. The Yubico SD Attestation B 1 issuer signs
// the SCP11 SD attestation chain on retail YubiKey 5.7.4+. Its
// SubjectKeyIdentifier is CE:5B:7E:AB:BC:68:28:DD:16:13:3A:5B:00:8C
// :3A:3F:18:5F:8A:E2 — confirmed against rmhrisk's hardware via
// `ykman sd info` on 2026-05-04. Without this cert in the trust
// pool, scpctl --yubico-roots fails on every retail YubiKey 5.7.4+
// with "x509: certificate signed by unknown authority".
func TestIntermediateCerts_IncludesSDAttestationB1(t *testing.T) {
	certs, err := yubico.IntermediateCerts()
	if err != nil {
		t.Fatalf("IntermediateCerts(): %v", err)
	}
	expectedSKI := []byte{
		0xCE, 0x5B, 0x7E, 0xAB, 0xBC, 0x68, 0x28, 0xDD, 0x16, 0x13,
		0x3A, 0x5B, 0x00, 0x8C, 0x3A, 0x3F, 0x18, 0x5F, 0x8A, 0xE2,
	}
	for _, c := range certs {
		if c.Subject.CommonName == "Yubico SD Attestation B 1" {
			if !bytes.Equal(c.SubjectKeyId, expectedSKI) {
				t.Errorf("SD Attestation B 1 SKI = %X, want %X",
					c.SubjectKeyId, expectedSKI)
			}
			return
		}
	}
	var got []string
	for _, c := range certs {
		got = append(got, c.Subject.CommonName)
	}
	t.Errorf("'Yubico SD Attestation B 1' not found in intermediates bundle. Present: %v", got)
}

// TestPool_IncludesBothRootsAndIntermediates confirms Pool() — the
// helper SCP11 callers actually want — has every cert from both
// embedded bundles loaded. The combined count is the simplest
// "did both files get added" probe.
func TestPool_IncludesBothRootsAndIntermediates(t *testing.T) {
	pool, err := yubico.Pool()
	if err != nil {
		t.Fatalf("Pool(): %v", err)
	}
	if pool == nil {
		t.Fatal("Pool() returned nil")
	}
	roots, _ := yubico.RootCerts()
	inters, _ := yubico.IntermediateCerts()
	wantSubjectCount := len(roots) + len(inters)

	subjects := pool.Subjects() //nolint:staticcheck // SA1019 — Subjects is fine for tests
	if len(subjects) != wantSubjectCount {
		t.Errorf("pool has %d subjects; want %d (roots %d + intermediates %d)",
			len(subjects), wantSubjectCount, len(roots), len(inters))
	}
}

// TestPool_AllPublishedCertsValidate confirms every cert in the
// embedded bundles chains to a published root. The verifier is
// configured with Roots = published roots, Intermediates = published
// intermediates — the standard x509.Verify shape. If any intermediate
// fails to chain, either the bundles have drifted relative to each
// other (Yubico published a new sub-CA under a not-yet-released
// root) or one of the embedded files is stale. Either way the test
// failure is the right signal: refresh both files together.
func TestPool_AllPublishedCertsValidate(t *testing.T) {
	roots, err := yubico.Roots()
	if err != nil {
		t.Fatalf("Roots(): %v", err)
	}
	intermediates, err := yubico.Intermediates()
	if err != nil {
		t.Fatalf("Intermediates(): %v", err)
	}

	allCerts := append([]*x509.Certificate{}, mustRootCerts(t)...)
	inters, err := yubico.IntermediateCerts()
	if err != nil {
		t.Fatalf("IntermediateCerts(): %v", err)
	}
	allCerts = append(allCerts, inters...)

	for _, c := range allCerts {
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := c.Verify(opts); err != nil {
			t.Errorf("cert %q failed to chain to a published root: %v",
				c.Subject.CommonName, err)
		}
	}
}

// TestPool_VerifyOptionsShape demonstrates the supported usage:
// Pool() goes into Roots and validation succeeds even with no
// Intermediates field set, because every intermediate in the pool
// is treated as an additional trust anchor.
func TestPool_AsRootsOnly(t *testing.T) {
	pool, err := yubico.Pool()
	if err != nil {
		t.Fatalf("Pool(): %v", err)
	}
	inters, err := yubico.IntermediateCerts()
	if err != nil {
		t.Fatalf("IntermediateCerts(): %v", err)
	}
	for _, c := range inters {
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := c.Verify(opts); err != nil {
			t.Errorf("intermediate %q does not validate against Pool() (Roots-only): %v",
				c.Subject.CommonName, err)
		}
	}
}

func mustRootCerts(t *testing.T) []*x509.Certificate {
	t.Helper()
	c, err := yubico.RootCerts()
	if err != nil {
		t.Fatalf("RootCerts(): %v", err)
	}
	return c
}
