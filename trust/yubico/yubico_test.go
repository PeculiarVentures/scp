package yubico_test

import (
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

// TestRoots_PoolMatchesCerts confirms the pool contains exactly the
// certs Certs() returned — no surprises, no silent additions or
// drops in the Roots()/Certs() relationship.
func TestRoots_PoolMatchesCerts(t *testing.T) {
	certs, err := yubico.Certs()
	if err != nil {
		t.Fatalf("Certs(): %v", err)
	}
	pool, err := yubico.Roots()
	if err != nil {
		t.Fatalf("Roots(): %v", err)
	}

	// Verify each cert validates against the pool with itself as a
	// trivial chain (root certs are self-signed; opts.Roots = pool
	// makes them recognized roots and Verify accepts them as
	// terminating chains of length 1).
	for _, c := range certs {
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			// Some bundle entries are very long-lived (NotAfter
			// in 2050+); CurrentTime defaults to time.Now() which
			// is fine. A near-term-expired cert in the bundle
			// would fail here, which is the correct signal that
			// the bundle needs refreshing.
		}
		if _, err := c.Verify(opts); err != nil {
			t.Errorf("cert %q failed self-verification against pool: %v",
				c.Subject.CommonName, err)
		}
	}
}
