package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp11"
)

// TestTrustFlags_LoadsRootsAndConfiguresAnchors confirms the
// --trust-roots flow: a PEM bundle is read, parsed, and applied as
// cfg.CardTrustAnchors, with InsecureSkipCardAuthentication left
// false so the SCP11 handshake will actually validate the card cert.
//
// Doesn't drive a full SCP11 session — that would need a mock card
// whose cert chains to the test root, which is more setup than the
// flag-handling logic deserves. The point here is that the flag
// parses, the file loads, and the config object reflects the
// caller's intent.
func TestTrustFlags_LoadsRootsAndConfiguresAnchors(t *testing.T) {
	// Build a self-signed CA cert as the trust root.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	dir := t.TempDir()
	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(rootsPath, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Drive the flags directly through trustFlags.applyTrust.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	tf := registerTrustFlags(fs)
	if err := fs.Parse([]string{"--trust-roots", rootsPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	report := &Report{Subcommand: "test"}
	proceed, err := tf.applyTrust(cfg, report)
	if err != nil {
		t.Fatalf("applyTrust: %v", err)
	}
	if !proceed {
		t.Error("expected proceed=true with --trust-roots set")
	}
	if cfg.CardTrustAnchors == nil {
		t.Error("CardTrustAnchors not set")
	}
	if cfg.InsecureSkipCardAuthentication {
		t.Error("InsecureSkipCardAuthentication should be false when trust roots configured")
	}
}

// TestTrustFlags_LabSkipPath confirms --lab-skip-scp11-trust still
// works for wire-only smoke testing.
func TestTrustFlags_LabSkipPath(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	tf := registerTrustFlags(fs)
	if err := fs.Parse([]string{"--lab-skip-scp11-trust"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	report := &Report{Subcommand: "test"}
	proceed, err := tf.applyTrust(cfg, report)
	if err != nil {
		t.Fatalf("applyTrust: %v", err)
	}
	if !proceed {
		t.Error("expected proceed=true with --lab-skip-scp11-trust")
	}
	if !cfg.InsecureSkipCardAuthentication {
		t.Error("InsecureSkipCardAuthentication should be true in lab-skip mode")
	}
}

// TestTrustFlags_NoFlagSkipsCleanly confirms the existing "no trust
// configured" path produces SKIP and proceed=false.
func TestTrustFlags_NoFlagSkipsCleanly(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	tf := registerTrustFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	report := &Report{Subcommand: "test"}
	proceed, err := tf.applyTrust(cfg, report)
	if err != nil {
		t.Fatalf("applyTrust: %v", err)
	}
	if proceed {
		t.Error("expected proceed=false when neither flag set")
	}
	// Report should have a SKIP entry for trust mode.
	var sawSkip bool
	for _, c := range report.Checks {
		if c.Name == "trust mode" && c.Result == ResultSkip {
			sawSkip = true
			break
		}
	}
	if !sawSkip {
		t.Error("expected SKIP entry for trust mode")
	}
}

// TestTrustFlags_RejectsBothFlagsSet confirms --trust-roots and
// --lab-skip-scp11-trust together is a usage error. Production
// trust and lab-skip are mutually exclusive — the operator should
// be deliberate about which one they're choosing.
func TestTrustFlags_RejectsBothFlagsSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	tf := registerTrustFlags(fs)
	if err := fs.Parse([]string{"--trust-roots", "/nonexistent", "--lab-skip-scp11-trust"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	report := &Report{Subcommand: "test"}
	_, err := tf.applyTrust(cfg, report)
	if err == nil {
		t.Fatal("expected usage error when both flags set")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError, got %T: %v", err, err)
	}
}

// TestLoadTrustRoots_RejectsBadInputs covers the file-shape
// guards: missing file, empty file, file with no CERTIFICATE
// blocks, file with the wrong PEM type (private key instead of
// cert).
func TestLoadTrustRoots_RejectsBadInputs(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		_, _, err := loadTrustRoots(filepath.Join(dir, "nope.pem"))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		p := filepath.Join(dir, "empty.pem")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadTrustRoots(p)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("no CERTIFICATE blocks", func(t *testing.T) {
		p := filepath.Join(dir, "junk.pem")
		if err := os.WriteFile(p, []byte("not a pem file at all\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadTrustRoots(p)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("private key instead of certificate", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(k)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		p := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadTrustRoots(p)
		if err == nil {
			t.Fatal("expected error: private key should be rejected")
		}
	})
}

// TestLoadTrustRoots_AcceptsMultipleCerts confirms a PEM with
// multiple CERTIFICATE blocks loads them all into the pool.
func TestLoadTrustRoots_AcceptsMultipleCerts(t *testing.T) {
	dir := t.TempDir()
	var combined []byte
	for i := 0; i < 3; i++ {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("ca-%d", i)},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	p := filepath.Join(dir, "multi.pem")
	if err := os.WriteFile(p, combined, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, n, err := loadTrustRoots(p)
	if err != nil {
		t.Fatalf("loadTrustRoots: %v", err)
	}
	if n != 3 {
		t.Errorf("got %d certs, want 3", n)
	}
	if pool == nil {
		t.Error("nil pool")
	}
}
