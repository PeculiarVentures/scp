package main

// SCP11 flag helper tests for Finding 4.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp11"
)

// TestSCP11Flags_NoFlagsSet_OptionalReturnsNil pins the optional-mode
// contract: with no --scp11-* flag set, applyToConfigOptional
// returns (nil, nil). The dispatcher uses this to decide between
// SCP03 and SCP11 open paths.
func TestSCP11Flags_NoFlagsSet_OptionalReturnsNil(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfigOptional()
	if err != nil {
		t.Errorf("applyToConfigOptional with no flags: err = %v, want nil", err)
	}
	if cfg != nil {
		t.Errorf("applyToConfigOptional with no flags: cfg = %+v, want nil", cfg)
	}
	if kf.anyFlagSet() {
		t.Errorf("anyFlagSet with no flags: true, want false")
	}
}

// TestSCP11Flags_RejectsSCP11b pins the host-side reject of
// --scp11-mode=b. SCP11b is one-way auth and the commands using
// these flags are all OCE-gated; the card would refuse, but we
// want a fast host-side error.
func TestSCP11Flags_RejectsSCP11b(t *testing.T) {
	for _, val := range []string{"b", "scp11b", "B", "SCP11B"} {
		t.Run(val, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP11KeyFlags(fs, scp11Optional)
			if err := fs.Parse([]string{"--scp11-mode", val}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			_, err := kf.variant()
			if err == nil {
				t.Fatalf("variant(--scp11-mode=%s) succeeded; want usage error", val)
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("err type = %T, want *usageError", err)
			}
			if !strings.Contains(err.Error(), "one-way auth") {
				t.Errorf("err = %q, want 'one-way auth' explanation", err.Error())
			}
		})
	}
}

// TestSCP11Flags_VariantParsing covers SCP11a and SCP11c happy paths.
func TestSCP11Flags_VariantParsing(t *testing.T) {
	cases := []struct {
		input string
		want  scp11Variant
	}{
		{"a", scp11VariantSCP11a},
		{"A", scp11VariantSCP11a},
		{"scp11a", scp11VariantSCP11a},
		{"SCP11A", scp11VariantSCP11a},
		{"c", scp11VariantSCP11c},
		{"C", scp11VariantSCP11c},
		{"scp11c", scp11VariantSCP11c},
		{"SCP11C", scp11VariantSCP11c},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP11KeyFlags(fs, scp11Optional)
			if err := fs.Parse([]string{"--scp11-mode", tc.input}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := kf.variant()
			if err != nil {
				t.Fatalf("variant: %v", err)
			}
			if got != tc.want {
				t.Errorf("variant(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestSCP11Flags_RejectsUnknownVariant pins that random values
// surface as a usage error pointing at the legal options.
func TestSCP11Flags_RejectsUnknownVariant(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse([]string{"--scp11-mode", "zzz"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err := kf.variant()
	if err == nil {
		t.Fatal("variant(--scp11-mode=zzz) succeeded; want error")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("err type = %T, want *usageError", err)
	}
}

// TestSCP11Flags_RequiresOCEInputs covers the validation surface
// when --scp11-mode is set but the OCE inputs aren't supplied.
func TestSCP11Flags_RequiresOCEInputs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		contains string
	}{
		{
			"missing --scp11-oce-key",
			[]string{"--scp11-mode", "a", "--scp11-oce-cert", "cert.pem", "--scp11-lab-skip-trust"},
			"--scp11-oce-key is required",
		},
		{
			"missing --scp11-oce-cert",
			[]string{"--scp11-mode", "a", "--scp11-oce-key", "key.pem", "--scp11-lab-skip-trust"},
			"--scp11-oce-cert is required",
		},
		{
			"missing trust config",
			[]string{"--scp11-mode", "a", "--scp11-oce-key", "key.pem", "--scp11-oce-cert", "cert.pem"},
			"--scp11-trust-roots",
		},
		{
			"trust roots and lab-skip both set",
			[]string{
				"--scp11-mode", "a",
				"--scp11-oce-key", "key.pem", "--scp11-oce-cert", "cert.pem",
				"--scp11-trust-roots", "roots.pem",
				"--scp11-lab-skip-trust",
			},
			"mutually exclusive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP11KeyFlags(fs, scp11Optional)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatalf("applyToConfig succeeded; want error containing %q", tc.contains)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("err = %q, want to contain %q", err.Error(), tc.contains)
			}
		})
	}
}

// TestSCP11Flags_HappyPath_SCP11a verifies a complete flag set
// parses into a valid *scp11.Config with Variant=SCP11a, the OCE
// chain populated, the SD KID at GP-default 0x11, and trust
// anchors loaded.
func TestSCP11Flags_HappyPath_SCP11a(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath, _ := writeTestOCEMaterial(t, dir)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse([]string{
		"--scp11-mode", "a",
		"--scp11-oce-key", keyPath,
		"--scp11-oce-cert", certPath,
		"--scp11-trust-roots", certPath, // self-signed, the leaf is its own anchor
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.Variant != scp11.SCP11a {
		t.Errorf("Variant = %v, want SCP11a", cfg.Variant)
	}
	if cfg.KeyID != 0x11 {
		t.Errorf("SD KeyID = 0x%02X, want 0x11 (GP SCP11a default)", cfg.KeyID)
	}
	if cfg.OCEPrivateKey == nil {
		t.Errorf("OCEPrivateKey nil")
	}
	if len(cfg.OCECertificates) == 0 {
		t.Errorf("OCECertificates empty")
	}
	if cfg.CardTrustAnchors == nil {
		t.Errorf("CardTrustAnchors nil")
	}
	if cfg.InsecureSkipCardAuthentication {
		t.Errorf("InsecureSkipCardAuthentication true; --scp11-trust-roots was set")
	}
}

// TestSCP11Flags_HappyPath_SCP11c verifies SCP11c selection and
// the SD KID default flips to 0x15 (GP SCP11c slot).
func TestSCP11Flags_HappyPath_SCP11c(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath, _ := writeTestOCEMaterial(t, dir)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse([]string{
		"--scp11-mode", "c",
		"--scp11-oce-key", keyPath,
		"--scp11-oce-cert", certPath,
		"--scp11-lab-skip-trust",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.Variant != scp11.SCP11c {
		t.Errorf("Variant = %v, want SCP11c", cfg.Variant)
	}
	if cfg.KeyID != 0x15 {
		t.Errorf("SD KeyID = 0x%02X, want 0x15 (GP SCP11c default)", cfg.KeyID)
	}
	if !cfg.InsecureSkipCardAuthentication {
		t.Errorf("InsecureSkipCardAuthentication false; --scp11-lab-skip-trust was set")
	}
}

// TestSCP11Flags_OverrideSDKID confirms --scp11-sd-kid overrides
// the per-variant default.
func TestSCP11Flags_OverrideSDKID(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath, _ := writeTestOCEMaterial(t, dir)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse([]string{
		"--scp11-mode", "a",
		"--scp11-oce-key", keyPath,
		"--scp11-oce-cert", certPath,
		"--scp11-lab-skip-trust",
		"--scp11-sd-kid", "7F",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyID != 0x7F {
		t.Errorf("SD KeyID = 0x%02X, want 0x7F (override)", cfg.KeyID)
	}
}

// TestValidateAuthFlags_MutualExclusion pins that --scp03-* and
// --scp11-* together is a usage error before any session opens.
func TestValidateAuthFlags_MutualExclusion(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath, _ := writeTestOCEMaterial(t, dir)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	scp11Keys := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse([]string{
		"--scp03-keys-default",
		"--scp11-mode", "a",
		"--scp11-oce-key", keyPath,
		"--scp11-oce-cert", certPath,
		"--scp11-lab-skip-trust",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err := validateAuthFlags(scp03Keys, scp11Keys)
	if err == nil {
		t.Fatal("validateAuthFlags(both groups set) succeeded; want usage error")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %q, want 'mutually exclusive'", err.Error())
	}
}

// TestValidateAuthFlags_BothEmpty_OK pins that the implicit-default
// path (no flags from either group) passes validation. Commands
// with --confirm-write fall through to dry-run with this state and
// shouldn't surface a flag error.
func TestValidateAuthFlags_BothEmpty_OK(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	scp11Keys := registerSCP11KeyFlags(fs, scp11Optional)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := validateAuthFlags(scp03Keys, scp11Keys); err != nil {
		t.Errorf("validateAuthFlags(both empty): err = %v, want nil", err)
	}
}

// writeTestOCEMaterial creates a self-signed P-256 OCE cert and
// PEM-encodes both the cert and the private key for the flag-
// validation tests. Returns paths to (key, cert, pubkey of the
// cert). The cert is its own trust anchor; tests that need a
// trust-roots PEM can pass the cert path twice (once for OCE
// chain, once as roots).
//
// Tests that need to cover trust failures should generate a
// distinct trust anchor — that's not what these tests cover; they
// cover flag parsing.
func writeTestOCEMaterial(t *testing.T, dir string) (keyPath, certPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test OCE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPath = filepath.Join(dir, "oce-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}

	certPath = filepath.Join(dir, "oce-cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	return keyPath, certPath, &priv.PublicKey
}
