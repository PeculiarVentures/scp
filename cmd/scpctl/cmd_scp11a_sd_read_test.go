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
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11aSDRead_Smoke runs cmdSCP11aSDRead end-to-end against the
// SCP11 mock card with a freshly generated OCE keypair + self-signed
// certificate written to temp PEM files. The mock accepts any OCE
// certificate (its trust model is "produce a valid PSO chain at all"),
// so this exercises the full CLI path: PEM loading → mutual-auth
// handshake → SM channel → SD reads.
//
// Two SCP11a-specific assertions worth seeing in the output:
//
//   - "OCE-authenticated" — SCP11a is mutual auth; the smoke command
//     fails if Session.OCEAuthenticated() returns false. A library
//     regression that silently downgraded SCP11a to SCP11b-shape
//     auth would surface here.
//   - "GetKeyInformation over SCP11a" — confirms reads work over
//     the resulting SM channel.
func TestSCP11aSDRead_Smoke(t *testing.T) {
	// Build a proper CA + leaf chain. The strip helper in scp11
	// removes self-signed certs at the start of the chain (the
	// trust anchor lives on the card), so a self-signed leaf
	// alone would be entirely stripped — leaving nothing to send
	// over PSO. Generate a CA, then a leaf signed by the CA;
	// write the chain (CA, leaf — leaf last) to the PEM file.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0xCA),
		Subject:               pkix.Name{CommonName: "scp-smoke test OCE CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	oceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen OCE key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xFEED),
		Subject:      pkix.Name{CommonName: "scp-smoke test OCE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &oceKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create OCE cert: %v", err)
	}

	// Write PEMs to temp files.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "oce.key.pem")
	certPath := filepath.Join(dir, "oce.cert.pem")

	keyDER, err := x509.MarshalPKCS8PrivateKey(oceKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: keyDER,
	}), 0o600); err != nil {
		t.Fatalf("write key PEM: %v", err)
	}
	if err := os.WriteFile(certPath, append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...,
	), 0o644); err != nil {
		t.Fatalf("write cert PEM: %v", err)
	}

	// Set up mock card in SCP11a mode.
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mockCard.Variant = 1 // SCP11a

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	args := []string{
		"--reader", "fake",
		"--oce-key", keyPath,
		"--oce-cert", certPath,
		"--lab-skip-scp11-trust",
		// Mock advertises only KID=0x01,KVN=0xFF in its synthetic
		// Key Information Template. Match the preflight against
		// what the mock has so the smoke runs to completion.
		// Real YubiKey hardware would use the default 0x11/0x01.
		"--sd-kid", "1",
		"--sd-kvn", "255",
	}
	if err := cmdSCP11aSDRead(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSCP11aSDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()

	for _, want := range []string{
		"load OCE key",
		"load OCE cert chain",
		"open SCP11a SD",
		"OCE-authenticated",
		"PASS",
		"GetKeyInformation over SCP11a",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestSCP11aSDRead_PreflightSkipsWhenSDKeyMissing exercises the
// preflight behavior added because of Ryan's hands-on report:
// running scp11a-sd-read against a card that doesn't have the
// requested SCP11a SD key (KID/KVN) used to fail with an opaque
// card-status error from the SCP11 open. Now the smoke command
// reads the Key Information Template via an unauthenticated SD
// session, sees the missing reference, and emits a SKIP that names
// it explicitly along with the keys actually installed.
//
// The mock advertises KID=0x01,KVN=0xFF; we ask for the YubiKey
// default 0x11/0x01 (also the smoke command's default), which is
// not installed. The smoke must end without a FAIL line and must
// not attempt the SCP11 open.
func TestSCP11aSDRead_PreflightSkipsWhenSDKeyMissing(t *testing.T) {
	keyPath, certPath := writeOCEFixturePEMs(t)

	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mockCard.Variant = 1 // SCP11a

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	// Default --sd-kid (0x11) and --sd-kvn (0x01) — not on the mock.
	args := []string{
		"--reader", "fake",
		"--oce-key", keyPath,
		"--oce-cert", certPath,
		"--lab-skip-scp11-trust",
	}
	if err := cmdSCP11aSDRead(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSCP11aSDRead: %v\n--- output ---\n%s", err, buf.String())
	}

	out := buf.String()
	wantSubstrings := []string{
		"SCP11a SD key preflight",
		"SKIP",
		"KID=0x11",
		"KVN=0x01",
		"not installed",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// The smoke must NOT have proceeded to OpenSCP11.
	if strings.Contains(out, "open SCP11a SD") {
		t.Errorf("preflight skipped, but smoke still attempted OpenSCP11\n--- output ---\n%s", out)
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("preflight emitted FAIL instead of SKIP\n--- output ---\n%s", out)
	}
}

// TestSCP11aSDRead_RequiresOCEKeyAndCert documents the CLI's
// fail-closed behavior: omitting either flag is a usage error, not a
// silent fall-through to the b-variant.
func TestSCP11aSDRead_RequiresOCEKeyAndCert(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return nil, errors.New("connect should not be called")
		},
	}
	err := cmdSCP11aSDRead(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected usage error for missing --oce-key/--oce-cert")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError; got %T: %v", err, err)
	}
}

// TestLoadOCEPrivateKey_PKCS8 confirms the loader handles modern
// openssl genpkey output (PKCS#8 "PRIVATE KEY" blocks).
func TestLoadOCEPrivateKey_PKCS8(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	path := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	got, err := loadOCEPrivateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.D.Cmp(k.D) != 0 {
		t.Errorf("loaded key differs from original")
	}
}

// TestLoadOCEPrivateKey_SEC1 confirms the loader handles legacy
// openssl ecparam -genkey output (SEC1 "EC PRIVATE KEY" blocks).
// Yubico reference fixtures use this format.
func TestLoadOCEPrivateKey_SEC1(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	path := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)

	got, err := loadOCEPrivateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.D.Cmp(k.D) != 0 {
		t.Errorf("loaded key differs from original")
	}
}

// TestLoadOCEPrivateKey_RejectsNonP256 confirms the curve check
// fires before the value reaches scp11.Open. SCP11 mandates P-256;
// failing here gives a clearer error than waiting for the protocol
// layer to reject.
func TestLoadOCEPrivateKey_RejectsNonP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	path := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)

	_, err := loadOCEPrivateKey(path)
	if err == nil {
		t.Fatal("expected curve-mismatch error")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should mention P-256; got: %v", err)
	}
}

// TestLoadOCECertChain_MultipleCerts confirms the loader returns
// multi-cert chains in the order they appear in the file. Operators
// pasting "ca.pem >> chain.pem; leaf.pem >> chain.pem" expect that
// ordering preserved end-to-end.
func TestLoadOCECertChain_MultipleCerts(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mkCert := func(serial int64) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "test"},
			NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	path := filepath.Join(t.TempDir(), "chain.pem")
	_ = os.WriteFile(path, append(mkCert(1), mkCert(2)...), 0o644)

	chain, err := loadOCECertChain(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(chain) != 2 || chain[0].SerialNumber.Int64() != 1 || chain[1].SerialNumber.Int64() != 2 {
		t.Errorf("chain order wrong: %+v", chain)
	}
}

// writeOCEFixturePEMs generates a fresh OCE keypair + self-signed
// cert and writes both to a tempdir as PEM files. Returns the paths.
// Shared by SCP11a and bootstrap-oce tests so the fixture shape stays
// consistent.
func writeOCEFixturePEMs(t *testing.T) (keyPath, certPath string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xFE),
		Subject:      pkix.Name{CommonName: "scp-smoke test OCE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)

	dir := t.TempDir()
	keyPath = filepath.Join(dir, "oce.key.pem")
	certPath = filepath.Join(dir, "oce.cert.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, certPath
}
