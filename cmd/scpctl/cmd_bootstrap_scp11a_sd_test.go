package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestBootstrapSCP11aSD_DryRun confirms that without --confirm-write
// the command validates inputs but transmits nothing. The mock
// connect must not be called.
func TestBootstrapSCP11aSD_DryRun(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}

	out := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11aSD(context.Background(), env, []string{
		"--reader", "fake",
		"--out", out,
	}); err != nil {
		t.Fatalf("dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have called connect")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
	// And no public key file should exist yet.
	if _, err := os.Stat(out); err == nil {
		t.Error("dry-run should not have written the public key file")
	}
}

// TestBootstrapSCP11aSD_RequiresOut documents fail-closed: --out is
// mandatory regardless of mode (otherwise we'd install a key and
// throw away the public half).
func TestBootstrapSCP11aSD_RequiresOut(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return nil, errors.New("connect should not be called")
		},
	}
	err := cmdBootstrapSCP11aSD(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected usage error for missing --out")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError; got %T: %v", err, err)
	}
}

// TestBootstrapSCP11aSD_ModeFlagValidation pins the mode validator.
// 'oncard' and 'import' are accepted; anything else is a usage error.
// And --key-pem is meaningless in 'oncard' mode.
func TestBootstrapSCP11aSD_ModeFlagValidation(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sd-pub.pem")

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "unknown mode rejected",
			args:    []string{"--reader", "fake", "--out", out, "--mode", "wat"},
			wantErr: "must be 'oncard' or 'import'",
		},
		{
			name:    "key-pem with oncard rejected",
			args:    []string{"--reader", "fake", "--out", out, "--mode", "oncard", "--key-pem", "/some/path"},
			wantErr: "only valid with --mode=import",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{
				out: &buf, errOut: &buf,
				connect: func(_ context.Context, _ string) (transport.Transport, error) {
					return nil, errors.New("connect should not be called")
				},
			}
			err := cmdBootstrapSCP11aSD(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestBootstrapSCP11aSD_OnCardMode runs the GENERATE KEY (Yubico
// extension) path against the SCP03 mock and verifies:
//   - SCP03 session opens
//   - GENERATE KEY APDU is sent
//   - the returned public key is written as PEM
//   - the PEM parses as a P-256 SubjectPublicKeyInfo
//
// On real hardware this is the recommended path because the private
// key never leaves the SE.
func TestBootstrapSCP11aSD_OnCardMode(t *testing.T) {
	mc := newSCP03MockCard(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11aSD(context.Background(), env, []string{
		"--reader", "fake",
		"--out", outPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("on-card mode: %v\n--- output ---\n%s", err, buf.String())
	}

	output := buf.String()
	for _, want := range []string{
		"open SCP03 SD",
		"install SCP11a SD key (on-card)",
		"KID=0x11 KVN=0x01",
		"write SD public key",
		"PASS",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, output)
		}
	}
	if strings.Contains(output, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", output)
	}

	assertSPKIPemIsP256(t, outPath)
}

// TestBootstrapSCP11aSD_ImportMode_FreshKeyOnHost runs the PUT KEY
// path with no --key-pem, so the host generates a fresh keypair.
// Verifies the public key in --out matches the keypair the host
// just generated and that PUT KEY was actually transmitted.
func TestBootstrapSCP11aSD_ImportMode_FreshKeyOnHost(t *testing.T) {
	mc := newSCP03MockCard(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11aSD(context.Background(), env, []string{
		"--reader", "fake",
		"--out", outPath,
		"--mode", "import",
		"--confirm-write",
	}); err != nil {
		t.Fatalf("import mode (fresh): %v\n--- output ---\n%s", err, buf.String())
	}

	output := buf.String()
	for _, want := range []string{
		"generate keypair",
		"open SCP03 SD",
		"install SCP11a SD key (import)",
		"write SD public key",
		"PASS",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, output)
		}
	}
	assertSPKIPemIsP256(t, outPath)
}

// TestBootstrapSCP11aSD_ImportMode_KeyPEM runs the PUT KEY path with
// a host-supplied keypair. The public key written to --out must
// match the public half of the supplied private key — that's the
// caller's only proof that what's installed is what they intended.
func TestBootstrapSCP11aSD_ImportMode_KeyPEM(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "sd-priv.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key PEM: %v", err)
	}

	mc := newSCP03MockCard(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11aSD(context.Background(), env, []string{
		"--reader", "fake",
		"--mode", "import",
		"--key-pem", keyPath,
		"--out", outPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("import mode (key-pem): %v\n--- output ---\n%s", err, buf.String())
	}

	got := assertSPKIPemIsP256(t, outPath)
	if !got.Equal(&priv.PublicKey) {
		t.Errorf("public key in --out does not match the supplied private key's public half")
	}
}

// newSCP03MockCard returns an scp03.MockCard preconfigured with the
// default factory keys, matching what registerSCP03KeyFlags's
// applyToConfig builds when no --scp03-* flags are passed. This is
// the same pattern bootstrap-oce's tests use.
func newSCP03MockCard(t *testing.T) *scp03.MockCard {
	t.Helper()
	return scp03.NewMockCard(scp03.DefaultKeys)
}

// assertSPKIPemIsP256 reads a SubjectPublicKeyInfo PEM file, asserts
// it parses as an ECDSA P-256 public key, and returns the parsed key.
func assertSPKIPemIsP256(t *testing.T, path string) *ecdsa.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("%s PEM type = %q, want PUBLIC KEY", path, block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	if ec.Curve != elliptic.P256() {
		t.Errorf("public key curve = %s, want P-256", ec.Curve.Params().Name)
	}
	return ec
}
