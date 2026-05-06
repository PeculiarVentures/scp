package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/transport/trace"
)

// TestBootstrapSCP11a_DryRun confirms that without --confirm-write
// the combined command validates inputs but transmits nothing.
func TestBootstrapSCP11a_DryRun(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

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
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-out", out,
	}); err != nil {
		t.Fatalf("dry-run: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have called connect")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("dry-run should not have written the public key file")
	}
	output := buf.String()
	for _, want := range []string{"dry-run", "install OCE CA public key", "install SCP11a SD key"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, output)
		}
	}
}

// TestBootstrapSCP11a_RequiredFlags pins both required flags. Both
// --oce-cert and --sd-key-out are mandatory; without either, the
// command must fail with a usage error before any side effects.
func TestBootstrapSCP11a_RequiredFlags(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)
	out := filepath.Join(t.TempDir(), "sd-pub.pem")

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing --oce-cert",
			args:    []string{"--reader", "fake", "--sd-key-out", out},
			wantErr: "--oce-cert is required",
		},
		{
			name:    "missing --sd-key-out",
			args:    []string{"--reader", "fake", "--oce-cert", certPath},
			wantErr: "--sd-key-out is required",
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
			err := cmdBootstrapSCP11a(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError; got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestBootstrapSCP11a_ModeFlagValidation: 'oncard'/'import' accepted,
// other values rejected; --sd-key-pem requires --sd-key-mode=import.
func TestBootstrapSCP11a_ModeFlagValidation(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)
	out := filepath.Join(t.TempDir(), "sd-pub.pem")

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name: "unknown sd-key-mode rejected",
			args: []string{
				"--reader", "fake", "--oce-cert", certPath, "--sd-key-out", out,
				"--sd-key-mode", "wat",
			},
			wantErr: "must be 'oncard' or 'import'",
		},
		{
			name: "sd-key-pem with oncard rejected",
			args: []string{
				"--reader", "fake", "--oce-cert", certPath, "--sd-key-out", out,
				"--sd-key-mode", "oncard", "--sd-key-pem", "/some/path",
			},
			wantErr: "only valid with --sd-key-mode=import",
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
			err := cmdBootstrapSCP11a(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestBootstrapSCP11a_OnCardMode is the headline test: verifies that
// running bootstrap-scp11a once against a fresh-card mock results in
// BOTH writes happening over the SAME SCP03 session — exactly one
// INITIALIZE UPDATE, then PUT KEY (OCE pub) followed by GENERATE KEY
// (SCP11a SD), in that order. This is the regression fence for the
// factory-key-burn issue: if anything in the codebase ever splits
// these into separate sessions, this test fails.
func TestBootstrapSCP11a_OnCardMode(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)
	mc := scp03.NewMockCard(scp03.DefaultKeys)

	connectCount := 0
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCount++
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-out", outPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("on-card mode: %v\n--- output ---\n%s", err, buf.String())
	}

	if connectCount != 1 {
		t.Errorf("connect called %d times; want 1 (the whole point is one session)", connectCount)
	}

	rec := mc.Recorded()
	var sawPutKey, sawGenerateKey bool
	var putKeyIdx, genKeyIdx = -1, -1
	for i, r := range rec {
		switch r.INS {
		case 0xD8:
			sawPutKey = true
			if putKeyIdx < 0 {
				putKeyIdx = i
			}
		case 0xF1:
			sawGenerateKey = true
			genKeyIdx = i
		}
	}
	if !sawPutKey {
		t.Errorf("expected PUT KEY (INS=0xD8) for the OCE public key; recorded: %d entries", len(rec))
	}
	if !sawGenerateKey {
		t.Errorf("expected GENERATE KEY (INS=0xF1) for the SCP11a SD key; recorded: %d entries", len(rec))
	}
	if sawPutKey && sawGenerateKey && genKeyIdx < putKeyIdx {
		t.Errorf("GENERATE KEY came before PUT KEY (idx %d vs %d); OCE side should install first",
			genKeyIdx, putKeyIdx)
	}

	output := buf.String()
	for _, want := range []string{
		"open SCP03 SD",
		"install OCE CA public key",
		"KID=0x10 KVN=0x03",
		"install SCP11a SD key (on-card)",
		"KID=0x11 KVN=0x01",
		"write SD public key",
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

// TestBootstrapSCP11a_ImportMode_KeyPEM exercises --sd-key-mode=import
// with a host-supplied keypair. The SD public key written to
// --sd-key-out must match the public half of the supplied private
// key. PUT KEY (INS=0xD8) should be issued at least twice: once for
// the OCE public key and once for the SD private key.
func TestBootstrapSCP11a_ImportMode_KeyPEM(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

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

	mc := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-mode", "import",
		"--sd-key-pem", keyPath,
		"--sd-key-out", outPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("import mode (key-pem): %v\n--- output ---\n%s", err, buf.String())
	}

	got := assertSPKIPemIsP256(t, outPath)
	if !got.Equal(&priv.PublicKey) {
		t.Errorf("public key in --sd-key-out does not match the supplied private key's public half")
	}

	// Two PUT KEY APDUs — one for OCE public key, one for SD
	// private key. No GENERATE KEY (we're importing, not generating).
	var putKeyCount, generateCount int
	for _, r := range mc.Recorded() {
		switch r.INS {
		case 0xD8:
			putKeyCount++
		case 0xF1:
			generateCount++
		}
	}
	if putKeyCount < 2 {
		t.Errorf("expected at least 2 PUT KEY (INS=0xD8) APDUs in import mode; got %d", putKeyCount)
	}
	if generateCount != 0 {
		t.Errorf("expected NO GENERATE KEY (INS=0xF1) in import mode; got %d", generateCount)
	}
}

// TestBootstrapSCP11a_ImportMode_FreshKeyOnHost: import mode without
// --sd-key-pem generates the keypair on the host and then PUT KEYs
// it. Output PEM is the matching public half.
func TestBootstrapSCP11a_ImportMode_FreshKeyOnHost(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)
	mc := scp03.NewMockCard(scp03.DefaultKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	outPath := filepath.Join(t.TempDir(), "sd-pub.pem")
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-mode", "import",
		"--sd-key-out", outPath,
		"--confirm-write",
	}); err != nil {
		t.Fatalf("import mode (fresh): %v\n--- output ---\n%s", err, buf.String())
	}

	output := buf.String()
	for _, want := range []string{
		"generate SD keypair",
		"open SCP03 SD",
		"install OCE CA public key",
		"install SCP11a SD key (import)",
		"write SD public key",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, output)
		}
	}
	assertSPKIPemIsP256(t, outPath)
}

// TestBootstrapSCP11a_APDUTrace exercises the --apdu-trace flag.
// Pins:
//
//   - the file is created at the supplied path
//   - it is non-empty and parses as the expected JSON shape
//   - it contains AT LEAST one PUT KEY (INS=0xD8) exchange — the
//     CA-KLOC install — because that's the wire shape the trace
//     was added to investigate (PSO SW=6A80 root cause)
//   - the recorded bytes match what the mock saw on the wire
//     (the recorder is below SCP03 wrapping at the transport layer,
//     so trace bytes are the post-wrapping bytes the mock received)
//
// This is the exact diagnostic surface we'd run against retail
// hardware to byte-diff against ykman+pcsc-spy. If the test stops
// passing, the trace flag has regressed and the on-hardware
// investigation is blocked.
func TestBootstrapSCP11a_APDUTrace(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)
	mc := scp03.NewMockCard(scp03.DefaultKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	dir := t.TempDir()
	tracePath := filepath.Join(dir, "scpctl-bootstrap.json")
	outPath := filepath.Join(dir, "sd-pub.pem")
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-out", outPath,
		"--confirm-write",
		"--apdu-trace", tracePath,
	}); err != nil {
		t.Fatalf("bootstrap with --apdu-trace: %v\n--- output ---\n%s", err, buf.String())
	}

	st, err := os.Stat(tracePath)
	if err != nil {
		t.Fatalf("trace file not created at %s: %v", tracePath, err)
	}
	if st.Size() == 0 {
		t.Fatalf("trace file %s is empty", tracePath)
	}

	raw, err := os.ReadFile(tracePath) //nolint:gosec // operator-supplied test path
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}

	// Parse as the trace.File shape and assert structural
	// invariants.
	var f trace.File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("trace JSON does not parse as trace.File: %v\n--- raw ---\n%s", err, string(raw))
	}
	if f.Profile != "scpctl bootstrap-scp11a" {
		t.Errorf("trace.Profile = %q; want %q", f.Profile, "scpctl bootstrap-scp11a")
	}
	if f.Reader != "fake" {
		t.Errorf("trace.Reader = %q; want %q", f.Reader, "fake")
	}
	if len(f.Exchanges) == 0 {
		t.Fatal("trace recorded zero exchanges; the recorder should sit on the wire path")
	}

	// Find a PUT KEY exchange. The recorder records POST-SCP03-
	// wrapping bytes, so the CLA byte of the wrapped APDU has the
	// secure-messaging bit set (0x84). The INS byte stays the
	// SAME between unwrapped and wrapped (SCP03 wraps the data
	// field, not the header). So INS=0xD8 in the recorded
	// command bytes is the fingerprint we look for.
	var sawPutKey bool
	for _, ex := range f.Exchanges {
		if len(ex.INS) == 1 && ex.INS[0] == 0xD8 {
			sawPutKey = true
			break
		}
	}
	if !sawPutKey {
		t.Errorf("trace contained no PUT KEY (INS=0xD8) exchange; "+
			"%d exchanges recorded", len(f.Exchanges))
	}

	// Postamble check: stderr line announcing where the trace
	// was written, so an operator running on hardware sees a
	// pointer to the file without having to know the flag's
	// behavior in advance.
	if !strings.Contains(buf.String(), "APDU trace written to "+tracePath) {
		t.Errorf("expected stderr line announcing trace path %q\n--- output ---\n%s",
			tracePath, buf.String())
	}
}

// TestBootstrapSCP11a_APDUTrace_DryRunNoFile pins that the trace
// flag does NOT create a file when the command runs in dry-run
// (no --confirm-write). The dry-run path returns before reaching
// the connect call, so the recorder is never wired up; that's
// the contract.
func TestBootstrapSCP11a_APDUTrace_DryRunNoFile(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("dry-run should not connect")
			return nil, nil
		},
	}

	dir := t.TempDir()
	tracePath := filepath.Join(dir, "should-not-exist.json")
	outPath := filepath.Join(dir, "sd-pub.pem")
	if err := cmdBootstrapSCP11a(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--sd-key-out", outPath,
		"--apdu-trace", tracePath,
		// no --confirm-write → dry-run
	}); err != nil {
		t.Fatalf("dry-run with --apdu-trace: %v\n--- output ---\n%s", err, buf.String())
	}
	if _, err := os.Stat(tracePath); err == nil {
		t.Errorf("trace file %s exists after dry-run; should not have been created", tracePath)
	}
}
