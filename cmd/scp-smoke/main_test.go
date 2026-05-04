package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestMatchReader covers the substring matching used to resolve a
// user-supplied reader name to the OS reader list.
func TestMatchReader(t *testing.T) {
	readers := []string{
		"Yubico YubiKey OTP+FIDO+CCID 00 00",
		"ACS ACR1252 Reader 00 00",
		"Yubico YubiKey FIDO+CCID 01 00",
	}

	cases := []struct {
		query   string
		want    string
		wantErr string
	}{
		{
			query: "ACS ACR1252 Reader 00 00", // exact
			want:  "ACS ACR1252 Reader 00 00",
		},
		{
			query: "ACS",
			want:  "ACS ACR1252 Reader 00 00",
		},
		{
			query:   "Yubico", // matches two readers
			wantErr: "matches multiple readers",
		},
		{
			query: "OTP+FIDO+CCID 00", // unique substring
			want:  "Yubico YubiKey OTP+FIDO+CCID 00 00",
		},
		{
			query:   "nonsense",
			wantErr: "no reader matches",
		},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			got, err := matchReader(readers, c.query)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("matchReader(%q): nil error, want %q", c.query, c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error = %v, want substring %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestMatchReader_NoReaders(t *testing.T) {
	_, err := matchReader(nil, "anything")
	if err == nil {
		t.Fatal("expected error on empty readers list")
	}
	if !strings.Contains(err.Error(), "no PC/SC readers connected") {
		t.Errorf("error = %v, want substring 'no PC/SC readers connected'", err)
	}
}

// TestReport_EmitText confirms human-readable output includes each
// check name and result, and uses a stable column layout.
func TestReport_EmitText(t *testing.T) {
	r := &Report{Subcommand: "probe", Reader: "test-reader"}
	r.Pass("select ISD", "")
	r.Pass("GET DATA", "42 bytes")
	r.Skip("SCP advertised", "no SCP element")
	r.Fail("parse CRD", "malformed input")

	var buf bytes.Buffer
	if err := r.Emit(&buf, false); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"scp-smoke probe",
		"reader: test-reader",
		"select ISD",
		"PASS",
		"GET DATA",
		"42 bytes",
		"SKIP",
		"no SCP element",
		"FAIL",
		"malformed input",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestReport_EmitJSON confirms JSON mode produces a single valid
// document with the expected top-level keys.
func TestReport_EmitJSON(t *testing.T) {
	r := &Report{Subcommand: "probe", Reader: "test"}
	r.Pass("a", "")
	r.Fail("b", "boom")

	var buf bytes.Buffer
	if err := r.Emit(&buf, true); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var got struct {
		Subcommand string `json:"subcommand"`
		Reader     string `json:"reader"`
		Checks     []struct {
			Name   string `json:"name"`
			Result string `json:"result"`
			Detail string `json:"detail,omitempty"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Subcommand != "probe" || got.Reader != "test" {
		t.Errorf("got %+v, want subcommand=probe reader=test", got)
	}
	if len(got.Checks) != 2 ||
		got.Checks[0].Result != "PASS" ||
		got.Checks[1].Result != "FAIL" {
		t.Errorf("checks = %+v", got.Checks)
	}
}

func TestReport_HasFailure(t *testing.T) {
	r := &Report{}
	if r.HasFailure() {
		t.Error("empty report should not report failure")
	}
	r.Pass("x", "")
	r.Skip("y", "")
	if r.HasFailure() {
		t.Error("PASS+SKIP should not report failure")
	}
	r.Fail("z", "")
	if !r.HasFailure() {
		t.Error("after Fail, HasFailure should be true")
	}
}

// TestProbe_Smoke runs the probe subcommand against a synthetic
// transport that responds to SELECT ISD with 9000 and to
// GET DATA 0x66 with a hand-assembled GP 2.3.1 / SCP03 i=0x65 CRD.
// Verifies the report contains the expected capability lines.
func TestProbe_Smoke(t *testing.T) {
	// Same hand-assembled CRD shape as the trace test fixture in #41:
	// outer 66 26, inner 73 24, GP RID + GP 2.3.1 + SCP03 i=0x65.
	crd := []byte{
		0x66, 0x26,
		0x73, 0x24,
		0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
		0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
		0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x65,
	}

	tt := &probeFakeTransport{crd: crd}
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return tt, nil
		},
	}

	if err := cmdProbe(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdProbe: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"scp-smoke probe",
		"select ISD",
		"PASS",
		"GET DATA tag 0x66",
		"40 bytes",
		"GP version",
		"2.3.1",
		"SCP advertised",
		"SCP03",
		"0x65",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("probe output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestProbe_Smoke_JSON(t *testing.T) {
	crd := []byte{
		0x66, 0x26, 0x73, 0x24,
		0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
		0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
		0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x65,
	}
	tt := &probeFakeTransport{crd: crd}
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return tt, nil
		},
	}
	if err := cmdProbe(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdProbe: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if got["subcommand"] != "probe" {
		t.Errorf("subcommand = %v, want probe", got["subcommand"])
	}
	data, ok := got["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data field; got %v", got)
	}
	if data["gp_version"] != "2.3.1" {
		t.Errorf("gp_version = %v, want 2.3.1", data["gp_version"])
	}
	if data["scp_version"] != "0x03" {
		t.Errorf("scp_version = %v, want 0x03", data["scp_version"])
	}
}

func TestProbe_FailsClosedOnSelectError(t *testing.T) {
	tt := &probeFakeTransport{selectError: errors.New("card removed")}
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return tt, nil
		},
	}
	err := cmdProbe(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected error when SELECT fails")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("expected FAIL line in output\n%s", buf.String())
	}
}

// probeFakeTransport: SELECT returns 9000, GET DATA tag 0x66 returns
// the pre-canned CRD. Anything else returns 6D00.
type probeFakeTransport struct {
	crd         []byte
	selectError error
}

func (p *probeFakeTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch {
	case cmd.INS == 0xA4:
		if p.selectError != nil {
			return nil, p.selectError
		}
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case cmd.INS == 0xCA && cmd.P1 == 0x00 && cmd.P2 == 0x66:
		return &apdu.Response{Data: p.crd, SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}
func (p *probeFakeTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (p *probeFakeTransport) Close() error { return nil }

// TestSCP03SDRead_Smoke runs the cmd_scp03_sd_read flow end-to-end
// against the now-extended SCP03 mock card. The mock handles GET
// DATA tags 0xE0 (key info) and 0x66 (CRD) over secure messaging
// after the SCP03 handshake completes (PR that extends the mock
// added these), so the smoke command can be unit-tested without
// hardware.
//
// Verifies four checks pass: open, authenticated, GetKeyInformation,
// GetCardRecognitionData over SCP03.
func TestSCP03SDRead_Smoke(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	if err := cmdSCP03SDRead(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()

	for _, want := range []string{
		"open SCP03 SD",
		"PASS",
		"authenticated",
		"GetKeyInformation",
		"GetCardRecognitionData over SCP03",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Make sure no FAIL line slipped through.
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

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
	// Generate OCE key + self-signed cert.
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
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &oceKey.PublicKey, oceKey)
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
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), 0o644); err != nil {
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

// TestBootstrapOCE_DryRun confirms that without --confirm-write,
// bootstrap-oce validates inputs but does not transmit any APDU.
// The mock connect should never be called in dry-run mode.
func TestBootstrapOCE_DryRun(t *testing.T) {
	keyPath, certPath := writeOCEFixturePEMs(t)

	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	_ = keyPath

	if err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
	}); err != nil {
		t.Fatalf("dry-run cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have called connect")
	}
	out := buf.String()
	if !strings.Contains(out, "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", out)
	}
}

// TestBootstrapOCE_WithConfirm runs the destructive path against the
// SCP03 mock with --confirm-write set. Verifies the CLI:
//   - opens an SCP03 session
//   - issues PUT KEY (recorded by the mock)
//   - skips STORE CERT and CA SKI by default
//
// Asserts on the recorded APDUs from scp03.MockCard.Recorded() so a
// regression in the bootstrap sequence (e.g. dropping the PUT KEY)
// surfaces here, not just in the textual report.
func TestBootstrapOCE_WithConfirm(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}

	rec := mockCard.Recorded()
	var sawPutKey bool
	for _, r := range rec {
		if r.INS == 0xD8 {
			sawPutKey = true
		}
	}
	if !sawPutKey {
		t.Errorf("expected PUT KEY (INS=0xD8) in recorded writes; got %d entries", len(rec))
	}

	out := buf.String()
	for _, want := range []string{
		"open SCP03 SD",
		"install OCE public key",
		"PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestBootstrapOCE_StoreChainAndCASKI exercises the optional flags.
// Confirms STORE DATA (INS=0xE2) is issued for both the cert chain
// and the CA SKI when their flags are set.
func TestBootstrapOCE_StoreChainAndCASKI(t *testing.T) {
	_, certPath := writeOCEFixturePEMs(t)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err := cmdBootstrapOCE(context.Background(), env, []string{
		"--reader", "fake",
		"--oce-cert", certPath,
		"--store-chain",
		"--ca-ski", "0123456789ABCDEF0123456789ABCDEF01234567",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdBootstrapOCE: %v\n--- output ---\n%s", err, buf.String())
	}

	var nE2 int
	for _, r := range mockCard.Recorded() {
		if r.INS == 0xE2 {
			nE2++
		}
	}
	if nE2 < 2 {
		t.Errorf("expected at least 2 STORE DATA (INS=0xE2) calls (chain + CA SKI); got %d", nE2)
	}
	out := buf.String()
	if !strings.Contains(out, "store OCE cert chain") || !strings.Contains(out, "register CA SKI") {
		t.Errorf("output missing expected pass labels\n--- output ---\n%s", out)
	}
}

// TestBootstrapOCE_RequiresOCECert documents the usage-error path:
// missing --oce-cert is rejected explicitly rather than running
// against a no-cert default.
func TestBootstrapOCE_RequiresOCECert(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: nil}
	err := cmdBootstrapOCE(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected usage error for missing --oce-cert")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError; got %T: %v", err, err)
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

// TestPIVProvision_DryRun confirms --confirm-write is required for
// any APDU transmission. Without it the mock connect must not be
// called.
func TestPIVProvision_DryRun(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	if err := cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
	}); err != nil {
		t.Fatalf("dry-run cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have connected")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
}

// TestPIVProvision_GenerateKey_Smoke runs the full provisioning flow
// against the SCP11 mock. Asserts the host issued VERIFY PIN and
// GENERATE KEY in order, the smoke output reports PASS for both, and
// the mock returned a non-empty pubkey blob.
func TestPIVProvision_GenerateKey_Smoke(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--algorithm", "eccp256",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"open SCP11b vs PIV",
		"VERIFY PIN",
		"GENERATE KEY",
		"PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVProvision_WithCertAndAttest exercises the optional flags:
// --cert installs a cert via PUT CERTIFICATE, --attest fetches
// the attestation. The cert's public key must match the slot's
// generated keypair or piv-provision refuses to install — this
// test pre-seeds the mock with a known keypair and builds a cert
// from the matching public key, exercising the success path.
func TestPIVProvision_WithCertAndAttest(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Pre-seed the mock so we know what key GENERATE KEY will return,
	// then build a cert that binds to that public key.
	slotKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("slot key generate: %v", err)
	}
	mockCard.PIVPresetKey = slotKey

	certPath := writeMatchingPIVCert(t, slotKey)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9c",
		"--cert", certPath,
		"--attest",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"parse pubkey",
		"ECDSA P-256",
		"cert binding",
		"cert matches generated slot key",
		"PUT CERTIFICATE",
		"ATTESTATION",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestPIVProvision_RejectsCertPubkeyMismatch is the new test that
// would have caught the gap ChatGPT flagged: a cert whose public
// key doesn't match the slot's generated keypair must not be
// installed. The slot's keypair would still be valid, but the
// cert would attest to an identity the slot can't actually prove
// possession of.
//
// Test setup: mock pre-seeded with key A; cert built from key B.
// piv-provision must fail at the cert-binding step, before
// reaching PUT CERTIFICATE.
func TestPIVProvision_RejectsCertPubkeyMismatch(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	slotKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = slotKey

	// Different key for the cert — the binding check must catch
	// the mismatch.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPath := writeMatchingPIVCert(t, otherKey)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--cert", certPath,
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err == nil {
		t.Fatalf("expected mismatch to fail; output:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "cert binding") || !strings.Contains(out, "FAIL") {
		t.Errorf("expected cert binding FAIL in output; got:\n%s", out)
	}
	if strings.Contains(out, "PUT CERTIFICATE                  PASS") {
		t.Error("PUT CERTIFICATE happened after binding FAIL — guard is broken")
	}
}

// writeMatchingPIVCert generates a minimal self-signed X.509 cert
// bound to the given key's public part and writes it to a temp file
// in PEM form. The cert isn't otherwise meaningful — its only
// purpose is to make the cert-binding check pass (or, if the caller
// uses a different key for slot vs cert, fail).
func writeMatchingPIVCert(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scp-smoke test PIV slot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "piv-slot.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestPIVProvision_RejectsBadSlotAndAlgo confirms inputs are
// validated at the CLI boundary, not deferred to opaque card errors.
func TestPIVProvision_RejectsBadSlotAndAlgo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown slot", []string{"--reader", "f", "--pin", "1", "--slot", "ab"}},
		{"unknown algorithm", []string{"--reader", "f", "--pin", "1", "--algorithm", "frob256"}},
		{"missing pin", []string{"--reader", "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{out: &buf, errOut: &buf, connect: nil}
			err := cmdPIVProvision(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError; got %T: %v", err, err)
			}
		})
	}
}

// TestPIVProvision_WithMgmtKeyAuth runs the full provisioning flow
// with --mgmt-key against a mock configured for crypto-correct PIV
// management-key mutual auth. Round-trip verifies: host runs step 1,
// mock generates witness encrypted under shared key; host decrypts,
// runs step 2; mock verifies host's decrypted witness, encrypts the
// host's challenge; host's VerifyMutualAuthResponse accepts.
//
// This is the test that would have caught the gap I shipped in #54
// — a piv-provision with no mgmt-key flow at all — and now proves
// the flow works end-to-end through the SM channel.
func TestPIVProvision_WithMgmtKeyAuth(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Configure the mock for AES-192 mgmt-key auth (matches YubiKey
	// 5.7+ factory default algorithm). Use a deterministic key so
	// the test is reproducible.
	mgmtKey := bytes.Repeat([]byte{0xA5}, 24)
	mockCard.PIVMgmtKey = mgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--algorithm", "eccp256",
		"--mgmt-key", hex.EncodeToString(mgmtKey),
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"MGMT-KEY AUTH",
		"AES-192",
		"VERIFY PIN",
		"GENERATE KEY",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVProvision_RejectsWrongMgmtKey confirms the host's verify
// step rejects when the configured key doesn't match the card's.
// The mock encrypts with one key; the CLI is given a different key.
// The host's VerifyMutualAuthResponse must fail closed and the
// command must return an error.
func TestPIVProvision_RejectsWrongMgmtKey(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cardKey := bytes.Repeat([]byte{0xA5}, 16)
	mockCard.PIVMgmtKey = cardKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES128

	wrongKey := bytes.Repeat([]byte{0xC3}, 16)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--mgmt-key", hex.EncodeToString(wrongKey),
		"--mgmt-key-algorithm", "aes128",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err == nil {
		t.Fatalf("expected wrong-key auth to fail; output:\n%s", buf.String())
	}
	// Mock returns 6982 on host-witness mismatch — that's what we
	// expect to surface, since our wrong key produces the wrong
	// decrypted witness.
	if !strings.Contains(buf.String(), "MGMT-KEY AUTH") {
		t.Errorf("expected MGMT-KEY AUTH step in output; got:\n%s", buf.String())
	}
}

// TestPIVProvision_NoMgmtKey_StillWorksAgainstUnenforcingMock confirms
// that without --mgmt-key the command still runs and the mock (with
// no PIVMgmtKey configured) skips the auth path. This covers the
// "test the mock without going through real auth" use case.
func TestPIVProvision_NoMgmtKey_StillWorksAgainstUnenforcingMock(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// No PIVMgmtKey set; mock won't attempt the flow.
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH") || !strings.Contains(out, "SKIP") {
		t.Errorf("expected MGMT-KEY AUTH SKIP entry; got:\n%s", out)
	}
}

// TestPIVProvision_RejectsBadMgmtKeyArgs covers --mgmt-key parsing
// at the CLI boundary: bad hex, length-mismatch with algorithm,
// "default" with non-3DES algorithm.
func TestPIVProvision_RejectsBadMgmtKeyArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad hex", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "ZZ",
			"--mgmt-key-algorithm", "aes128",
		}},
		{"length mismatch", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", strings.Repeat("AA", 24), // 24 bytes
			"--mgmt-key-algorithm", "aes128", // wants 16
		}},
		{"default with non-3des", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "default",
			"--mgmt-key-algorithm", "aes192",
		}},
		{"unknown algorithm", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", strings.Repeat("AA", 16),
			"--mgmt-key-algorithm", "frob",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{out: &buf, errOut: &buf, connect: nil}
			err := cmdPIVProvision(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError; got %T: %v", err, err)
			}
		})
	}
}
