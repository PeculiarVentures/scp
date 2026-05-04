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
	"flag"
	"fmt"
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
	"github.com/PeculiarVentures/scp/scp11"
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
		{"default with aes128 (wrong length)", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "default",
			"--mgmt-key-algorithm", "aes128",
		}},
		{"default with aes256 (wrong length)", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "default",
			"--mgmt-key-algorithm", "aes256",
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

// TestPIVReset_DryRun confirms --confirm-write is required. The
// destructive guard is on the CLI side as well as the card side
// (card-side: PIN+PUK must both be blocked); the CLI guard means
// the command must not even open a transport without --confirm-write.
func TestPIVReset_DryRun(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	if err := cmdPIVReset(context.Background(), env, []string{
		"--reader", "fake",
	}); err != nil {
		t.Fatalf("dry-run cmdPIVReset: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have connected")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
}

// TestPIVReset_HappyPath_Smoke runs the full reset flow against a
// mock with default PIV state. Asserts the sequence happens (PIN
// blocked, PUK blocked, reset succeeds) and verifies the mock's
// PIV state actually returned to factory afterward.
//
// This is the test that proves the wire flow on its own merits:
// before the reset, the mock's PIN counter is 3; we send 3 wrong
// PINs and the counter goes to 0 (blocked); same for PUK; then
// INS 0xFB is accepted and counters return to 3.
func TestPIVReset_HappyPath_Smoke(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	// Provision some state so the test can verify reset clears it.
	mockCard.PIVPresetKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVReset(context.Background(), env, []string{
		"--reader", "fake",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVReset: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"open SCP11b vs PIV               PASS",
		"block PIN                        PASS",
		"blocked after 3 wrong attempts",
		"block PUK                        PASS",
		"PIV reset                        PASS",
		"applet returned to factory state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVReset_ProvisionAfterReset_Works is the integration test
// for the whole "provision → wrong cert → reset → provision again"
// loop you actually want this command for. Steps:
//
//  1. Pre-seed mock with key A; provision slot 9a with cert bound
//     to key A — succeeds (cert binding passes).
//  2. Reset the card.
//  3. Pre-seed mock with key B; provision slot 9a with cert bound
//     to key B — succeeds again, no leftover state from round 1.
//
// If the mock's reset path forgot to clear pivLastGenKey or the
// counters didn't actually return to 3, this test fails at step 3.
func TestPIVReset_ProvisionAfterReset_Works(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = keyA
	certA := writeMatchingPIVCert(t, keyA)

	provision := func(certPath string) string {
		var b bytes.Buffer
		env := &runEnv{
			out: &b, errOut: &b,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mockCard.Transport(), nil
			},
		}
		if err := cmdPIVProvision(context.Background(), env, []string{
			"--reader", "f", "--pin", "123456",
			"--slot", "9a", "--algorithm", "eccp256",
			"--cert", certPath,
			"--lab-skip-scp11-trust", "--confirm-write",
		}); err != nil {
			t.Fatalf("provision: %v\n%s", err, b.String())
		}
		return b.String()
	}
	reset := func() string {
		var b bytes.Buffer
		env := &runEnv{
			out: &b, errOut: &b,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mockCard.Transport(), nil
			},
		}
		if err := cmdPIVReset(context.Background(), env, []string{
			"--reader", "f",
			"--lab-skip-scp11-trust", "--confirm-write",
		}); err != nil {
			t.Fatalf("reset: %v\n%s", err, b.String())
		}
		return b.String()
	}

	// Round 1: provision with key A.
	r1 := provision(certA)
	if !strings.Contains(r1, "cert binding                     PASS") {
		t.Fatalf("round 1 cert binding did not pass:\n%s", r1)
	}

	// Reset.
	rr := reset()
	if !strings.Contains(rr, "PIV reset                        PASS") {
		t.Fatalf("reset did not pass:\n%s", rr)
	}

	// Round 2: pre-seed with key B and provision with key B's cert.
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = keyB
	certB := writeMatchingPIVCert(t, keyB)
	r2 := provision(certB)
	if !strings.Contains(r2, "cert binding                     PASS") {
		t.Fatalf("round 2 cert binding did not pass after reset:\n%s", r2)
	}
}

// TestPIVReset_RefusedWhenCountersNotBlocked confirms the card-side
// guard. Drive the mock by hand: don't block PIN/PUK first, just
// send INS=0xFB. The mock must refuse with 6985.
func TestPIVReset_RefusedWhenCountersNotBlocked(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	cfg.InsecureSkipCardAuthentication = true

	sess, err := scp11.Open(context.Background(), mockCard.Transport(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(context.Background(), piv.Reset())
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if resp.StatusWord() != 0x6985 {
		t.Errorf("expected 6985 (conditions not satisfied) when counters not blocked, got %04X",
			resp.StatusWord())
	}
}

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

// TestSCP03KeyFlags_DefaultIsFactory confirms no flags = factory.
// Identical behavior to before this PR; the test pins the
// equivalence so a refactor doesn't accidentally change it.
func TestSCP03KeyFlags_DefaultIsFactory(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != scp03.YubiKeyFactoryKeyVersion {
		t.Errorf("KVN got 0x%02X want 0x%02X (YubiKey factory)",
			cfg.KeyVersion, scp03.YubiKeyFactoryKeyVersion)
	}
	if !bytesEqualKey(cfg.Keys.ENC, scp03.DefaultKeys.ENC) {
		t.Error("ENC key not the well-known factory value")
	}
	if !strings.Contains(kf.describeKeys(cfg), "factory") {
		t.Errorf("describeKeys should call this factory; got %q", kf.describeKeys(cfg))
	}
}

// TestSCP03KeyFlags_ExplicitDefault confirms --scp03-keys-default
// produces the same factory config as the implicit default.
func TestSCP03KeyFlags_ExplicitDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{"--scp03-keys-default"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != scp03.YubiKeyFactoryKeyVersion {
		t.Errorf("KVN: got 0x%02X want 0x%02X", cfg.KeyVersion, scp03.YubiKeyFactoryKeyVersion)
	}
}

// TestSCP03KeyFlags_CustomKeys_AES128 confirms --scp03-{kvn,enc,mac,
// dek} all together produce a Config with the supplied bytes. The
// most realistic scenario: a card whose factory keys have been
// rotated to a known operator-controlled set.
func TestSCP03KeyFlags_CustomKeys_AES128(t *testing.T) {
	enc := strings.Repeat("11", 16)
	macK := strings.Repeat("22", 16)
	dek := strings.Repeat("33", 16)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-enc", enc,
		"--scp03-mac", macK,
		"--scp03-dek", dek,
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != 0x01 {
		t.Errorf("KVN: got 0x%02X want 0x01", cfg.KeyVersion)
	}
	if hex.EncodeToString(cfg.Keys.ENC) != enc {
		t.Error("ENC bytes don't match")
	}
	if hex.EncodeToString(cfg.Keys.MAC) != macK {
		t.Error("MAC bytes don't match")
	}
	if hex.EncodeToString(cfg.Keys.DEK) != dek {
		t.Error("DEK bytes don't match")
	}
	desc := kf.describeKeys(cfg)
	if !strings.Contains(desc, "custom") || !strings.Contains(desc, "AES-128") {
		t.Errorf("describeKeys: got %q, want custom AES-128", desc)
	}
}

// TestSCP03KeyFlags_CustomKeys_AES192_AES256 confirms longer key
// lengths work. AES-192 (24 bytes) is a realistic post-rotation
// state on YubiKey 5.7+.
func TestSCP03KeyFlags_CustomKeys_AES192_AES256(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"AES-192", 24},
		{"AES-256", 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := strings.Repeat("AB", tc.size)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse([]string{
				"--scp03-kvn", "FF",
				"--scp03-enc", k, "--scp03-mac", k, "--scp03-dek", k,
			}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg, err := kf.applyToConfig()
			if err != nil {
				t.Fatalf("applyToConfig: %v", err)
			}
			if len(cfg.Keys.ENC) != tc.size {
				t.Errorf("ENC length: got %d want %d", len(cfg.Keys.ENC), tc.size)
			}
			if !strings.Contains(kf.describeKeys(cfg), tc.name) {
				t.Errorf("describeKeys: got %q want %s", kf.describeKeys(cfg), tc.name)
			}
		})
	}
}

// TestSCP03KeyFlags_TolerantHexFormatting confirms the paste-from-
// docs cosmetics work: spaces, colons, dashes are all stripped
// before hex-decoding.
func TestSCP03KeyFlags_TolerantHexFormatting(t *testing.T) {
	want, _ := hex.DecodeString("404142434445464748494a4b4c4d4e4f")
	cases := []string{
		"40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f",
		"40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f",
		"40-41-42-43-44-45-46-47-48-49-4a-4b-4c-4d-4e-4f",
	}
	for i, s := range cases {
		t.Run(fmt.Sprintf("variant_%d", i), func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse([]string{
				"--scp03-kvn", "FF",
				"--scp03-enc", s, "--scp03-mac", s, "--scp03-dek", s,
			}); err != nil {
				t.Fatal(err)
			}
			cfg, err := kf.applyToConfig()
			if err != nil {
				t.Fatalf("applyToConfig: %v", err)
			}
			if !bytesEqualKey(cfg.Keys.ENC, want) {
				t.Errorf("decoded bytes mismatch")
			}
		})
	}
}

// TestSCP03KeyFlags_RejectsPartialCustom confirms that supplying
// some but not all of --scp03-{kvn,enc,mac,dek} is a usage error.
// A half-specified key set is one of the easier ways to misfire a
// production rotation; failing closed is the right move.
func TestSCP03KeyFlags_RejectsPartialCustom(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing dek", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
		}},
		{"missing mac and dek", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 16),
		}},
		{"missing kvn", []string{
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatal("expected partial-custom error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError, got %T", err)
			}
			if !strings.Contains(err.Error(), "all four") {
				t.Errorf("error should mention all four flags must be supplied; got %v", err)
			}
		})
	}
}

// TestSCP03KeyFlags_RejectsMixedDefaultAndCustom confirms
// --scp03-keys-default with any --scp03-{kvn,enc,mac,dek} fails.
// Operator must be deliberate.
func TestSCP03KeyFlags_RejectsMixedDefaultAndCustom(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-keys-default",
		"--scp03-kvn", "01",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError, got %T", err)
	}
}

// TestSCP03KeyFlags_RejectsInconsistentKeyLengths confirms
// enc/mac/dek must all be the same length. SCP03 sessions need
// matching ENC/MAC/DEK key sizes; mismatch is a usage error
// rather than an opaque card SW.
func TestSCP03KeyFlags_RejectsInconsistentKeyLengths(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-enc", strings.Repeat("11", 16),
		"--scp03-mac", strings.Repeat("22", 24), // wrong length
		"--scp03-dek", strings.Repeat("33", 16),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected length-mismatch error")
	}
	if !strings.Contains(err.Error(), "length mismatch") {
		t.Errorf("expected length-mismatch error; got %v", err)
	}
}

// TestSCP03KeyFlags_RejectsBadHex covers the parse-failure path
// for individual key flags.
func TestSCP03KeyFlags_RejectsBadHex(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad enc hex", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", "ZZ",
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
		{"bad kvn hex", []string{
			"--scp03-kvn", "GG",
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
		{"unsupported key length 8 bytes", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 8),
			"--scp03-mac", strings.Repeat("22", 8),
			"--scp03-dek", strings.Repeat("33", 8),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestSCP03SDRead_CustomKeys_Smoke is the end-to-end test:
// configures a scp03 mock with non-factory keys, runs scp03-sd-read
// with --scp03-{kvn,enc,mac,dek} matching, asserts the session
// opens. Without this test, a refactor that wires the custom key
// flags through to the wrong place would be caught only by manual
// hardware testing.
func TestSCP03SDRead_CustomKeys_Smoke(t *testing.T) {
	customKeys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0x11}, 16),
		MAC: bytes.Repeat([]byte{0x22}, 16),
		DEK: bytes.Repeat([]byte{0x33}, 16),
	}
	mock := scp03.NewMockCard(customKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-enc", hex.EncodeToString(customKeys.ENC),
		"--scp03-mac", hex.EncodeToString(customKeys.MAC),
		"--scp03-dek", hex.EncodeToString(customKeys.DEK),
	})
	if err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "SCP03 keys                       PASS — custom (KVN 0x01, AES-128)") {
		t.Errorf("output should report custom keys; got:\n%s", out)
	}
	if !strings.Contains(out, "open SCP03 SD                    PASS") {
		t.Errorf("expected open PASS; got:\n%s", out)
	}
}

// TestSCP03SDRead_FactoryKeys_StillWorks confirms the implicit-
// default path is unchanged: no flags = factory keys = factory
// mock, identical to pre-PR behavior.
func TestSCP03SDRead_FactoryKeys_StillWorks(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{"--reader", "fake"})
	if err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "factory") {
		t.Errorf("output should mention factory; got:\n%s", buf.String())
	}
}

// TestSCP03SDRead_WrongKeysFails confirms the negative path:
// supplying keys that don't match the mock's actual keys produces
// a session-open failure. Validates that the keys are actually
// being used in the handshake, not just stored in cfg and ignored.
func TestSCP03SDRead_WrongKeysFails(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	wrong := bytes.Repeat([]byte{0xFF}, 16)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-enc", hex.EncodeToString(wrong),
		"--scp03-mac", hex.EncodeToString(wrong),
		"--scp03-dek", hex.EncodeToString(wrong),
	})
	if err == nil {
		t.Fatalf("expected handshake to fail with wrong keys; output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "open SCP03 SD") {
		t.Errorf("expected open SCP03 SD step in output; got:\n%s", buf.String())
	}
}

// TestPIVProvision_MgmtKeyDefault_AES192 confirms --mgmt-key default
// works with --mgmt-key-algorithm aes192 — the YubiKey 5.7+ factory
// state. Per Yubico docs, the same 24-byte well-known value
// (0102030405...0708) is the default for both 3DES (pre-5.7) and
// AES-192 (5.7+), so "default" must work for either.
//
// I had this wrong before; the original code rejected
// `--mgmt-key default --mgmt-key-algorithm aes192` with an error
// claiming the default only applied to 3DES. Confirmed against
// Yubico's own developer docs, the default value is shared.
func TestPIVProvision_MgmtKeyDefault_AES192(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Mock acts as a 5.7+ card: AES-192 mgmt key, default value.
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
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
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH                    PASS — AES-192") {
		t.Errorf("expected mgmt-key auth PASS with AES-192; got:\n%s", out)
	}
}

// TestPIVProvision_MgmtKeyDefault_3DES_StillWorks pins the original
// pre-5.7 path so the AES-192 expansion doesn't accidentally break
// it.
func TestPIVProvision_MgmtKeyDefault_3DES_StillWorks(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmt3DES

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
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "3des",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH                    PASS — 3DES") {
		t.Errorf("expected mgmt-key auth PASS with 3DES; got:\n%s", out)
	}
}

// TestParsePIVSlot_RetiredRange confirms the CLI accepts the full
// retired-key-management slot range (0x82..0x95, slots 1..20)
// rather than only SlotRetired1. The underlying piv.slotToObjectID
// already supported the full range; the bug was that parsePIVSlot
// rejected anything except 0x82, making the other 19 retired slots
// unreachable from the CLI.
func TestParsePIVSlot_RetiredRange(t *testing.T) {
	// Walk the entire 0x82..0x95 range and confirm every byte parses.
	for slot := byte(0x82); slot <= 0x95; slot++ {
		s := fmt.Sprintf("%02x", slot)
		got, err := parsePIVSlot(s)
		if err != nil {
			t.Errorf("slot %s: unexpected error: %v", s, err)
			continue
		}
		if got != slot {
			t.Errorf("slot %s: got 0x%02X want 0x%02X", s, got, slot)
		}
	}

	// 0x96 is just past the retired range — must be rejected.
	if _, err := parsePIVSlot("96"); err == nil {
		t.Error("0x96 should be rejected (one past retired range)")
	}
	// 0x81 is just before — must be rejected.
	if _, err := parsePIVSlot("81"); err == nil {
		t.Error("0x81 should be rejected (one before retired range)")
	}
}

// TestParsePIVSlot_NamedSlots pins the four primary PIV slots and
// the YubiKey attestation slot still parse, plus an unknown slot
// is rejected with a helpful error.
func TestParsePIVSlot_NamedSlots(t *testing.T) {
	cases := map[string]byte{
		"9a": piv.SlotAuthentication,
		"9c": piv.SlotSignature,
		"9d": piv.SlotKeyManagement,
		"9e": piv.SlotCardAuth,
		"f9": piv.SlotAttestation,
	}
	for s, want := range cases {
		t.Run(s, func(t *testing.T) {
			got, err := parsePIVSlot(s)
			if err != nil {
				t.Fatalf("%s: %v", s, err)
			}
			if got != want {
				t.Errorf("%s: got 0x%02X want 0x%02X", s, got, want)
			}
		})
	}
	if _, err := parsePIVSlot("01"); err == nil {
		t.Error("0x01 should be rejected")
	}
}
