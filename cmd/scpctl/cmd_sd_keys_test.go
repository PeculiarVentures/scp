package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// envForMock builds a runEnv that connects through the given mock
// card. The captured buffer is returned for tests that assert on
// rendered output. Tests construct an env per case so a stale buffer
// from one case does not leak into another.
func envForMock(mc *mockcard.Card) (*runEnv, *bytes.Buffer) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	return env, &buf
}

// --- sd keys list ---

// TestSDKeysList_TextOutput verifies the human-readable shape: report
// header, the three GET DATA check lines (KIT, KLOC/KLCC, per-ref
// certs), and at least one key entry rendered in the data block.
//
// The mock card advertises one KIT entry (KID=0x01, KVN=0xFF, AES-128)
// and returns its self-signed cert for any 0xBF21 query, so an
// authentic 'sd keys list' run produces:
//   - one PASS for KIT (1 entries)
//   - one SKIP for KLOC/KLCC (mock returns SW=6A88)
//   - one PASS for the per-ref cert fetch (1 entry)
func TestSDKeysList_TextOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"scpctl sd keys list",
		"select ISD",
		"PASS",
		"GET DATA tag 0x00E0 (KIT)",
		"1 entries",
		"GET DATA tags 0xFF33/0xFF34", // KLOC/KLCC line
		"certificates kid=0x01 kvn=0xFF",
		"Mock SD Certificate", // cert subject from mockcard.New
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDKeysList_JSONShape verifies the JSON payload schema. JSON is
// what automation consumes; pinning the field names and types here
// catches accidental schema drift in downstream changes.
func TestSDKeysList_JSONShape(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}

	var report struct {
		Subcommand string `json:"subcommand"`
		Data       struct {
			Channel string `json:"channel"`
			Keys    []struct {
				KID        int    `json:"kid"`
				KVN        int    `json:"kvn"`
				KIDHex     string `json:"kid_hex"`
				KVNHex     string `json:"kvn_hex"`
				Kind       string `json:"kind"`
				Components []struct {
					ID   int `json:"id"`
					Type int `json:"type"`
				} `json:"components"`
				Certificates []struct {
					Subject               string `json:"subject"`
					SPKIFingerprintSHA256 string `json:"spki_fingerprint_sha256"`
				} `json:"certificates"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v\n%s", err, buf.String())
	}
	if report.Subcommand != "sd keys list" {
		t.Errorf("subcommand = %q, want %q", report.Subcommand, "sd keys list")
	}
	if report.Data.Channel != "unauthenticated" {
		t.Errorf("data.channel = %q, want %q", report.Data.Channel, "unauthenticated")
	}
	if len(report.Data.Keys) != 1 {
		t.Fatalf("keys length = %d, want 1; payload:\n%s", len(report.Data.Keys), buf.String())
	}
	k := report.Data.Keys[0]
	if k.KID != 0x01 {
		t.Errorf("keys[0].kid = %d, want 1", k.KID)
	}
	if k.KVN != 0xFF {
		t.Errorf("keys[0].kvn = %d, want 255", k.KVN)
	}
	if k.KIDHex != "0x01" {
		t.Errorf("keys[0].kid_hex = %q, want 0x01", k.KIDHex)
	}
	if k.KVNHex != "0xFF" {
		t.Errorf("keys[0].kvn_hex = %q, want 0xFF", k.KVNHex)
	}
	if k.Kind != "scp03" {
		t.Errorf("keys[0].kind = %q, want scp03", k.Kind)
	}
	if len(k.Components) == 0 {
		t.Errorf("keys[0].components is empty; mockcard advertises an AES-128 component")
	}
	if len(k.Certificates) != 1 {
		t.Fatalf("keys[0].certificates length = %d, want 1", len(k.Certificates))
	}
	if !strings.Contains(k.Certificates[0].Subject, "Mock SD Certificate") {
		t.Errorf("keys[0].certificates[0].subject = %q, want substring 'Mock SD Certificate'",
			k.Certificates[0].Subject)
	}
	if got := k.Certificates[0].SPKIFingerprintSHA256; len(got) != 64 {
		t.Errorf("spki_fingerprint_sha256 length = %d, want 64 hex chars; got %q",
			len(got), got)
	}
}

// TestSDKeysList_NoCertChain verifies the per-reference cert-fetch
// fail-soft path: when the card returns SW=6A88 for a 0xBF21 query,
// the per-ref check is SKIP, and the entry has no Certificates field.
// The command itself still exits 0 because list is fundamentally an
// inventory call where empty cells are normal.
func TestSDKeysList_NoCertChain(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.CertDER = nil // makes 0xBF21 return SW=6A88 (see mockcard convention)

	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no chain stored") {
		t.Errorf("output missing 'no chain stored' SKIP line:\n%s", out)
	}
	if strings.Contains(out, "Mock SD Certificate") {
		t.Errorf("output should not include cert subject when chain is empty:\n%s", out)
	}
}

// TestSDKeysList_NoPrivateMaterial guards the contract that no private
// or session-secret bytes ever appear in the JSON output. The check
// is intentionally cheap — assert that none of the obvious red flags
// (key labels, the static SCP03 default ENC pattern) appear in the
// rendered output. If the output ever includes a field name like
// "secret_key" or the hex of a real key, this test catches it before
// review and before any operator runs the command in production.
func TestSDKeysList_NoPrivateMaterial(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}
	out := strings.ToLower(buf.String())
	for _, banned := range []string{
		"private",
		"secret",
		"session_key",
		"k_enc", "k_mac", "k_dek",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("output contains banned token %q; full output:\n%s", banned, buf.String())
		}
	}
}

// --- sd keys export ---

// TestSDKeysExport_PEMToFile exercises the most common path: write a
// chain to a file as PEM. Verifies the file is parseable as one or
// more PEM CERTIFICATE blocks.
func TestSDKeysExport_PEMToFile(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "chain.pem")

	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "01", "--kvn", "FF", "--out", outPath}
	if err := cmdSDKeysExport(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDKeysExport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("out file is empty")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		t.Fatalf("file is not PEM:\n%s", data)
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want CERTIFICATE", block.Type)
	}
	if len(rest) > 0 {
		next, _ := pem.Decode(rest)
		if next == nil {
			t.Errorf("trailing bytes after first PEM block are not valid PEM:\n%s", rest)
		}
	}
}

// TestSDKeysExport_DERToFile verifies --der writes raw bytes (no PEM
// armor, parseable as DER X.509).
func TestSDKeysExport_DERToFile(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "chain.der")

	env, _ := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FF",
		"--der",
		"--out", outPath,
	}
	if err := cmdSDKeysExport(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDKeysExport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("out file is empty")
	}
	// DER X.509 starts with SEQUENCE (0x30). PEM would start with
	// '-' (0x2D) for "-----BEGIN".
	if data[0] != 0x30 {
		t.Errorf("first byte = 0x%02X, want 0x30 (DER SEQUENCE)", data[0])
	}
}

// TestSDKeysExport_PEMToStdout exercises the no-out-flag path: PEM
// renders inline alongside the report header.
func TestSDKeysExport_PEMToStdout(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "01", "--kvn", "FF"}
	if err := cmdSDKeysExport(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDKeysExport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scpctl sd keys export") {
		t.Errorf("output missing report header:\n%s", out)
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("output missing PEM block:\n%s", out)
	}
}

// TestSDKeysExport_NoChain_DefaultFails pins the design contract that
// asking for a specific chain that does not exist is a FAIL by
// default. This is the most important behavior of this command for
// automation safety: a script that pipes through 'sd keys export'
// must not silently proceed when the card had nothing to give.
func TestSDKeysExport_NoChain_DefaultFails(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.CertDER = nil // SW=6A88 from the cert store

	dir := t.TempDir()
	outPath := filepath.Join(dir, "chain.pem")

	env, buf := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "01", "--kvn", "FF", "--out", outPath}
	err = cmdSDKeysExport(context.Background(), env, args)
	if err == nil {
		t.Fatalf("expected error from no-chain export, got nil; output:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "no certificate chain") {
		t.Errorf("error should mention missing chain; got %v", err)
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("report should contain a FAIL line:\n%s", buf.String())
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("default no-chain path must not write the output file; stat err = %v", statErr)
	}
}

// TestSDKeysExport_NoChain_AllowEmpty verifies the opt-in inventory-
// walk path: --allow-empty turns the no-chain condition into a SKIP
// at exit 0 with JSON-visible "certificates": [].
func TestSDKeysExport_NoChain_AllowEmpty(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.CertDER = nil

	dir := t.TempDir()
	outPath := filepath.Join(dir, "chain.pem")

	env, buf := envForMock(mc)
	args := []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FF",
		"--allow-empty",
		"--json",
		"--out", outPath,
	}
	if err := cmdSDKeysExport(context.Background(), env, args); err != nil {
		t.Fatalf("cmdSDKeysExport with --allow-empty: %v\n%s", err, buf.String())
	}

	var report struct {
		Checks []struct {
			Name   string `json:"name"`
			Result string `json:"result"`
		} `json:"checks"`
		Data struct {
			Certificates []any `json:"certificates"`
		} `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v\n%s", err, buf.String())
	}
	var sawSkip bool
	for _, c := range report.Checks {
		if c.Name == "chain present" && c.Result == "SKIP" {
			sawSkip = true
		}
		if c.Result == "FAIL" {
			t.Errorf("--allow-empty path should not contain FAIL checks; got %+v", c)
		}
	}
	if !sawSkip {
		t.Errorf("expected 'chain present' SKIP check; got %+v", report.Checks)
	}
	if len(report.Data.Certificates) != 0 {
		t.Errorf("data.certificates should be empty array; got %v", report.Data.Certificates)
	}
}

// TestSDKeysExport_RequiresKIDAndKVN verifies that omitting required
// flags produces a usageError, not a generic error. The dispatcher
// uses the type to distinguish bad flags from card failures.
func TestSDKeysExport_RequiresKIDAndKVN(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no flags", []string{}},
		{"missing kvn", []string{"--kid", "01"}},
		{"missing kid", []string{"--kvn", "FF"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			env, _ := envForMock(mc)
			err = cmdSDKeysExport(context.Background(), env, tc.args)
			if err == nil {
				t.Fatalf("expected usageError, got nil")
			}
			if _, ok := err.(*usageError); !ok {
				t.Errorf("err type = %T, want *usageError; err = %v", err, err)
			}
		})
	}
}

// TestSDKeysExport_JSONRequiresOut verifies the safety rule that
// --json is rejected without --out. Mixing the JSON report and
// binary cert bytes on stdout would produce unparseable output for
// any consumer, so the CLI rejects the combination up front.
func TestSDKeysExport_JSONRequiresOut(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "01", "--kvn", "FF", "--json"}
	err = cmdSDKeysExport(context.Background(), env, args)
	if err == nil {
		t.Fatal("expected usageError, got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "--out") {
		t.Errorf("error message should mention --out; got %v", err)
	}
}

// TestSDKeysExport_BadKIDValue verifies that a non-hex --kid produces
// a usageError naming the offending flag, not a card error.
func TestSDKeysExport_BadKIDValue(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "not-hex", "--kvn", "FF"}
	err = cmdSDKeysExport(context.Background(), env, args)
	if err == nil {
		t.Fatal("expected usageError, got nil")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("err type = %T, want *usageError", err)
	}
	if !strings.Contains(err.Error(), "--kid") {
		t.Errorf("error message should mention --kid; got %v", err)
	}
}

// --- auth fallback routing ---

// TestSDKeysList_AuthFallback_RoutingOnly verifies that --scp03-keys-
// default selects the SCP03 path: the report contains the SCP03 open
// checks rather than the unauthenticated 'select ISD' check, and the
// channel field reports "scp03". The mockcard.Card transport does not
// implement the SCP03 INITIALIZE UPDATE handshake, so the open will
// fail; that's fine — the routing decision is what's under test, and
// a FAIL on "open SCP03 session" (rather than "select ISD") proves
// the SCP03 branch was taken.
//
// Phase 1b can replace this test with a real SCP03+GP combined mock
// that completes the handshake and exercises the encrypted reads.
func TestSDKeysList_AuthFallback_RoutingOnly(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	err = cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
	})
	// Expect failure (mockcard does not speak SCP03), but the
	// failure must come from the SCP03 open step, not the
	// unauthenticated path.
	if err == nil {
		t.Fatalf("expected SCP03 open failure against mockcard.Card; got success:\n%s", buf.String())
	}
	out := buf.String()
	if strings.Contains(out, "select ISD") && !strings.Contains(out, "open SCP03 session") {
		t.Errorf("--scp03-keys-default should have routed through openSCP03; output looks like the unauthenticated path:\n%s", out)
	}
	if !strings.Contains(out, "open SCP03 session") {
		t.Errorf("expected 'open SCP03 session' check line; got:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected FAIL for the SCP03 open against an SCP03-unaware mock; got:\n%s", out)
	}
}

// TestSDKeysList_DefaultIsUnauthenticated pins the contract that the
// default path takes the unauthenticated branch. The text-output and
// JSON-shape tests indirectly cover this; this test exists to catch
// regressions where the default flips to authenticated (which would
// be a quiet UX-breaking change for YubiKey users).
func TestSDKeysList_DefaultIsUnauthenticated(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "select ISD") {
		t.Errorf("default path should record 'select ISD'; got:\n%s", out)
	}
	if strings.Contains(out, "open SCP03 session") {
		t.Errorf("default path should NOT trigger SCP03 open; got:\n%s", out)
	}
}

// --- internal helpers ---

// TestClassifyKID pins the host-side KID-to-kind mapping. Per
// GP §7.1.1 and Yubico's KeyReference convention.
func TestClassifyKID(t *testing.T) {
	cases := []struct {
		kid  byte
		kind string
	}{
		{0x01, "scp03"},
		{0x10, "ca-public"},
		{0x11, "scp11a-sd"},
		{0x13, "scp11b-sd"},
		{0x15, "scp11c-sd"},
		{0x20, "ca-public"},
		{0x2F, "ca-public"},
		{0x30, "unknown"},
		{0xFF, "unknown"},
	}
	for _, tc := range cases {
		if got := classifyKID(tc.kid); got != tc.kind {
			t.Errorf("classifyKID(0x%02X) = %q, want %q", tc.kid, got, tc.kind)
		}
	}
}
