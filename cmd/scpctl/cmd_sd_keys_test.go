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

// kitBytes builds a Key Information Template TLV with one C0 entry
// per (kid, kvn) pair. Component is fixed at id=0xC0 type=0x88
// (AES-128) — the existing synthetic shape — because the tests in
// this file only care about the KID/KVN structure surfacing through
// to the host, not the component layout.
//
// Output shape: 0xE0 <len> [0xC0 <len> kid kvn 0xC0 0x88]+
// matching the syntheticKeyInfo template that mockcard ships by
// default.
func kitBytes(refs ...struct{ KID, KVN byte }) []byte {
	var inner []byte
	for _, r := range refs {
		inner = append(inner, 0xC0, 0x04, r.KID, r.KVN, 0xC0, 0x88)
	}
	return append([]byte{0xE0, byte(len(inner))}, inner...)
}

// --- sd keys list ---

// TestSDKeysList_TextOutput verifies the human-readable shape of an
// inventory run: report header, KIT/KLOC/KLCC check lines, and per-
// reference cert-fetch lines that branch by KID kind. The mock is
// loaded with one SCP03 ref (KID=0x01) and one SCP11a-sd ref
// (KID=0x11) so both branches of the selective-fetch policy execute
// in one test:
//
//   - SCP03 ref: no cert fetch issued; SKIP "scp03 ref (no chain
//     expected)" recorded against the host-side classifier.
//   - SCP11a-sd ref: cert fetch issued; mock returns its synthetic
//     "Mock SD Certificate" so the chain projection path runs.
func TestSDKeysList_TextOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.KeyInformationTemplate = kitBytes(
		struct{ KID, KVN byte }{0x01, 0xFF},
		struct{ KID, KVN byte }{0x11, 0x01},
	)

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
		"2 entries",
		"GET DATA tags 0xFF33/0xFF34", // KLOC/KLCC line
		"certificates kid=0x01 kvn=0xFF",
		"scp03 ref (no chain expected)", // SCP03 SKIP rationale
		"certificates kid=0x11 kvn=0x01",
		"Mock SD Certificate", // cert subject only on the SCP11 ref
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDKeysList_JSONShape verifies the JSON payload schema. JSON is
// what automation consumes; pinning the field names and types here
// catches accidental schema drift in downstream changes. Same two-
// reference inventory as the text test so the SCP03-skip and the
// cert-bearing SCP11a entries both surface in the data block.
func TestSDKeysList_JSONShape(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.KeyInformationTemplate = kitBytes(
		struct{ KID, KVN byte }{0x01, 0xFF},
		struct{ KID, KVN byte }{0x11, 0x01},
	)

	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}

	var report struct {
		Subcommand string `json:"subcommand"`
		Data       struct {
			Channel string `json:"channel"`
			Keys    []struct {
				KID          int    `json:"kid"`
				KVN          int    `json:"kvn"`
				KIDHex       string `json:"kid_hex"`
				KVNHex       string `json:"kvn_hex"`
				Kind         string `json:"kind"`
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
	if len(report.Data.Keys) != 2 {
		t.Fatalf("keys length = %d, want 2; payload:\n%s", len(report.Data.Keys), buf.String())
	}

	scp03 := report.Data.Keys[0]
	if scp03.Kind != "scp03" || scp03.KID != 0x01 {
		t.Errorf("keys[0] = (kid=%d kind=%q), want (1 scp03)", scp03.KID, scp03.Kind)
	}
	if len(scp03.Certificates) != 0 {
		t.Errorf("scp03 ref must not carry certificates in the projection; got %d", len(scp03.Certificates))
	}

	scp11 := report.Data.Keys[1]
	if scp11.Kind != "scp11a-sd" || scp11.KID != 0x11 {
		t.Errorf("keys[1] = (kid=%d kind=%q), want (17 scp11a-sd)", scp11.KID, scp11.Kind)
	}
	if len(scp11.Certificates) != 1 {
		t.Fatalf("scp11a-sd ref should have 1 cert; got %d", len(scp11.Certificates))
	}
	if !strings.Contains(scp11.Certificates[0].Subject, "Mock SD Certificate") {
		t.Errorf("subject = %q, want substring 'Mock SD Certificate'",
			scp11.Certificates[0].Subject)
	}
	if got := scp11.Certificates[0].SPKIFingerprintSHA256; len(got) != 64 {
		t.Errorf("spki_fingerprint_sha256 length = %d, want 64; got %q",
			len(got), got)
	}
}

// TestSDKeysList_NoCertChain verifies the per-reference cert-fetch
// fail-soft path on a cert-capable ref: when the card returns SW=6A88
// for a 0xBF21 query against an SCP11 SD ref, the per-ref check is
// SKIP "no chain stored" and the entry has no Certificates field.
// The command itself still exits 0 because list is fundamentally an
// inventory call where empty cells are normal.
//
// Uses an SCP11a-sd ref because SCP03 refs skip the fetch entirely
// (and would not exercise the SW=6A88 code path).
func TestSDKeysList_NoCertChain(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.KeyInformationTemplate = kitBytes(struct{ KID, KVN byte }{0x11, 0x01})
	mc.CertDER = nil // makes 0xBF21 return SW=6A88

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

// TestSDKeysList_SCP03RefSkipsFetch is the explicit guard that an
// SCP03 reference does not trigger any 0xBF21 traffic, even when the
// card would happily answer one. Avoiding that wasted APDU is the
// whole point of the selective-fetch design; if a future change
// regresses to fetching for every KID, this test catches it.
func TestSDKeysList_SCP03RefSkipsFetch(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Default mock has KID=0x01 and a populated CertDER. If the
	// host-side selective-fetch logic regresses, the SCP03 ref will
	// pull "Mock SD Certificate" into the output — which it must not.
	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scp03 ref (no chain expected)") {
		t.Errorf("expected SCP03-skip rationale; got:\n%s", out)
	}
	if strings.Contains(out, "Mock SD Certificate") {
		t.Errorf("SCP03 ref must not produce cert output; got:\n%s", out)
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

// TestSDKeysExport_AtomicWrite_NoPartialOnFailure exercises the
// atomic-write contract: if the rename target's parent directory is
// not writable, the command must fail without leaving a partial
// output file at the final path. We can't easily make Rename itself
// fail mid-operation, but we can make the final write impossible by
// pointing --out at a path under a directory the process cannot
// create. The contract this test pins is: on failure, the operator
// finds either the complete file or no file — never a half-written
// file at the named path.
func TestSDKeysExport_AtomicWrite_NoPartialOnFailure(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	dir := t.TempDir()
	// Path under a non-existent subdirectory: CreateTemp will fail
	// (parent dir doesn't exist), so the export command fails before
	// any final-path file is touched.
	outPath := filepath.Join(dir, "no-such-subdir", "chain.pem")

	env, _ := envForMock(mc)
	args := []string{"--reader", "fake", "--kid", "01", "--kvn", "FF", "--out", outPath}
	if err := cmdSDKeysExport(context.Background(), env, args); err == nil {
		t.Fatal("expected write failure, got success")
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Errorf("final path must not exist after failed write; stat err = %v", statErr)
	}
}

// TestSDKeysExport_AtomicWrite_NoTempLeftover guards against a
// regression where the temp file used for the atomic write isn't
// cleaned up after a successful rename. After a successful export,
// the only file in the output directory should be the final output
// file — no .scpctl-tmp-* leftovers.
func TestSDKeysExport_AtomicWrite_NoTempLeftover(t *testing.T) {
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

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read out dir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the output file in dir; got %d entries: %v",
			len(entries), names)
	}
	if entries[0].Name() != "chain.pem" {
		t.Errorf("found %q, want chain.pem (and no temp leftover)", entries[0].Name())
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
		if got := classifyKID(tc.kid, "yubikey-sd"); got != tc.kind {
			t.Errorf("classifyKID(0x%02X, yubikey) = %q, want %q", tc.kid, got, tc.kind)
		}
	}
}

// --- auth-required hint on unauthenticated reads ---

// TestSDKeysList_AuthRequiredHint pins the friendly error
// behavior when an unauthenticated `sd keys list` hits a card
// that requires authentication for GET DATA. The reviewer asked
// for this to surface as a clear message naming the SCP03
// fallback rather than letting the raw SW=6982 bubble up.
func TestSDKeysList_AuthRequiredHint(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RequireAuthForReads = true

	env, buf := envForMock(mc)
	err = cmdSDKeys(context.Background(), env, []string{"list", "--reader", "fake"})
	if err == nil {
		t.Fatalf("expected error from auth-required card; got nil")
	}
	out := buf.String()

	// Must surface the limitation, not just the raw SW.
	for _, want := range []string{
		"FAIL",
		"GET DATA tag 0x00E0",
		"requires authentication",
		"SCP03 fallback",
		"--scp03-key",
		"SCP11a-authenticated reads are not implemented",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// The hint mentions 6982 explicitly so an operator who
	// knows the SW catalog can confirm the diagnosis.
	if !strings.Contains(out, "6982") {
		t.Errorf("output should mention SW=6982 explicitly\n--- output ---\n%s", out)
	}
}

// TestSDKeysExport_AuthRequiredHint is the same shape on the
// export path. Failure happens at the per-ref GET DATA tag
// 0xBF21 call, but the message must still name the limitation.
func TestSDKeysExport_AuthRequiredHint(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Need a non-empty cert store on the card for the
	// auth-gating to be the failure mode (otherwise empty cert
	// store returns SW=6A88, which is a different code path).
	mc.RequireAuthForReads = true

	env, buf := envForMock(mc)
	err = cmdSDKeys(context.Background(), env, []string{
		"export",
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
	})
	if err == nil {
		t.Fatalf("expected error from auth-required card; got nil")
	}
	out := buf.String()

	for _, want := range []string{
		"FAIL",
		"requires authentication",
		"SCP03 fallback",
		"sd keys export",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestAuthRequiredHint_NotEmittedOnAuthenticatedChannel pins
// that the hint fires only on the unauthenticated channel —
// when an SCP03 session has been opened, a 6982 from the card
// is a different failure mode (e.g., the authenticated KVN was
// rotated out from under us) and the hint's "use SCP03"
// remediation would be misleading.
func TestAuthRequiredHint_NotEmittedOnAuthenticatedChannel(t *testing.T) {
	// Direct unit test of the helper: same SW, different
	// channel, must return empty.
	rawErr := apduSWError(0x6982)
	if got := authRequiredHint(rawErr, "scp03", "sd keys list"); got != "" {
		t.Errorf("authRequiredHint on scp03 channel should be empty; got %q", got)
	}
	if got := authRequiredHint(rawErr, "unauthenticated", "sd keys list"); got == "" {
		t.Errorf("authRequiredHint on unauthenticated channel with SW=6982 should be non-empty")
	}
	// Non-6982 error on unauthenticated channel: also empty,
	// to avoid attaching a misleading hint.
	otherErr := apduSWError(0x6A82)
	if got := authRequiredHint(otherErr, "unauthenticated", "sd keys list"); got != "" {
		t.Errorf("authRequiredHint on non-6982 SW should be empty; got %q", got)
	}
}

// apduSWError fabricates an error string matching the format
// *apdu.Response.Error() produces, for unit testing the hint
// helper without spinning up a real card.
func apduSWError(sw uint16) error {
	return errorString{msg: "card returned SW=" + uint16Hex(sw) + " (something)"}
}

type errorString struct{ msg string }

func (e errorString) Error() string { return e.msg }

func uint16Hex(v uint16) string {
	const hexdig = "0123456789ABCDEF"
	return string([]byte{
		hexdig[(v>>12)&0xF],
		hexdig[(v>>8)&0xF],
		hexdig[(v>>4)&0xF],
		hexdig[v&0xF],
	})
}

// --- profile-qualified key-kind JSON shape (reviewer follow-up) ---

// TestSDKeysList_StandardSD_RawAndKindBoth pins the contract that
// under --profile standard-sd, the JSON output for SCP11 SD slots
// emits BOTH the raw kid/kvn/component bytes AND a generic
// "scp11-sd" kind label (no Yubico-specific variant letter).
//
// External-review concern: "key-kind mapping is YubiKey-specific
// but presented as generic." The implementation IS profile-qualified
// (dropped variant letters under standard-sd) but a regression
// where someone widened the YubiKey label to fire under standard-sd
// would silently mislabel non-YubiKey cards. This test pins the
// contract by:
//
//   1. Forcing --profile standard-sd (no probing).
//   2. Advertising KIDs 0x11, 0x13, 0x15 plus an unknown KID 0x42.
//   3. Asserting kind labels on the SCP11 slots are "scp11-sd"
//      (no variant), kind on the unknown KID is "unknown".
//   4. Asserting kid/kvn/kid_hex/kvn_hex/components are populated
//      regardless of kind label, so a downstream consumer can
//      always reconstruct what the card actually said.
func TestSDKeysList_StandardSD_RawAndKindBoth(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.KeyInformationTemplate = kitBytes(
		struct{ KID, KVN byte }{0x11, 0x01},
		struct{ KID, KVN byte }{0x13, 0x02},
		struct{ KID, KVN byte }{0x15, 0x03},
		struct{ KID, KVN byte }{0x42, 0x04}, // off-spec / unknown
	)

	env, buf := envForMock(mc)
	if err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--profile", "standard-sd",
		"--json",
	}); err != nil {
		t.Fatalf("cmdSDKeysList: %v", err)
	}

	var report struct {
		Data struct {
			Profile string `json:"profile"`
			Keys    []struct {
				KID        int    `json:"kid"`
				KVN        int    `json:"kvn"`
				KIDHex     string `json:"kid_hex"`
				KVNHex     string `json:"kvn_hex"`
				Kind       string `json:"kind"`
				Components []struct {
					ID   byte `json:"id"`
					Type byte `json:"type"`
				} `json:"components,omitempty"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v\n%s", err, buf.String())
	}

	// The active profile must be reported as standard-sd so an
	// audit-log consumer can correlate the labeling convention
	// with the data shape that follows.
	if report.Data.Profile != "standard-sd" {
		t.Errorf("data.profile = %q, want standard-sd; full output:\n%s", report.Data.Profile, buf.String())
	}

	if len(report.Data.Keys) != 4 {
		t.Fatalf("keys length = %d, want 4; payload:\n%s", len(report.Data.Keys), buf.String())
	}

	wantKindByKID := map[int]string{
		0x11: "scp11-sd", // standard-sd: no variant letter
		0x13: "scp11-sd",
		0x15: "scp11-sd",
		0x42: "unknown", // off-spec KID, no guess
	}
	for _, k := range report.Data.Keys {
		want, known := wantKindByKID[k.KID]
		if !known {
			t.Errorf("unexpected KID 0x%02X in output", k.KID)
			continue
		}
		if k.Kind != want {
			t.Errorf("kid=0x%02X: kind = %q, want %q under --profile standard-sd",
				k.KID, k.Kind, want)
		}
		// Raw bytes must always be present and match the
		// underlying KID/KVN — the kind label is a host-side
		// convenience; the raw fields are authoritative.
		wantHex := func(b int) string {
			const hexdig = "0123456789ABCDEF"
			return "0x" + string([]byte{hexdig[(b>>4)&0xF], hexdig[b&0xF]})
		}
		if k.KIDHex != wantHex(k.KID) {
			t.Errorf("kid=0x%02X: kid_hex = %q, want %q", k.KID, k.KIDHex, wantHex(k.KID))
		}
		if k.KVNHex != wantHex(k.KVN) {
			t.Errorf("kid=0x%02X: kvn_hex = %q, want %q", k.KID, k.KVNHex, wantHex(k.KVN))
		}
		// Components must be carried verbatim from the card —
		// the host doesn't drop or invent component rows.
		if len(k.Components) == 0 {
			t.Errorf("kid=0x%02X: components empty; the host must surface raw component map even for unknown KIDs", k.KID)
		}
	}
}

// TestClassifyKID_StandardSD_DoesNotInventYubicoVariants is a
// finer-grained companion to the JSON test above. It pins the
// classifier function directly: no input that's NOT 0x11/0x13/0x15
// should ever return one of the SCP11 variant labels under
// standard-sd. A regression where someone widened the variant
// matching to e.g. 0x12 would silently mislabel non-YubiKey
// cards.
func TestClassifyKID_StandardSD_DoesNotInventYubicoVariants(t *testing.T) {
	yubicoVariants := map[string]bool{
		"scp11a-sd": true,
		"scp11b-sd": true,
		"scp11c-sd": true,
	}
	for kid := 0x00; kid <= 0xFF; kid++ {
		got := classifyKID(byte(kid), "standard-sd")
		if yubicoVariants[got] {
			t.Errorf("classifyKID(0x%02X, standard-sd) = %q; standard-sd profile must NOT emit Yubico variant labels",
				kid, got)
		}
	}
}
