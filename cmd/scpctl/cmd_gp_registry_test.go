package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// scp03.MockCard authenticates the SCP03 handshake but does not have
// a GET STATUS handler — it returns SW=6D00 ("instruction not
// supported") for INS 0xF2. mockcard.Card has the GET STATUS handler
// but does not speak SCP03. There is no fixture today that combines
// SCP03 secure messaging with a populated GP registry simulator.
//
// The tests below exercise the authenticated-plumbing path against
// scp03.MockCard: the handshake succeeds, walkRegistry issues GET
// STATUS for each scope, the card returns 6D00, and walkRegistry
// records SKIP per scope. This validates that the command:
//
//   - Parses SCP03 key flags correctly.
//   - Opens an authenticated SCP03 session.
//   - Walks all three scopes without short-circuiting on the first
//     unsupported-INS response.
//   - Renders SKIP without surfacing a FAIL (skipped scopes are
//     not failures, they're absences).
//   - Emits the report under the 'gp registry' subcommand label.
//
// Full end-to-end registry-content validation requires either a
// real card or a SCP03+GP combined simulator. Both are tracked as
// future work outside the MVP main body.

// TestGPRegistry_AuthSuccess_PlumbingPath confirms gp registry works
// end-to-end through OpenSCP03 + walkRegistry against a SCP03 mock,
// even though the mock has no registry data to return. The walk
// records SKIP per scope (SW=6D00); SKIP is not FAIL so the command
// returns nil.
func TestGPRegistry_AuthSuccess_PlumbingPath(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	out := runGPRegistry(t, mock, []string{"--reader", "fake", "--scp03-keys-default"})

	for _, want := range []string{
		"scpctl gp registry",
		"open SCP03 SD",
		"GET STATUS scope=ISD",
		"GET STATUS scope=Applications",
		"GET STATUS scope=LoadFiles",
		"PASS",
		"SKIP",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// SKIPs should not promote to FAILs. A FAIL line in the output
	// would mean walkRegistry mis-classified an unsupported-INS
	// response as a hard error.
	if strings.Contains(out, "FAIL") {
		t.Errorf("FAIL appeared in output for skipped scopes\n--- output ---\n%s", out)
	}
}

// TestGPRegistry_JSONShape_NoRegistryWhenAllSkipped verifies that
// when every scope returns an error/skip, the JSON omits the
// `registry` field rather than emitting an empty object. Avoids
// confusing consumers who'd otherwise see `data.registry: {}` and
// have to guess whether that means "no entries" or "not walked."
func TestGPRegistry_JSONShape_NoRegistryWhenAllSkipped(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	out := runGPRegistry(t, mock, []string{"--reader", "fake", "--json", "--scp03-keys-default"})

	var report struct {
		Subcommand string `json:"subcommand"`
		Data       struct {
			Protocol string                 `json:"protocol"`
			Registry map[string]interface{} `json:"registry,omitempty"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal JSON: %v\n--- output ---\n%s", err, out)
	}
	if report.Subcommand != "gp registry" {
		t.Errorf("Subcommand = %q, want %q", report.Subcommand, "gp registry")
	}
	if !strings.HasPrefix(report.Data.Protocol, "SCP03") {
		t.Errorf("Protocol = %q, want SCP03 prefix", report.Data.Protocol)
	}
	if report.Data.Registry != nil {
		t.Errorf("Registry should be omitted when all scopes skipped; got %v",
			report.Data.Registry)
	}
}

// TestGPRegistry_AuthFailure_PropagatesError confirms that an SCP03
// authentication failure surfaces as a FAIL in the report and a
// returned error rather than a silent success. Defends against a
// future refactor that loses the FAIL-becomes-error wiring.
func TestGPRegistry_AuthFailure_PropagatesError(t *testing.T) {
	// Mock expecting factory keys; we authenticate with all-DE's,
	// so INITIALIZE UPDATE's MAC check fails on the host side.
	mock := scp03.NewMockCard(scp03.DefaultKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-key", strings.Repeat("DE", 16),
	})
	if err == nil {
		t.Fatal("expected auth-failure error, got nil")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("expected FAIL line in output\n--- output ---\n%s", buf.String())
	}
}

// TestGPRegistry_CustomKeysViaShorthand confirms that the new
// --scp03-key shorthand introduced earlier in this branch is
// exercised by gp registry: open SCP03 with custom keys via the
// single-key form, then walk (which SKIPs because of the mock
// limitation noted above).
func TestGPRegistry_CustomKeysViaShorthand(t *testing.T) {
	keyHex := strings.Repeat("AB", 16)
	keyBytes, _ := hex.DecodeString(keyHex)
	customKeys := scp03.StaticKeys{
		ENC: keyBytes, MAC: keyBytes, DEK: keyBytes,
	}
	mock := scp03.NewMockCard(customKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	if err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-key", keyHex,
	}); err != nil {
		t.Fatalf("cmdGPRegistry: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "custom (KVN 0x01, AES-128)") {
		t.Errorf("expected describeKeys to report custom AES-128\n--- output ---\n%s", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("unexpected FAIL\n--- output ---\n%s", out)
	}
}

// runGPRegistry invokes cmdGPRegistry against the supplied SCP03
// mock and returns captured output. Errors from the command are
// returned to the caller via t.Fatalf so tests don't accidentally
// silence them.
func runGPRegistry(t *testing.T, mock *scp03.MockCard, args []string) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	if err := cmdGPRegistry(context.Background(), env, args); err != nil {
		t.Fatalf("cmdGPRegistry: %v\n--- output ---\n%s", err, buf.String())
	}
	return buf.String()
}

// TestGPRegistry_RequiresExplicitKeyChoice confirms gp registry
// refuses to fall through to the YubiKey factory SCP03 keys
// implicitly, unlike the legacy YubiKey-flavored commands. The
// gp group's audience may be running a non-YubiKey GP card where
// the public 404142...4F factory keys are meaningless, and
// silently trying them is operator-hygiene surprising.
//
// Acceptable invocations (explicit) include: --scp03-keys-default,
// --scp03-key with --scp03-kvn, or split --scp03-{enc,mac,dek}
// with --scp03-kvn. This test verifies the bare invocation that
// previous commands accepted is now a usage error.
func TestGPRegistry_RequiresExplicitKeyChoice(t *testing.T) {
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			t.Fatal("connect should not be reached when key choice is missing")
			return nil, nil
		},
	}
	err := cmdGPRegistry(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected usage error for missing SCP03 key choice")
	}
	var ue *usageError
	if !errorsAs(err, &ue) {
		t.Fatalf("expected *usageError, got %T: %v", err, err)
	}
	if !strings.Contains(ue.msg, "--scp03-keys-default") ||
		!strings.Contains(ue.msg, "--scp03-key") {
		t.Errorf("usage error should name the explicit options; got %q", ue.msg)
	}
}

// TestGPRegistry_JSONShape_LoadFilesScopeFallback covers the
// requested vs actual scope reporting. The brief flagged that
// operators couldn't tell from JSON when the LoadFilesAndModules
// fallback fired — only the human report's "modules omitted"
// note hinted at it. JSON consumers driving registry assertions
// across mixed deployments need to detect when module
// enumeration is unavailable so they don't incorrectly assert
// module presence on cards that returned LoadFiles-only.
//
// This is a JSON-shape test on registryDump itself: marshal a
// dump with mismatched scope fields, round-trip through JSON,
// assert both fields appear with the expected names. Tests the
// schema contract operators rely on.
func TestGPRegistry_JSONShape_LoadFilesScopeFallback(t *testing.T) {
	dump := &registryDump{
		LoadFiles:               []registryEntryView{},
		LoadFilesRequestedScope: "load_files_and_modules",
		LoadFilesActualScope:    "load_files",
	}
	b, err := json.Marshal(dump)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{
		"load_files_requested_scope": "load_files_and_modules",
		"load_files_actual_scope":    "load_files",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("JSON field %q = %v, want %q", k, got[k], v)
		}
	}
}

// TestGPRegistry_JSONShape_LoadFilesScopeOmittedWhenSame: the
// scope fields use omitempty so an unfired registry walk doesn't
// pollute the JSON with empty strings. When requested == actual
// (no fallback), consumers shouldn't see the fields at all.
func TestGPRegistry_JSONShape_LoadFilesScopeOmittedWhenSame(t *testing.T) {
	dump := &registryDump{
		LoadFiles: []registryEntryView{},
		// scope fields left zero — equivalent to "scope was never set"
	}
	b, err := json.Marshal(dump)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "load_files_requested_scope") ||
		strings.Contains(s, "load_files_actual_scope") {
		t.Errorf("scope fields should be omitted when empty; got: %s", s)
	}
}

// TestScopeName covers the StatusScope -> JSON-friendly string
// mapping. Operators reading the JSON expect the same vocabulary
// as GP §11.4.2; an unrecognized scope should produce a
// readable hex form rather than panic or empty string.
func TestScopeName(t *testing.T) {
	cases := []struct {
		scope securitydomain.StatusScope
		want  string
	}{
		{securitydomain.StatusScopeISD, "isd"},
		{securitydomain.StatusScopeApplications, "applications"},
		{securitydomain.StatusScopeLoadFiles, "load_files"},
		{securitydomain.StatusScopeLoadFilesAndModules, "load_files_and_modules"},
		{securitydomain.StatusScope(0xFE), "unknown_0xFE"},
	}
	for _, tc := range cases {
		if got := scopeName(tc.scope); got != tc.want {
			t.Errorf("scopeName(0x%02X) = %q, want %q", byte(tc.scope), got, tc.want)
		}
	}
}
