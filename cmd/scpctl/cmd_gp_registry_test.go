package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
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
	out := runGPRegistry(t, mock, []string{"--reader", "fake"})

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
	out := runGPRegistry(t, mock, []string{"--reader", "fake", "--json"})

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
