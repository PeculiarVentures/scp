package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestGPProbe_TextOutput exercises 'gp probe' against a mockcard that
// returns a populated CRD. Confirms the report label is 'gp probe'
// (distinct from the historical 'probe') and the same probe checks
// run successfully.
func TestGPProbe_TextOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	out := runGPProbe(t, mc, []string{"--reader", "fake"})

	for _, want := range []string{
		"scpctl gp probe",
		"PASS",
		"select ISD",
		"GET DATA tag 0x66",
		"parse CRD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Distinct from the legacy top-level command's label so an
	// operator running 'gp probe' sees gp-tagged output even if
	// the implementation is shared with cmdProbe.
	if !strings.Contains(out, "scpctl gp probe") {
		t.Errorf("output should be tagged 'scpctl gp probe', not 'scpctl probe'\n--- output ---\n%s", out)
	}
}

// TestGPProbe_JSONOutput confirms the JSON report carries
// subcommand="gp probe" and the same probeData fields the legacy
// command produces.
func TestGPProbe_JSONOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	out := runGPProbe(t, mc, []string{"--reader", "fake", "--json"})

	var report struct {
		Subcommand string `json:"subcommand"`
		Reader     string `json:"reader"`
		Data       struct {
			SCPVersion string `json:"scp_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal JSON: %v\n--- output ---\n%s", err, out)
	}
	if report.Subcommand != "gp probe" {
		t.Errorf("Subcommand = %q, want %q", report.Subcommand, "gp probe")
	}
	if report.Data.SCPVersion == "" {
		t.Error("data.scp_version is empty; mockcard CRD should populate it")
	}
}

// TestGPProbe_NoFullFlag confirms 'gp probe' does NOT expose --full
// (the GP registry walk lives behind 'gp registry' instead, just as
// the legacy split keeps --full on 'sd info' rather than top-level
// 'probe'). Regression guard so a future change cannot accidentally
// add --full to gp probe and create a parallel surface.
func TestGPProbe_NoFullFlag(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	err = cmdGPProbe(context.Background(), env, []string{"--reader", "fake", "--full"})
	if err == nil {
		t.Fatal("expected error for --full on 'gp probe'; got nil")
	}
	// The flag package's "flag provided but not defined" error is
	// what fires here; confirm the unknown flag is the cause.
	if !strings.Contains(err.Error(), "full") {
		t.Errorf("error should reference unknown --full flag; got %v", err)
	}
}

func runGPProbe(t *testing.T, mc *mockcard.Card, args []string) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdGPProbe(context.Background(), env, args); err != nil {
		t.Fatalf("cmdGPProbe: %v", err)
	}
	return buf.String()
}

// TestGPProbe_CPLCSurfacedInJSON confirms that the optional GET DATA
// reads added in PR #(probe-expansion) populate the CPLC field of
// the JSON output when the mock card advertises CPLC. The mockcard
// returns YubiKey-shape CPLC bytes (CPLC present at tag 9F7F, but
// post-fabrication date fields contain random per-card serial bytes
// that don't decode as valid BCD). The parser must succeed and
// surface ICFabricator/ICType/serial; date fields render as "raw".
//
// Pins regression: pre-fix the probe didn't read 9F7F at all and
// the JSON had no cplc field. Post-fix, every probe (including the
// gp probe variant) populates it.
func TestGPProbe_CPLCSurfacedInJSON(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	out := runGPProbe(t, mc, []string{"--reader", "fake", "--json"})

	type cplcView struct {
		ICFabricator      string `json:"ic_fabricator"`
		ICSerialNumber    string `json:"ic_serial_number"`
		ICFabricationDate string `json:"ic_fabrication_date"`
	}
	type probeData struct {
		CPLC *cplcView `json:"cplc"`
		IIN  string    `json:"iin"`
		CIN  string    `json:"cin"`
	}
	var report struct {
		Data probeData `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal JSON: %v\n--- output ---\n%s", err, out)
	}

	if report.Data.CPLC == nil {
		t.Fatalf("data.cplc should be populated when card advertises 9F7F; got nil\n--- output ---\n%s", out)
	}
	if report.Data.CPLC.ICFabricator != "4090" {
		t.Errorf("CPLC.ICFabricator = %q, want %q (mockcard fixture)", report.Data.CPLC.ICFabricator, "4090")
	}
	// YubiKey-shape CPLC has random bytes in date fields so they
	// surface as "{raw} (raw)" rather than YYYY-MM-DD. Confirms the
	// parser's tolerance fed through to the report layer.
	if !strings.Contains(report.Data.CPLC.ICFabricationDate, "(raw)") {
		t.Errorf("CPLC.ICFabricationDate should report raw bytes for the YubiKey-shape mock; got %q",
			report.Data.CPLC.ICFabricationDate)
	}

	// IIN/CIN aren't present on YubiKey-shape mock (default 6A88
	// case in doGetData). Confirm omitted from JSON via the
	// json:"omitempty" tag.
	if report.Data.IIN != "" {
		t.Errorf("data.iin should be empty when card returns 6A88; got %q", report.Data.IIN)
	}
	if report.Data.CIN != "" {
		t.Errorf("data.cin should be empty when card returns 6A88; got %q", report.Data.CIN)
	}
}

// TestGPProbe_CardCapabilitiesStructured exercises the structured
// Card Capability Information decode path end-to-end against a
// mockcard configured with the real-card SafeNet Token JC bytes.
// Pre-fix the probe surfaced only raw hex; post-fix the JSON
// includes a card_capabilities_parsed field with named SCP entries
// and decoded hash algorithms. The structured fixture matches what
// gppro v25.10.20 produces against the same bytes.
func TestGPProbe_CardCapabilitiesStructured(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Inject SafeNet Token JC's Card Capabilities response. The
	// hex matches the fixture pinned in gp/cardcaps.
	cc, err := hex.DecodeString("673E673C" +
		"A00780010181020515" +
		"A009800102810405154555" +
		"A00A80010381020010820107" +
		"8103FFFE80" +
		"82031E0600" +
		"830401020304" +
		"85023B00" +
		"86023C00" +
		"87023F00")
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	mc.CardCapabilitiesData = cc

	out := runGPProbe(t, mc, []string{"--reader", "fake", "--json"})

	type scpEntry struct {
		Version  string   `json:"version"`
		IValues  []string `json:"i_values"`
		KeySizes []string `json:"key_sizes"`
	}
	type capsView struct {
		SCPEntries     []scpEntry `json:"scp_entries"`
		HashAlgorithms []string   `json:"hash_algorithms"`
	}
	type probeData struct {
		CardCapabilitiesParsed *capsView `json:"card_capabilities_parsed"`
		CardCapabilities       string    `json:"card_capabilities"`
	}
	var report struct {
		Data probeData `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal JSON: %v\n--- output ---\n%s", err, out)
	}

	// Raw hex must still appear (parser-success path keeps both).
	if report.Data.CardCapabilities == "" {
		t.Errorf("card_capabilities raw hex should be populated; got empty\n%s", out)
	}

	if report.Data.CardCapabilitiesParsed == nil {
		t.Fatalf("card_capabilities_parsed should be populated; got nil\n%s", out)
	}

	scps := report.Data.CardCapabilitiesParsed.SCPEntries
	if len(scps) != 3 {
		t.Fatalf("expected 3 SCP entries; got %d", len(scps))
	}
	if scps[0].Version != "SCP01" {
		t.Errorf("scps[0].Version = %q, want SCP01", scps[0].Version)
	}
	if scps[2].Version != "SCP03" {
		t.Errorf("scps[2].Version = %q, want SCP03", scps[2].Version)
	}
	wantSCP03Sizes := []string{"AES-128", "AES-192", "AES-256"}
	if !equalStrSlice(scps[2].KeySizes, wantSCP03Sizes) {
		t.Errorf("SCP03 key sizes = %v, want %v", scps[2].KeySizes, wantSCP03Sizes)
	}
	wantHashes := []string{"SHA-1", "SHA-256", "SHA-384", "SHA-512"}
	if !equalStrSlice(report.Data.CardCapabilitiesParsed.HashAlgorithms, wantHashes) {
		t.Errorf("hash algorithms = %v, want %v",
			report.Data.CardCapabilitiesParsed.HashAlgorithms, wantHashes)
	}
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
