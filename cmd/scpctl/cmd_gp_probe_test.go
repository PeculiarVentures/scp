package main

import (
	"bytes"
	"context"
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
