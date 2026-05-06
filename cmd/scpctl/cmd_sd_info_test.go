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

// TestSDInfo_Full_TextOutput populates the mock card's GP registry
// across all three scopes and verifies the human-readable output
// from 'sd info --full'.
func TestSDInfo_Full_TextOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle:  0x0F,
			Privileges: [3]byte{0xC0, 0x00, 0x00},
		},
	}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00},
			Lifecycle:  0x07,
			Privileges: [3]byte{0x00, 0x00, 0x00},
		},
	}
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{
		{
			AID:       []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01},
			Lifecycle: 0x01,
			Version:   []byte{0x01, 0x02},
		},
	}
	out := runSDInfoFull(t, mc)

	for _, want := range []string{
		"scpctl sd info",
		"PASS",
		"GET STATUS scope=ISD",
		"1 entries",
		"A000000151000000",
		"GET STATUS scope=Applications",
		"GET STATUS scope=LoadFiles",
		"A0000006472F0001",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDInfo_Full_JSONOutput verifies the JSON shape of --full output:
// each scope under data.registry as a structured array.
func TestSDInfo_Full_JSONOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle:  0x0F,
			Privileges: [3]byte{0xC0, 0x00, 0x00},
		},
	}
	out := runSDInfoFullJSON(t, mc)

	var report struct {
		Data struct {
			Registry struct {
				ISD []struct {
					AID           string   `json:"aid"`
					Lifecycle     string   `json:"lifecycle"`
					LifecycleByte string   `json:"lifecycle_byte"`
					Privileges    []string `json:"privileges"`
				} `json:"isd"`
			} `json:"registry"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("JSON decode: %v\n--- output ---\n%s", err, out)
	}
	if got := len(report.Data.Registry.ISD); got != 1 {
		t.Fatalf("registry.isd count = %d, want 1\n--- output ---\n%s", got, out)
	}
	isd := report.Data.Registry.ISD[0]
	if isd.AID != "A000000151000000" {
		t.Errorf("isd[0].aid = %q, want A000000151000000", isd.AID)
	}
	if isd.Lifecycle != "SECURED" {
		t.Errorf("isd[0].lifecycle = %q, want SECURED", isd.Lifecycle)
	}
	if isd.LifecycleByte != "0x0F" {
		t.Errorf("isd[0].lifecycle_byte = %q, want 0x0F", isd.LifecycleByte)
	}
	wantPrivs := map[string]bool{"SecurityDomain": true, "DAPVerification": true}
	for _, p := range isd.Privileges {
		if !wantPrivs[p] {
			t.Errorf("isd[0].privileges contains unexpected %q", p)
		}
		delete(wantPrivs, p)
	}
	if len(wantPrivs) > 0 {
		t.Errorf("isd[0].privileges missing %v", wantPrivs)
	}
}

// TestSDInfo_Full_EmptyRegistry verifies that scopes with no entries
// (mock returns SW=6A88) are reported as "no entries" PASS lines, not
// failures.
func TestSDInfo_Full_EmptyRegistry(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Leave all three registry slices empty; mockcard returns
	// SW=6A88 for each scope.
	out := runSDInfoFull(t, mc)
	for _, want := range []string{
		"GET STATUS scope=ISD",
		"GET STATUS scope=Applications",
		"GET STATUS scope=LoadFiles",
		"no entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDInfo_NoFull_NoRegistryFields confirms that without --full,
// no GET STATUS calls are issued and no registry block appears in
// either text or JSON output. This pins the surface so 'sd info'
// without --full stays the lightweight unauthenticated probe it has
// always been.
func TestSDInfo_NoFull_NoRegistryFields(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, Lifecycle: 0x0F},
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "registry") || strings.Contains(out, "GET STATUS") {
		t.Errorf("sd info without --full should not mention the registry; got:\n%s", out)
	}
}

// runSDInfoFull invokes 'sd info --full' against a mock card and
// returns the captured stdout. Used by tests that need to assert on
// human-readable output.
func runSDInfoFull(t *testing.T, mc *mockcard.Card) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--full"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	return buf.String()
}

// runSDInfoFullJSON invokes 'sd info --full --json' and returns the
// captured stdout, expected to be a JSON object.
func runSDInfoFullJSON(t *testing.T, mc *mockcard.Card) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--full", "--json"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	return buf.String()
}
