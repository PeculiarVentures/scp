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

// TestPIVInfo_MockFallsThroughToStandardPIV exercises the happy path
// against the in-tree mockcard. The mock's INS=0xFD handler echoes
// the request payload, so GET VERSION returns 9000 with zero bytes
// of data, which the probe interprets (correctly) as "not a YubiKey"
// and falls through to the Standard PIV profile. This is the right
// safe-default behavior for an unidentified card.
//
// To exercise the YubiKey path without a real card, see the
// piv/profile package tests, which use a fake transmitter that
// returns a 3-byte version blob.
func TestPIVInfo_MockFallsThroughToStandardPIV_TextOutput(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return card.Transport(), nil
		},
	}

	if err := cmdPIVInfo(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdPIVInfo: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"scpctl piv info",
		"PASS",
		// Probe falls through to standard-piv on the mock.
		"standard-piv",
		// Capabilities the Standard PIV profile claims.
		"alg:RSA-2048",
		"alg:ECC P-256",
		"alg:ECC P-384",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("piv info output missing %q\n--- output ---\n%s", want, out)
		}
	}

	// And capabilities the Standard PIV profile must NOT claim.
	for _, mustNot := range []string{
		"reset",
		"attestation",
		"scp11b-piv",
		"key-import",
		"pin-policy",
		"touch-policy",
	} {
		if strings.Contains(out, mustNot) {
			t.Errorf("piv info output should not include %q under Standard PIV\n--- output ---\n%s",
				mustNot, out)
		}
	}
}

// TestPIVInfo_MockFallsThroughToStandardPIV_JSONOutput exercises
// --json against the same mock setup.
func TestPIVInfo_MockFallsThroughToStandardPIV_JSONOutput(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return card.Transport(), nil
		},
	}

	if err := cmdPIVInfo(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdPIVInfo: %v", err)
	}

	var got struct {
		Subcommand string `json:"subcommand"`
		Data       struct {
			Profile        string   `json:"profile"`
			YubiKeyVersion string   `json:"yubikey_version"`
			Capabilities   []string `json:"capabilities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON parse failed: %v\noutput:\n%s", err, buf.String())
	}

	if got.Subcommand != "piv info" {
		t.Errorf("subcommand = %q, want 'piv info'", got.Subcommand)
	}
	// Mock falls through to standard-piv, wrapped in the probed
	// prefix.
	if !strings.Contains(got.Data.Profile, "standard-piv") {
		t.Errorf("profile = %q, want it to contain 'standard-piv'", got.Data.Profile)
	}
	if got.Data.YubiKeyVersion != "" {
		t.Errorf("yubikey_version should be empty for non-YubiKey card, got %q",
			got.Data.YubiKeyVersion)
	}
	if len(got.Data.Capabilities) == 0 {
		t.Error("capabilities should not be empty")
	}

	// Standard PIV must include 'standard-piv' in the capability
	// list (its self-identifying flag) and must not include
	// YubiKey-only capabilities.
	hasStandardPIV := false
	for _, c := range got.Data.Capabilities {
		if c == "standard-piv" {
			hasStandardPIV = true
		}
		if c == "reset" || c == "attestation" || c == "scp11b-piv" {
			t.Errorf("standard-piv profile should not advertise %q", c)
		}
	}
	if !hasStandardPIV {
		t.Errorf("capabilities should include 'standard-piv', got %v",
			got.Data.Capabilities)
	}
}
