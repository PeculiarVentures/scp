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

// TestPIVInfo_ROCANote_Emitted_OnAffectedFirmware: a 4.3.1 YubiKey
// (inside the ROCA-affected range 4.2.6 through 4.3.4 inclusive)
// must produce a ROCA disclosure in the 'note' lines of `piv info`
// output. The disclosure must be precise: RSA generated on-card
// is affected, ECC and imported RSA are not. This was the
// motivating gap for the parent commit — a real 4.3.1 YubiKey
// captured May 2026 produced no warning.
func TestPIVInfo_ROCANote_Emitted_OnAffectedFirmware(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.MockYubiKeyVersion = []byte{4, 3, 1}

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}

	if err := cmdPIVInfo(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdPIVInfo: %v", err)
	}
	out := buf.String()

	// Required substrings: the firmware version string, the CVE
	// or advisory ID, and the precise scope (RSA on-card affected;
	// ECC and imported RSA unaffected).
	for _, want := range []string{
		"4.3.1",
		"YSA-2017-01",
		"CVE-2017-15361",
		"RSA",
		"GENERATED on-card",
		"factorable",
		"ECC",
		"IMPORTED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ROCA note should contain %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestPIVInfo_ROCANote_Suppressed_OnUnaffectedFirmware: a 4.3.5
// YubiKey is NOT in the affected range (Yubico fixed ROCA in
// 4.3.5+). The note must not appear. Same for current 5.7.x
// firmware, which we already exercise via TestPIVInfo_MockFalls...
// but worth pinning explicitly here.
func TestPIVInfo_ROCANote_Suppressed_OnUnaffectedFirmware(t *testing.T) {
	cases := []struct {
		name string
		ver  []byte
	}{
		{"4.3.5 (the fix)", []byte{4, 3, 5}},
		{"4.4.0 hypothetical", []byte{4, 4, 0}},
		{"5.7.4 current", []byte{5, 7, 4}},
		{"4.2.5 just below", []byte{4, 2, 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc, err := mockcard.New()
			if err != nil {
				t.Fatalf("mockcard.New: %v", err)
			}
			mc.MockYubiKeyVersion = tc.ver

			var buf bytes.Buffer
			env := &runEnv{
				out:    &buf,
				errOut: &buf,
				connect: func(_ context.Context, _ string) (transport.Transport, error) {
					return mc.Transport(), nil
				},
			}

			if err := cmdPIVInfo(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
				t.Fatalf("cmdPIVInfo: %v", err)
			}

			var got struct {
				Data struct {
					Notes []string `json:"notes"`
				} `json:"data"`
			}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("JSON parse: %v\n%s", err, buf.String())
			}
			for _, note := range got.Data.Notes {
				if strings.Contains(note, "ROCA") || strings.Contains(note, "YSA-2017-01") {
					t.Errorf("ROCA note should NOT appear for %s; got: %q", tc.name, note)
				}
			}
		})
	}
}
