package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
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
		"scpctl smoke probe",
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
		"scpctl smoke probe",
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
