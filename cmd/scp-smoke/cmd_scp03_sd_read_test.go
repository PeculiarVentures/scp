package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP03SDRead_Smoke runs the cmd_scp03_sd_read flow end-to-end
// against the now-extended SCP03 mock card. The mock handles GET
// DATA tags 0xE0 (key info) and 0x66 (CRD) over secure messaging
// after the SCP03 handshake completes (PR that extends the mock
// added these), so the smoke command can be unit-tested without
// hardware.
//
// Verifies four checks pass: open, authenticated, GetKeyInformation,
// GetCardRecognitionData over SCP03.
func TestSCP03SDRead_Smoke(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	if err := cmdSCP03SDRead(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()

	for _, want := range []string{
		"open SCP03 SD",
		"PASS",
		"authenticated",
		"GetKeyInformation",
		"GetCardRecognitionData over SCP03",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Make sure no FAIL line slipped through.
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestSCP03SDRead_CustomKeys_Smoke is the end-to-end test:
// configures a scp03 mock with non-factory keys, runs scp03-sd-read
// with --scp03-{kvn,enc,mac,dek} matching, asserts the session
// opens. Without this test, a refactor that wires the custom key
// flags through to the wrong place would be caught only by manual
// hardware testing.
func TestSCP03SDRead_CustomKeys_Smoke(t *testing.T) {
	customKeys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0x11}, 16),
		MAC: bytes.Repeat([]byte{0x22}, 16),
		DEK: bytes.Repeat([]byte{0x33}, 16),
	}
	mock := scp03.NewMockCard(customKeys)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-enc", hex.EncodeToString(customKeys.ENC),
		"--scp03-mac", hex.EncodeToString(customKeys.MAC),
		"--scp03-dek", hex.EncodeToString(customKeys.DEK),
	})
	if err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "SCP03 keys                       PASS — custom (KVN 0x01, AES-128)") {
		t.Errorf("output should report custom keys; got:\n%s", out)
	}
	if !strings.Contains(out, "open SCP03 SD                    PASS") {
		t.Errorf("expected open PASS; got:\n%s", out)
	}
}

// TestSCP03SDRead_FactoryKeys_StillWorks confirms the implicit-
// default path is unchanged: no flags = factory keys = factory
// mock, identical to pre-PR behavior.
func TestSCP03SDRead_FactoryKeys_StillWorks(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{"--reader", "fake"})
	if err != nil {
		t.Fatalf("cmdSCP03SDRead: %v\n--- output ---\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "factory") {
		t.Errorf("output should mention factory; got:\n%s", buf.String())
	}
}

// TestSCP03SDRead_WrongKeysFails confirms the negative path:
// supplying keys that don't match the mock's actual keys produces
// a session-open failure. Validates that the keys are actually
// being used in the handshake, not just stored in cfg and ignored.
func TestSCP03SDRead_WrongKeysFails(t *testing.T) {
	mock := scp03.NewMockCard(scp03.DefaultKeys)
	wrong := bytes.Repeat([]byte{0xFF}, 16)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mock.Transport(), nil
		},
	}
	err := cmdSCP03SDRead(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-kvn", "01",
		"--scp03-enc", hex.EncodeToString(wrong),
		"--scp03-mac", hex.EncodeToString(wrong),
		"--scp03-dek", hex.EncodeToString(wrong),
	})
	if err == nil {
		t.Fatalf("expected handshake to fail with wrong keys; output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "open SCP03 SD") {
		t.Errorf("expected open SCP03 SD step in output; got:\n%s", buf.String())
	}
}
