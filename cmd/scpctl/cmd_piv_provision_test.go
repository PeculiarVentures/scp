package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/transport"
)

// TestPIVProvision_DryRun confirms --confirm-write is required for
// any APDU transmission. Without it the mock connect must not be
// called.
func TestPIVProvision_DryRun(t *testing.T) {
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return nil, errors.New("dry-run should not connect")
		},
	}
	if err := cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
	}); err != nil {
		t.Fatalf("dry-run cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	if connectCalled {
		t.Error("dry-run should not have connected")
	}
	if !strings.Contains(buf.String(), "dry-run") {
		t.Errorf("output should mention dry-run; got:\n%s", buf.String())
	}
}

// TestPIVProvision_GenerateKey_Smoke runs the full provisioning flow
// against the SCP11 mock. Asserts the host issued VERIFY PIN and
// GENERATE KEY in order, the smoke output reports PASS for both, and
// the mock returned a non-empty pubkey blob.
func TestPIVProvision_GenerateKey_Smoke(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// pivsession.Session.GenerateKey requires mgmt-key auth
	// host-side (matching real PIV behavior). The previous raw-
	// APDU path didn't enforce this, so the smoke test passed
	// without --mgmt-key against a permissive mock. The migration
	// to OpenSCP11bPIV in cmd_piv_provision.go surfaces the gate.
	// Configure the mock + pass --mgmt-key so the smoke flow
	// completes the way it would against a real card.
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--algorithm", "eccp256",
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"open SCP11b vs PIV",
		"VERIFY PIN",
		"GENERATE KEY",
		"PASS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVProvision_WithCertAndAttest exercises the optional flags:
// --cert installs a cert via PUT CERTIFICATE, --attest fetches
// the attestation. The cert's public key must match the slot's
// generated keypair or piv-provision refuses to install — this
// test pre-seeds the mock with a known keypair and builds a cert
// from the matching public key, exercising the success path.
func TestPIVProvision_WithCertAndAttest(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Pre-seed the mock so we know what key GENERATE KEY will return,
	// then build a cert that binds to that public key.
	slotKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("slot key generate: %v", err)
	}
	mockCard.PIVPresetKey = slotKey
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	// Stage a parseable cert as the ATTEST response. The mock
	// can't sign a real attestation, but pivsession.Session.Attest
	// parses the response as x509 and we want the test to drive
	// the parse path end-to-end. A self-signed cert under the
	// slot key serves as a valid syntactic stand-in.
	attestTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xA77E57),
		Subject:      pkix.Name{CommonName: "mock attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	attestDER, err := x509.CreateCertificate(rand.Reader, attestTmpl, attestTmpl, &slotKey.PublicKey, slotKey)
	if err != nil {
		t.Fatalf("create attest cert: %v", err)
	}
	mockCard.PIVAttestCertDER = attestDER

	certPath := writeMatchingPIVCert(t, slotKey)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9c",
		"--cert", certPath,
		"--attest",
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"parse pubkey",
		"ECDSA P-256",
		"cert binding",
		"cert matches generated slot key",
		"PUT CERTIFICATE",
		"ATTESTATION",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestPIVProvision_RejectsCertPubkeyMismatch is the new test that
// would have caught the gap ChatGPT flagged: a cert whose public
// key doesn't match the slot's generated keypair must not be
// installed. The slot's keypair would still be valid, but the
// cert would attest to an identity the slot can't actually prove
// possession of.
//
// Test setup: mock pre-seeded with key A; cert built from key B.
// piv-provision must fail at the cert-binding step, before
// reaching PUT CERTIFICATE.
func TestPIVProvision_RejectsCertPubkeyMismatch(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	slotKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCard.PIVPresetKey = slotKey
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	// Different key for the cert — the binding check must catch
	// the mismatch.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPath := writeMatchingPIVCert(t, otherKey)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--cert", certPath,
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err == nil {
		t.Fatalf("expected mismatch to fail; output:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "cert binding") || !strings.Contains(out, "FAIL") {
		t.Errorf("expected cert binding FAIL in output; got:\n%s", out)
	}
	if strings.Contains(out, "PUT CERTIFICATE                  PASS") {
		t.Error("PUT CERTIFICATE happened after binding FAIL — guard is broken")
	}
}

// writeMatchingPIVCert generates a minimal self-signed X.509 cert
// bound to the given key's public part and writes it to a temp file
// in PEM form. The cert isn't otherwise meaningful — its only
// purpose is to make the cert-binding check pass (or, if the caller
// uses a different key for slot vs cert, fail).
func writeMatchingPIVCert(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scp-smoke test PIV slot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "piv-slot.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestPIVProvision_RejectsBadSlotAndAlgo confirms inputs are
// validated at the CLI boundary, not deferred to opaque card errors.
func TestPIVProvision_RejectsBadSlotAndAlgo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown slot", []string{"--reader", "f", "--pin", "1", "--slot", "ab"}},
		{"unknown algorithm", []string{"--reader", "f", "--pin", "1", "--algorithm", "frob256"}},
		{"missing pin", []string{"--reader", "f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{out: &buf, errOut: &buf, connect: nil}
			err := cmdPIVProvision(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError; got %T: %v", err, err)
			}
		})
	}
}

// TestPIVProvision_WithMgmtKeyAuth runs the full provisioning flow
// with --mgmt-key against a mock configured for crypto-correct PIV
// management-key mutual auth. Round-trip verifies: host runs step 1,
// mock generates witness encrypted under shared key; host decrypts,
// runs step 2; mock verifies host's decrypted witness, encrypts the
// host's challenge; host's VerifyMutualAuthResponse accepts.
//
// This is the test that would have caught the gap I shipped in #54
// — a piv-provision with no mgmt-key flow at all — and now proves
// the flow works end-to-end through the SM channel.
func TestPIVProvision_WithMgmtKeyAuth(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Configure the mock for AES-192 mgmt-key auth (matches YubiKey
	// 5.7+ factory default algorithm). Use a deterministic key so
	// the test is reproducible.
	mgmtKey := bytes.Repeat([]byte{0xA5}, 24)
	mockCard.PIVMgmtKey = mgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--algorithm", "eccp256",
		"--mgmt-key", hex.EncodeToString(mgmtKey),
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"MGMT-KEY AUTH",
		"AES-192",
		"VERIFY PIN",
		"GENERATE KEY",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, " FAIL") {
		t.Errorf("output contains FAIL\n--- output ---\n%s", out)
	}
}

// TestPIVProvision_RejectsWrongMgmtKey confirms the host's verify
// step rejects when the configured key doesn't match the card's.
// The mock encrypts with one key; the CLI is given a different key.
// The host's VerifyMutualAuthResponse must fail closed and the
// command must return an error.
func TestPIVProvision_RejectsWrongMgmtKey(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	cardKey := bytes.Repeat([]byte{0xA5}, 16)
	mockCard.PIVMgmtKey = cardKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES128

	wrongKey := bytes.Repeat([]byte{0xC3}, 16)

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}

	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--mgmt-key", hex.EncodeToString(wrongKey),
		"--mgmt-key-algorithm", "aes128",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err == nil {
		t.Fatalf("expected wrong-key auth to fail; output:\n%s", buf.String())
	}
	// Mock returns 6982 on host-witness mismatch — that's what we
	// expect to surface, since our wrong key produces the wrong
	// decrypted witness.
	if !strings.Contains(buf.String(), "MGMT-KEY AUTH") {
		t.Errorf("expected MGMT-KEY AUTH step in output; got:\n%s", buf.String())
	}
}

// TestPIVProvision_NoMgmtKey_FailsBeforeGenerateKey pins the
// host-side mgmt-key gate that pivsession.Session.GenerateKey
// enforces. Without --mgmt-key, the command runs through SCP11b
// open and VERIFY PIN cleanly, then fails on GENERATE KEY because
// the library refuses to send GENERATE ASYMMETRIC KEY without an
// authenticated management key.
//
// This is a behavior change from the deprecated raw-APDU path,
// which would have sent GENERATE KEY anyway and let the card
// refuse with SW=6982. Surfacing the gate host-side is the
// correctness improvement the migration to OpenSCP11bPIV brings.
//
// Per the fourth external review, cross-branch issue #2
// (cmd_piv_provision migrated to OpenSCP11bPIV).
func TestPIVProvision_NoMgmtKey_FailsBeforeGenerateKey(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// No PIVMgmtKey configured; --mgmt-key not passed.
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	// The command should report failures (GENERATE KEY refused
	// host-side) and return a non-nil error to surface the
	// problem to scripts.
	if err == nil {
		t.Fatalf("expected failure when --mgmt-key is omitted; output:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH") || !strings.Contains(out, "SKIP") {
		t.Errorf("expected MGMT-KEY AUTH SKIP entry; got:\n%s", out)
	}
	// GENERATE KEY must fail with the host-side auth gate
	// message, not a card-side SW.
	if !strings.Contains(out, "GENERATE KEY") || !strings.Contains(out, "FAIL") {
		t.Errorf("expected GENERATE KEY FAIL; got:\n%s", out)
	}
	if !strings.Contains(out, "AuthenticateManagementKey") &&
		!strings.Contains(out, "authentication has not been performed") {
		t.Errorf("expected error to reference host-side mgmt-key gate; got:\n%s", out)
	}
}

// TestPIVProvision_RejectsBadMgmtKeyArgs covers --mgmt-key parsing
// at the CLI boundary: bad hex, length-mismatch with algorithm,
// "default" with non-3DES algorithm.
func TestPIVProvision_RejectsBadMgmtKeyArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad hex", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "ZZ",
			"--mgmt-key-algorithm", "aes128",
		}},
		{"length mismatch", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", strings.Repeat("AA", 24), // 24 bytes
			"--mgmt-key-algorithm", "aes128", // wants 16
		}},
		{"default with aes128 (wrong length)", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "default",
			"--mgmt-key-algorithm", "aes128",
		}},
		{"default with aes256 (wrong length)", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", "default",
			"--mgmt-key-algorithm", "aes256",
		}},
		{"unknown algorithm", []string{
			"--reader", "f", "--pin", "1",
			"--mgmt-key", strings.Repeat("AA", 16),
			"--mgmt-key-algorithm", "frob",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			env := &runEnv{out: &buf, errOut: &buf, connect: nil}
			err := cmdPIVProvision(context.Background(), env, tc.args)
			if err == nil {
				t.Fatal("expected usage error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError; got %T: %v", err, err)
			}
		})
	}
}

// TestPIVProvision_MgmtKeyDefault_AES192 confirms --mgmt-key default
// works with --mgmt-key-algorithm aes192 — the YubiKey 5.7+ factory
// state. Per Yubico docs, the same 24-byte well-known value
// (0102030405...0708) is the default for both 3DES (pre-5.7) and
// AES-192 (5.7+), so "default" must work for either.
//
// I had this wrong before; the original code rejected
// `--mgmt-key default --mgmt-key-algorithm aes192` with an error
// claiming the default only applied to 3DES. Confirmed against
// Yubico's own developer docs, the default value is shared.
func TestPIVProvision_MgmtKeyDefault_AES192(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Mock acts as a 5.7+ card: AES-192 mgmt key, default value.
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "aes192",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH                    PASS — AES-192") {
		t.Errorf("expected mgmt-key auth PASS with AES-192; got:\n%s", out)
	}
}

// TestPIVProvision_MgmtKeyDefault_3DES_StillWorks pins the original
// pre-5.7 path so the AES-192 expansion doesn't accidentally break
// it.
func TestPIVProvision_MgmtKeyDefault_3DES_StillWorks(t *testing.T) {
	mockCard, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mockCard.PIVMgmtKey = piv.DefaultMgmtKey
	mockCard.PIVMgmtKeyAlgo = piv.AlgoMgmt3DES

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	err = cmdPIVProvision(context.Background(), env, []string{
		"--reader", "fake",
		"--pin", "123456",
		"--slot", "9a",
		"--mgmt-key", "default",
		"--mgmt-key-algorithm", "3des",
		"--lab-skip-scp11-trust",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdPIVProvision: %v\n--- output ---\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "MGMT-KEY AUTH                    PASS — 3DES") {
		t.Errorf("expected mgmt-key auth PASS with 3DES; got:\n%s", out)
	}
}

// TestParsePIVSlot_RetiredRange confirms the CLI accepts the full
// retired-key-management slot range (0x82..0x95, slots 1..20)
// rather than only SlotRetired1. The underlying piv.slotToObjectID
// already supported the full range; the bug was that parsePIVSlot
// rejected anything except 0x82, making the other 19 retired slots
// unreachable from the CLI.
func TestParsePIVSlot_RetiredRange(t *testing.T) {
	// Walk the entire 0x82..0x95 range and confirm every byte parses.
	for slot := byte(0x82); slot <= 0x95; slot++ {
		s := fmt.Sprintf("%02x", slot)
		got, err := parsePIVSlot(s)
		if err != nil {
			t.Errorf("slot %s: unexpected error: %v", s, err)
			continue
		}
		if got != slot {
			t.Errorf("slot %s: got 0x%02X want 0x%02X", s, got, slot)
		}
	}

	// 0x96 is just past the retired range — must be rejected.
	if _, err := parsePIVSlot("96"); err == nil {
		t.Error("0x96 should be rejected (one past retired range)")
	}
	// 0x81 is just before — must be rejected.
	if _, err := parsePIVSlot("81"); err == nil {
		t.Error("0x81 should be rejected (one before retired range)")
	}
}

// TestParsePIVSlot_NamedSlots pins the four primary PIV slots and
// the YubiKey attestation slot still parse, plus an unknown slot
// is rejected with a helpful error.
func TestParsePIVSlot_NamedSlots(t *testing.T) {
	cases := map[string]byte{
		"9a": piv.SlotAuthentication,
		"9c": piv.SlotSignature,
		"9d": piv.SlotKeyManagement,
		"9e": piv.SlotCardAuth,
		"f9": piv.SlotAttestation,
	}
	for s, want := range cases {
		t.Run(s, func(t *testing.T) {
			got, err := parsePIVSlot(s)
			if err != nil {
				t.Fatalf("%s: %v", s, err)
			}
			if got != want {
				t.Errorf("%s: got 0x%02X want 0x%02X", s, got, want)
			}
		})
	}
	if _, err := parsePIVSlot("01"); err == nil {
		t.Error("0x01 should be rejected")
	}
}
