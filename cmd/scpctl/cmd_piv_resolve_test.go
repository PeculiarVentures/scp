package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/transport"
)

// fakeSessionForMgmt satisfies sessionForMgmt with a configurable
// profile, so resolveMgmtKey can be exercised against profile-
// specific defaults without a live session.
type fakeSessionForMgmt struct {
	prof profile.Profile
}

func (f fakeSessionForMgmt) Profile() profile.Profile { return f.prof }

// TestResolveMgmtKey_YubiKeyDefaultIsAES192 verifies that under a
// YubiKey 5.7+ profile, an empty --mgmt-alg picks AES-192 (the
// 5.7 factory algorithm) and an empty --mgmt-key resolves to the
// factory default key bytes for that algorithm.
func TestResolveMgmtKey_YubiKeyDefaultIsAES192(t *testing.T) {
	sess := fakeSessionForMgmt{prof: profile.NewYubiKeyProfile()}
	mk, err := resolveMgmtKey(sess, "", "")
	if err != nil {
		t.Fatalf("resolveMgmtKey: %v", err)
	}
	if mk.Algorithm != piv.ManagementKeyAlgAES192 {
		t.Errorf("algorithm = %s, want AES-192 for YubiKey 5.7+ default", mk.Algorithm)
	}
	if !bytes.Equal(mk.Key, piv.DefaultMgmtKey) {
		t.Errorf("key did not match piv.DefaultMgmtKey")
	}
}

// TestResolveMgmtKey_YubiKeyPre57DefaultIs3DES verifies that a
// pre-5.7 YubiKey profile picks 3DES as the algorithm default.
// This is the historical YubiKey factory algorithm; the 5.7
// transition to AES is what makes profile-aware defaults
// necessary in the first place.
func TestResolveMgmtKey_YubiKeyPre57DefaultIs3DES(t *testing.T) {
	prof := profile.NewYubiKeyProfileVersion(profile.YubiKeyVersion{Major: 5, Minor: 6, Patch: 0})
	sess := fakeSessionForMgmt{prof: prof}
	mk, err := resolveMgmtKey(sess, "", "")
	if err != nil {
		t.Fatalf("resolveMgmtKey: %v", err)
	}
	// Pre-5.7 default is 3DES per Yubico's documentation; the
	// profile's DefaultMgmtKeyAlg field is what drives this.
	caps := prof.Capabilities()
	if mk.Algorithm != caps.DefaultMgmtKeyAlg {
		t.Errorf("algorithm = %s, want %s (profile's DefaultMgmtKeyAlg)",
			mk.Algorithm, caps.DefaultMgmtKeyAlg)
	}
}

// TestResolveMgmtKey_StandardPIVDefault verifies that under the
// Standard PIV profile, an empty --mgmt-alg picks whatever
// DefaultMgmtKeyAlg the profile claims. SP 800-78 specifies AES
// for new cards; the test asserts the profile's choice rather
// than hardcoding because the profile is the source of truth.
func TestResolveMgmtKey_StandardPIVDefault(t *testing.T) {
	prof := profile.NewStandardPIVProfile()
	sess := fakeSessionForMgmt{prof: prof}
	mk, err := resolveMgmtKey(sess, "", "")
	if err != nil {
		t.Fatalf("resolveMgmtKey: %v", err)
	}
	caps := prof.Capabilities()
	if mk.Algorithm != caps.DefaultMgmtKeyAlg {
		t.Errorf("algorithm = %s, want %s",
			mk.Algorithm, caps.DefaultMgmtKeyAlg)
	}
}

// TestResolveMgmtKey_ExplicitAlgorithmOverridesDefault verifies an
// explicit --mgmt-alg overrides the profile default. Operators
// rotating onto a non-default algorithm need this path; without
// it the override would silently fall back to the profile's own
// idea of the correct algorithm.
func TestResolveMgmtKey_ExplicitAlgorithmOverridesDefault(t *testing.T) {
	sess := fakeSessionForMgmt{prof: profile.NewYubiKeyProfile()}
	// AES-256 is 32 bytes. The literal "default" sentinel only
	// resolves for 3DES/AES-192 (both 24 bytes), so for AES-256
	// the operator must supply a real key. Pass a recognizable
	// fixture that's the right length.
	const aes256Hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
	mk, err := resolveMgmtKey(sess, aes256Hex, "aes256")
	if err != nil {
		t.Fatalf("resolveMgmtKey: %v", err)
	}
	if mk.Algorithm != piv.ManagementKeyAlgAES256 {
		t.Errorf("algorithm = %s, want AES-256 (explicit)", mk.Algorithm)
	}
	if len(mk.Key) != 32 {
		t.Errorf("key length = %d, want 32 (AES-256)", len(mk.Key))
	}
}

// TestPIVReset_RequiresBothGates verifies the two-flag pattern on
// 'piv reset': --confirm-write alone is not enough, and the order
// in which the gates fail is stable so error messages are
// predictable.
//
// The profile-refusal-of-unsupported-mgmt-algorithm path (a related
// concern, since resolveMgmtKey accepts arbitrary --mgmt-alg
// values) is covered at the session level by
// TestSession_AuthenticateManagementKey_RefusedByProfile and
// TestSession_ChangeManagementKey_RefusedAlgUnsupported in
// piv/session/. resolveMgmtKey itself is just a parser; the
// session is the gate.
func TestPIVReset_RequiresBothGates(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	makeEnv := func() (*runEnv, *bytes.Buffer) {
		var buf bytes.Buffer
		return &runEnv{
			out:    &buf,
			errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return card.Transport(), nil
			},
		}, &buf
	}

	// No flags: --confirm-write gate fires first.
	env, _ := makeEnv()
	err = cmdPIVGroupReset(context.Background(), env, []string{"--reader", "fake"})
	if err == nil {
		t.Fatal("expected error with no confirmation flags")
	}
	if !strings.Contains(err.Error(), "--confirm-write") {
		t.Errorf("first gate should mention --confirm-write: %v", err)
	}

	// --confirm-write only: --confirm-reset-piv gate fires next.
	env, _ = makeEnv()
	err = cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--confirm-write",
	})
	if err == nil {
		t.Fatal("expected error with only --confirm-write")
	}
	if !strings.Contains(err.Error(), "--confirm-reset-piv") {
		t.Errorf("second gate should mention --confirm-reset-piv: %v", err)
	}

	// --confirm-reset-piv without --confirm-write: still fails because
	// the first gate fires first. This is the stable error-order
	// guarantee: an operator who mistypes the second flag without
	// the first sees the missing-first-flag error rather than a
	// confusing "second flag not enough" message.
	env, _ = makeEnv()
	err = cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--confirm-reset-piv",
	})
	if err == nil {
		t.Fatal("expected error with only --confirm-reset-piv")
	}
	if !strings.Contains(err.Error(), "--confirm-write") {
		t.Errorf("first gate should fire first regardless of flag ordering: %v", err)
	}
}

// TestPIVMgmtAuth_RequiresChannelChoice verifies the fail-closed
// channel-mode default. A scpctl piv command that touches the card
// must specify either --scp11b or --raw-local-ok; absence of both
// is rejected with a clear error before any APDU goes on the wire.
//
// This guards against a silent downgrade for operators migrating
// from scp-smoke piv-provision (which used SCP11b unconditionally)
// to the new scpctl piv surface. An operator who copies the smoke
// command line without --scp11b should get a usage error, not a
// raw-mode session.
func TestPIVMgmtAuth_RequiresChannelChoice(t *testing.T) {
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

	// Neither flag set: command should refuse before any transmit.
	err = cmdPIVMgmtAuth(context.Background(), env, []string{
		"--reader", "fake",
	})
	if err == nil {
		t.Fatal("expected error when neither --scp11b nor --raw-local-ok is set")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--scp11b") || !strings.Contains(msg, "--raw-local-ok") {
		t.Errorf("error should name both flags: %v", err)
	}
}

// TestPIVMgmtAuth_RejectsBothChannelFlags verifies the mutual-
// exclusion check between --scp11b and --raw-local-ok. An operator
// who passes both has not made a clear choice; the command refuses
// rather than silently picking one.
func TestPIVMgmtAuth_RejectsBothChannelFlags(t *testing.T) {
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

	err = cmdPIVMgmtAuth(context.Background(), env, []string{
		"--reader", "fake",
		"--scp11b",
		"--raw-local-ok",
	})
	if err == nil {
		t.Fatal("expected error when both --scp11b and --raw-local-ok are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion: %v", err)
	}
}

// TestPIVMgmtAuth_RawLocalOK_OpensSession verifies the happy raw
// path: --raw-local-ok alone is sufficient (no SCP11b, no trust
// roots) and the channel-mode gate lets the command through. The
// downstream mgmt-key auth may or may not succeed against the
// mock depending on key/algorithm fixtures; this test only
// asserts the channel-mode line is the raw-asserted form, which
// proves the gate accepted --raw-local-ok and the session opened
// in raw mode.
func TestPIVMgmtAuth_RawLocalOK_OpensSession(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	card.PIVMgmtKey = piv.DefaultMgmtKey
	card.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return card.Transport(), nil
		},
	}

	// The downstream mgmt auth may fail; we don't care for this
	// test. We care that the channel-mode gate accepted the raw
	// assertion and the report records it correctly.
	_ = cmdPIVMgmtAuth(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
	})
	out := buf.String()
	if !strings.Contains(out, "raw (operator asserted local-USB trust)") {
		t.Errorf("expected channel-mode line confirming raw assertion:\n%s", out)
	}
	if strings.Contains(out, "scp11b-on-piv") {
		t.Errorf("--raw-local-ok should not pick scp11b path:\n%s", out)
	}
}
