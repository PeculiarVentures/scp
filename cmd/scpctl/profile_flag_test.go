package main

// Tests for --profile auto|standard-sd|yubikey-sd.
//
// The flag has three behavioral effects, each tested below:
//
//   1. SCP03 factory-key-default rejection: --scp03-keys-default
//      is only valid when the resolved profile is yubikey-sd. The
//      CLI fast-fails on explicit --profile=standard-sd; the
//      library-level Capabilities gate is the authoritative check
//      for the auto path that resolves to standard at runtime.
//   2. sd keys generate refusal: GENERATE EC KEY (INS=0xF1) is a
//      Yubico extension; the CLI refuses on explicit
//      --profile=standard-sd before APDU emission. Library-level
//      Session.GenerateECKey + ErrUnsupportedByProfile is the
//      authoritative gate (covered separately in
//      securitydomain/profile_gating_test.go).
//   3. sd keys list KID labeling: kind labels for KIDs 0x11/0x13/
//      0x15 depend on the resolved profile name passed through to
//      classifyKID — yubikey-sd → scp11a/b/c-sd; standard-sd →
//      scp11-sd without the variant letter.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestProfileFlag_StandardSD_RejectsFactoryDefault confirms
// --scp03-keys-default + --profile=standard-sd is a usage error
// on every required-auth verb. Tests sd keys delete as the
// representative path; the other required-auth verbs share the
// same applyToConfig code path.
func TestProfileFlag_StandardSD_RejectsFactoryDefault(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
		"--confirm-delete-key",
		"--scp03-keys-default",
		"--profile", "standard-sd",
	})
	if err == nil {
		t.Fatalf("expected profile rejection, got success\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "standard-sd") && !strings.Contains(err.Error(), "YubiKey factory") {
		t.Errorf("expected profile-related diagnostic, got %q", err.Error())
	}
}

// TestProfileFlag_StandardSD_RejectsImplicitFactoryFallback —
// even without --scp03-keys-default, a required-auth verb on
// --profile=standard-sd with no SCP03 flags must refuse rather
// than silently fall back to the YubiKey factory keys.
func TestProfileFlag_StandardSD_RejectsImplicitFactoryFallback(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
		"--confirm-delete-key",
		"--profile", "standard-sd",
	})
	if err == nil {
		t.Fatalf("expected refusal of implicit factory-default on standard-sd, got success\n%s",
			buf.String())
	}
	if !strings.Contains(err.Error(), "explicit") {
		t.Errorf("expected diagnostic mentioning explicit keys requirement, got %q",
			err.Error())
	}
}

// TestProfileFlag_StandardSD_AcceptsCustomTriple — operator on a
// non-YubiKey card supplies the explicit triple; --profile=
// standard-sd should accept this combination cleanly.
func TestProfileFlag_StandardSD_AcceptsCustomTriple(t *testing.T) {
	customKeys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0x11}, 16),
		MAC: bytes.Repeat([]byte{0x22}, 16),
		DEK: bytes.Repeat([]byte{0x33}, 16),
	}
	mockCard := scp03.NewMockCard(customKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
		"--confirm-delete-key",
		"--profile", "standard-sd",
		"--scp03-kvn", "FF",
		"--scp03-enc", "11111111111111111111111111111111",
		"--scp03-mac", "22222222222222222222222222222222",
		"--scp03-dek", "33333333333333333333333333333333",
	})
	if err != nil {
		t.Fatalf("standard-sd + custom triple should work: %v\n%s", err, buf.String())
	}
}

// TestProfileFlag_StandardSD_RefusesGenerate confirms sd keys
// generate refuses on --profile=standard-sd because INS=0xF1 is
// a Yubico extension.
func TestProfileFlag_StandardSD_RefusesGenerate(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysGenerate(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", t.TempDir() + "/gen.pem",
		"--confirm-write",
		"--profile", "standard-sd",
	})
	if err == nil {
		t.Fatalf("expected profile refusal of generate on standard-sd, got success\n%s",
			buf.String())
	}
	if !strings.Contains(err.Error(), "Yubico") || !strings.Contains(err.Error(), "INS=0xF1") {
		t.Errorf("expected diagnostic mentioning Yubico extension, got %q", err.Error())
	}
	if recordedAPDUWithINS(mockCard.Recorded(), 0xF1) != nil {
		t.Errorf("CLI refusal must occur before GENERATE EC KEY emission; got APDU %+v",
			mockCard.Recorded())
	}
}

// TestProfileFlag_InvalidValue rejects a typo'd --profile value
// at first applyToConfig call.
func TestProfileFlag_InvalidValue(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--profile", "yubilkey-sd", // typo
	})
	if err == nil {
		t.Fatalf("expected --profile typo rejection, got success\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected diagnostic naming the flag, got %q", err.Error())
	}
}

// TestClassifyKID_StandardSD_DropsVariantLetters: KIDs 0x11/0x13/
// 0x15 collapse to "scp11-sd" without the variant letter on
// standard-sd. The variant mapping is a YubiKey convention; on
// standard GP cards the raw KID is preserved as authoritative.
func TestClassifyKID_StandardSD_DropsVariantLetters(t *testing.T) {
	cases := []struct {
		kid      byte
		yubikey  string
		standard string
	}{
		{0x11, "scp11a-sd", "scp11-sd"},
		{0x13, "scp11b-sd", "scp11-sd"},
		{0x15, "scp11c-sd", "scp11-sd"},
	}
	for _, c := range cases {
		gotY := classifyKID(c.kid, "yubikey-sd")
		gotS := classifyKID(c.kid, "standard-sd")
		if gotY != c.yubikey {
			t.Errorf("classifyKID(0x%02X, yubikey-sd) = %q, want %q", c.kid, gotY, c.yubikey)
		}
		if gotS != c.standard {
			t.Errorf("classifyKID(0x%02X, standard-sd) = %q, want %q", c.kid, gotS, c.standard)
		}
	}
}

// TestClassifyKID_StableForVendorAgnosticKIDs: SCP03 (KID=0x01)
// and OCE/CA-public (KID=0x10, 0x20-0x2F) are GP-spec
// conventions that don't depend on profile. Their labels stay
// the same regardless of profile name.
func TestClassifyKID_StableForVendorAgnosticKIDs(t *testing.T) {
	cases := []struct {
		kid  byte
		want string
	}{
		{0x01, "scp03"},
		{0x10, "ca-public"},
		{0x20, "ca-public"},
		{0x2F, "ca-public"},
	}
	for _, c := range cases {
		gotY := classifyKID(c.kid, "yubikey-sd")
		gotS := classifyKID(c.kid, "standard-sd")
		if gotY != c.want || gotS != c.want {
			t.Errorf("classifyKID(0x%02X) should be %q in both profiles; got yubikey-sd=%q standard-sd=%q",
				c.kid, c.want, gotY, gotS)
		}
	}
}

// TestProfileFlag_AutoIsDefault confirms the default --profile
// value is "auto" — i.e. omitting --profile triggers probe-based
// resolution rather than pinning to yubikey-sd. This is the
// behavior the profile package's auto-detection mode is built
// for.
func TestProfileFlag_AutoIsDefault(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	// No --profile flag: should use auto, which should NOT
	// reject like standard-sd would. Successful list.
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
	})
	if err != nil {
		t.Fatalf("default --profile (auto) should not error on a YubiKey-shaped mock; got %v\n%s",
			err, buf.String())
	}
}
