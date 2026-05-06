package main

// Tests for --vendor-profile yubikey|generic.
//
// The flag has three behavioral effects:
//
//   1. SCP03 factory-key-default rejection: --scp03-keys-default
//      is only valid on yubikey (the factory keys are
//      vendor-specific). Required-auth verbs also refuse
//      implicit factory fallback when vendor=generic.
//   2. sd keys generate refusal: GENERATE EC KEY (INS=0xF1) is
//      a Yubico extension; refuse on vendor=generic before APDU
//      emission rather than letting the card error surface as
//      noise.
//   3. sd keys list KID labeling: vendor=generic relabels
//      0x11/0x13/0x15 as "scp11-sd" without the variant letter,
//      because generic GP cards don't promise the YubiKey KID
//      → SCP11 variant mapping.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestVendorProfile_Generic_RejectsFactoryDefault confirms
// --scp03-keys-default + --vendor-profile generic is a usage
// error on every required-auth verb. Tests sd keys delete as
// the representative path; the other required-auth verbs share
// the same applyToConfig code path.
func TestVendorProfile_Generic_RejectsFactoryDefault(t *testing.T) {
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
		"--vendor-profile", "generic",
	})
	if err == nil {
		t.Fatalf("expected vendor-profile rejection, got success\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "vendor-profile") && !strings.Contains(err.Error(), "YubiKey factory") {
		t.Errorf("expected vendor-related diagnostic, got %q", err.Error())
	}
}

// TestVendorProfile_Generic_RejectsImplicitFactoryFallback —
// even without --scp03-keys-default, a required-auth verb on
// vendor=generic with no SCP03 flags must refuse rather than
// silently fall back to the YubiKey factory keys.
func TestVendorProfile_Generic_RejectsImplicitFactoryFallback(t *testing.T) {
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
		"--vendor-profile", "generic",
		// Note: no --scp03-* flags. Yubikey-default would normally
		// auto-apply; vendor=generic must refuse.
	})
	if err == nil {
		t.Fatalf("expected refusal of implicit factory-default on generic, got success\n%s",
			buf.String())
	}
	if !strings.Contains(err.Error(), "explicit") {
		t.Errorf("expected diagnostic mentioning explicit keys requirement, got %q",
			err.Error())
	}
}

// TestVendorProfile_Generic_AcceptsCustomTriple — the operator on
// a non-YubiKey card supplies the explicit triple; vendor=generic
// should accept this combination cleanly.
func TestVendorProfile_Generic_AcceptsCustomTriple(t *testing.T) {
	// Use a custom-keyed mock so the SCP03 handshake actually
	// completes against the supplied keys. We can't use the
	// default mock here because it has the YubiKey factory keys
	// installed; the operator's custom triple wouldn't match.
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
		"--vendor-profile", "generic",
		"--scp03-kvn", "FF",
		"--scp03-enc", "11111111111111111111111111111111",
		"--scp03-mac", "22222222222222222222222222222222",
		"--scp03-dek", "33333333333333333333333333333333",
	})
	if err != nil {
		t.Fatalf("vendor=generic + custom triple should work: %v\n%s", err, buf.String())
	}
}

// TestVendorProfile_Generic_RefusesGenerate confirms sd keys
// generate refuses on vendor=generic because INS=0xF1 is a
// Yubico extension.
func TestVendorProfile_Generic_RefusesGenerate(t *testing.T) {
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
		"--vendor-profile", "generic",
	})
	if err == nil {
		t.Fatalf("expected vendor-profile refusal of generate on generic, got success\n%s",
			buf.String())
	}
	if !strings.Contains(err.Error(), "Yubico") || !strings.Contains(err.Error(), "INS=0xF1") {
		t.Errorf("expected diagnostic mentioning Yubico extension, got %q", err.Error())
	}
	// CRITICAL: no GENERATE EC KEY APDU should have been sent.
	if recordedAPDUWithINS(mockCard.Recorded(), 0xF1) != nil {
		t.Errorf("vendor refusal must occur before GENERATE EC KEY emission; got APDU %+v",
			mockCard.Recorded())
	}
}

// TestVendorProfile_InvalidValue rejects a typo'd vendor value
// at first applyToConfig call rather than silently treating it
// as yubikey or as generic.
func TestVendorProfile_InvalidValue(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--vendor-profile", "yubilkey", // typo
	})
	if err == nil {
		t.Fatalf("expected vendor-profile typo rejection, got success\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "vendor-profile") {
		t.Errorf("expected diagnostic naming the flag, got %q", err.Error())
	}
}

// TestClassifyKID_Generic_DropsVariantLetters checks the relabel
// behavior: 0x11/0x13/0x15 all become "scp11-sd" without the
// variant letter on generic, because generic GP doesn't promise
// the YubiKey KID-to-variant mapping.
func TestClassifyKID_Generic_DropsVariantLetters(t *testing.T) {
	cases := []struct {
		kid    byte
		yubikey string
		generic string
	}{
		{0x11, "scp11a-sd", "scp11-sd"},
		{0x13, "scp11b-sd", "scp11-sd"},
		{0x15, "scp11c-sd", "scp11-sd"},
	}
	for _, c := range cases {
		gotY := classifyKID(c.kid, "yubikey")
		gotG := classifyKID(c.kid, "generic")
		if gotY != c.yubikey {
			t.Errorf("classifyKID(0x%02X, yubikey) = %q, want %q", c.kid, gotY, c.yubikey)
		}
		if gotG != c.generic {
			t.Errorf("classifyKID(0x%02X, generic) = %q, want %q", c.kid, gotG, c.generic)
		}
	}
}

// TestClassifyKID_Generic_StableForVendorAgnosticKIDs: SCP03
// (KID=0x01) and OCE/CA-public (KID=0x10, 0x20-0x2F) are GP-spec
// conventions that don't depend on vendor. Their labels stay the
// same regardless of vendor profile.
func TestClassifyKID_Generic_StableForVendorAgnosticKIDs(t *testing.T) {
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
		gotY := classifyKID(c.kid, "yubikey")
		gotG := classifyKID(c.kid, "generic")
		if gotY != c.want || gotG != c.want {
			t.Errorf("classifyKID(0x%02X) should be %q in both vendors; got yubikey=%q generic=%q",
				c.kid, c.want, gotY, gotG)
		}
	}
}
