package profile_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
)

func TestStandard_Capabilities(t *testing.T) {
	caps := profile.Standard().Capabilities()
	if !caps.StandardSD {
		t.Error("Standard().Capabilities().StandardSD = false, want true")
	}
	if !caps.SCP03 || !caps.SCP11 || !caps.CertificateStore || !caps.KeyDelete {
		t.Error("Standard profile should claim all standardized GP/Amendment-F surfaces (SCP03, SCP11, CertificateStore, KeyDelete)")
	}
	// Allowlist is deliberately FALSE on standard-sd. GP Amendment F
	// §7.1.5 defines the concept, but the wire shape this library
	// emits (BER-TLV with yubikit/_int2asn1-derived integer encoding)
	// has not been measured against any non-YubiKey card. Marking
	// allowlist as a generic GP capability would make an interop
	// promise we can't keep. Until a non-YubiKey card is measured,
	// standard-sd reports false and the library refuses StoreAllowlist
	// / ClearAllowlist on this profile with an explicit error.
	if caps.Allowlist {
		t.Error("Standard profile must NOT claim Allowlist: the wire shape is the yubikit/Yubico encoding, " +
			"not measured against non-YubiKey cards (regression — see standard.go for rationale)")
	}
	if caps.GenerateECKey {
		t.Error("Standard profile must NOT claim GenerateECKey (INS=0xF1 is Yubico-specific)")
	}
	if caps.Reset {
		t.Error("Standard profile must NOT claim Reset (YubiKey factory-reset is vendor-specific)")
	}
	if profile.Standard().Name() != "standard-sd" {
		t.Errorf("Name = %q, want standard-sd", profile.Standard().Name())
	}
}

func TestYubiKey_Capabilities(t *testing.T) {
	caps := profile.YubiKey().Capabilities()
	if caps.StandardSD {
		t.Error("YubiKey().Capabilities().StandardSD = true, want false (vendor-extended)")
	}
	if !caps.GenerateECKey {
		t.Error("YubiKey profile must claim GenerateECKey")
	}
	if !caps.Reset {
		t.Error("YubiKey profile must claim Reset")
	}
	if profile.YubiKey().Name() != "yubikey-sd" {
		t.Errorf("Name = %q, want yubikey-sd", profile.YubiKey().Name())
	}
}

// scriptedTransmitter answers SELECT and GET DATA based on a
// playbook the test sets up. Used to exercise Probe's branches
// without requiring mockcard plumbing.
type scriptedTransmitter struct {
	selectSW   uint16
	selectData []byte
	versionSW  uint16
	verData    []byte
}

func (s *scriptedTransmitter) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4: // SELECT
		return &apdu.Response{
			SW1:  byte(s.selectSW >> 8),
			SW2:  byte(s.selectSW),
			Data: s.selectData,
		}, nil
	case 0xCA: // GET DATA
		return &apdu.Response{
			SW1:  byte(s.versionSW >> 8),
			SW2:  byte(s.versionSW),
			Data: s.verData,
		}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}

func TestProbe_NoSDReachable(t *testing.T) {
	tr := &scriptedTransmitter{selectSW: 0x6A82}
	_, err := profile.Probe(context.Background(), tr, nil)
	if err == nil {
		t.Fatal("expected error on unreachable SD")
	}
	if !errors.Is(err, profile.ErrNoSecurityDomain) {
		t.Errorf("err should wrap ErrNoSecurityDomain: %v", err)
	}
}

func TestProbe_DetectsYubiKey(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:  0x9000,
		versionSW: 0x9000,
		verData:   []byte{0x05, 0x07, 0x02}, // 5.7.2
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "yubikey-sd" {
		t.Errorf("expected yubikey-sd profile, got %v", res.Profile)
	}
	if len(res.YubiKeyVersion) != 3 {
		t.Errorf("YubiKeyVersion = %v, want 3 bytes", res.YubiKeyVersion)
	}
}

func TestProbe_FallsBackToStandardOn6A88(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:  0x9000,
		versionSW: 0x6A88, // referenced data not found — the standard signal
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "standard-sd" {
		t.Errorf("expected standard-sd profile, got %v", res.Profile)
	}
	if res.YubiKeyVersion != nil {
		t.Errorf("YubiKeyVersion should be nil for non-YubiKey card: %v", res.YubiKeyVersion)
	}
}

// TestProbe_NonConformantVersionResponseFallsThrough: a card that
// returns 9000 to GET DATA 5FC109 but with a payload that doesn't
// look like a YubiKey version (too short, empty) should NOT be
// silently classified as YubiKey. The probe falls through to
// standard rather than guessing.
func TestProbe_NonConformantVersionResponseFallsThrough(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:  0x9000,
		versionSW: 0x9000,
		verData:   []byte{0x01}, // too short to be major.minor.patch
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile.Name() != "standard-sd" {
		t.Errorf("non-conformant response should fall through to standard, got %s",
			res.Profile.Name())
	}
}
