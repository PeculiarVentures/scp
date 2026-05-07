package profile_test

import (
	"context"
	"encoding/hex"
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
//
// Two-phase script: SELECT returns selectData under selectSW; the
// optional follow-up GET DATA tag 0x66 (CRD fetch) returns
// crdData under crdSW. The probe under test will only issue the
// follow-up when the SELECT response was not parseable as CRD.
type scriptedTransmitter struct {
	selectSW   uint16
	selectData []byte
	crdSW      uint16
	crdData    []byte
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
		// Probe issues exactly one GET DATA — for tag 0x66 (CRD
		// follow-up). Return the scripted CRD.
		return &apdu.Response{
			SW1:  byte(s.crdSW >> 8),
			SW2:  byte(s.crdSW),
			Data: s.crdData,
		}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}

// realYubiKeyCRD is the actual Card Recognition Data captured
// from a retail YubiKey 5.7.4 (rmhrisk's test card,
// 2026-05-04). Pinned in cardrecognition's
// TestParse_RetailYubiKey5_BothSCPs fixture too — kept here as
// a literal so this package's tests don't import cardrecognition's
// test fixtures.
var realYubiKeyCRD = mustHex(
	"663F733D" +
		"06072A864886FC6B01" + // GP RID
		"600C060A2A864886FC6B02020301" + // GP 2.3.1
		"630906072A864886FC6B03" + // card identification scheme (the YubiKey signature OID)
		"640B06092A864886FC6B040360" + // SCP03 i=0x60
		"640C060A2A864886FC6B04119B06") // SCP11 i=0x0D86

// nonYubiKeyCRD is a synthetic CRD with a Card Identification
// Scheme OID that's NOT 1.2.840.114283.3 — uses 1.2.840.114283.99
// (an out-of-band-allocated arc that isn't the YubiKey signature)
// to verify Probe's discriminator only fires on the exact Yubico
// OID, not on any GP-RID-rooted card identification.
//
// Length math: outer tag 0x66 length 0x24 (=36 bytes inner). Inner
// tag 0x73 length 0x22 (=34 bytes children). Children: GP RID OID
// (9 bytes) + GP version 2.3.1 (14 bytes) + card-id OID 1.2.840.
// 114283.99 (11 bytes) = 34 bytes.
var nonYubiKeyCRD = mustHex(
	"6624" + "7322" +
		"06072A864886FC6B01" + // GP RID
		"600C060A2A864886FC6B02020301" + // GP 2.3.1
		"6309" + "06072A864886FC6B63") // card identification scheme = 1.2.840.114283.99 (NOT YubiKey)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
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

// TestProbe_DetectsYubiKeyViaCRD verifies the post-fix probe
// classifies a card as YubiKey when its SELECT response carries
// CRD with the Yubico Card Identification Scheme OID
// (1.2.840.114283.3). This is the primary detection path on real
// YubiKey 5.7+ hardware: SELECT returns CRD inline, no follow-up
// GET DATA needed.
func TestProbe_DetectsYubiKeyViaCRD(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:   0x9000,
		selectData: realYubiKeyCRD,
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "yubikey-sd" {
		t.Errorf("expected yubikey-sd profile, got %v", res.Profile)
	}
	if res.CardInfo == nil {
		t.Fatal("CardInfo should be populated when CRD parsed successfully")
	}
}

// TestProbe_FallsBackToCRDViaGetData verifies the fallback path:
// some cards return a minimal SELECT response that doesn't
// include CRD, and the probe must issue GET DATA tag 0x66 to
// fetch CRD explicitly. When that fallback succeeds and produces
// a YubiKey-signature CRD, classification still lands on
// yubikey-sd.
func TestProbe_FallsBackToCRDViaGetData(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:   0x9000,
		selectData: nil, // SELECT returns no FCI body
		crdSW:      0x9000,
		crdData:    realYubiKeyCRD,
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "yubikey-sd" {
		t.Errorf("expected yubikey-sd via GET DATA fallback, got %v", res.Profile)
	}
}

// TestProbe_NonYubiKeyCRDFallsThroughToStandard verifies that a
// card emitting CRD with a non-YubiKey Card Identification
// Scheme OID drops to Standard, not YubiKey. The discriminator
// must be exact-OID match — matching just the GP-RID prefix
// would misclassify any card that happens to fill the card-id
// arc with a vendor-specific value.
func TestProbe_NonYubiKeyCRDFallsThroughToStandard(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:   0x9000,
		selectData: nonYubiKeyCRD,
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "standard-sd" {
		t.Errorf("non-YubiKey CRD should classify as standard-sd, got %v", res.Profile)
	}
	if res.CardInfo == nil {
		t.Fatal("CardInfo should be populated even for standard-sd classification")
	}
}

// TestProbe_NoCRDFallsThroughToStandard verifies that a card with
// SELECT 9000 but no parseable CRD anywhere (neither inline nor
// via GET DATA tag 0x66) drops to Standard. The previous probe
// implementation always returned Standard for every card; this
// test pins that "no CRD reachable" still produces Standard
// (just for the right reason now — the parse fell through, not
// because every probe always produced Standard regardless).
func TestProbe_NoCRDFallsThroughToStandard(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:   0x9000,
		selectData: nil, // no FCI
		crdSW:      0x6A88,
		crdData:    nil, // no CRD via GET DATA either
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "standard-sd" {
		t.Errorf("expected standard-sd when no CRD parseable, got %v", res.Profile)
	}
	if res.CardInfo != nil {
		t.Errorf("CardInfo should be nil when no CRD reachable, got %+v", res.CardInfo)
	}
}
