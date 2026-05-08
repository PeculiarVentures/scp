package profile_test

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cardrecognition"
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
		"630906072A864886FC6B03" + // Card_IDS (GP-standard, not YubiKey-specific)
		"640B06092A864886FC6B040360" + // SCP03 i=0x60
		"640C060A2A864886FC6B04119B06") // SCP11 i=0x0D86

// nonYubiKeyCRD is a synthetic CRD with a Card Identification
// Scheme OID that's NOT 1.2.840.114283.3 — uses 1.2.840.114283.99
// (an out-of-band-allocated arc that isn't a real Card_IDS) to
// verify classifyByCRD's first-gate check rejects CRDs where the
// Card Identification arc is some other vendor-specific value.
// Real-world non-YubiKey cards that do emit the GP-standard
// 1.2.840.114283.3 (e.g. SafeNet eToken Fusion) are covered by
// realSafeNetEtokenFusionCRD, which exercises the chip-details and
// SCP11-advertised narrowing signals instead.
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
// a YubiKey-shaped CRD (Card_IDS OID present, no chip details,
// SCP11 advertised), classification still lands on yubikey-sd.
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
// card emitting CRD with a Card Identification Scheme OID other
// than the GP-standard 1.2.840.114283.3 drops to standard-sd.
// classifyByCRD requires the GP-standard Card_IDS OID as its
// first gate; any other arc (here, 1.2.840.114283.99) fails the
// gate immediately and never reaches the chip-details and SCP11-
// advertised checks. Pre-fix the classifier matched on the
// GP-standard OID alone and would have classified any GP-
// conformant card as YubiKey; that path is covered by the
// SafeNet test (real card, Card_IDS present, classifies as
// standard-sd because CardChipDetailsOID is set and SCP11 is
// not advertised).
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

// realSafeNetEtokenFusionCRD is the actual Card Recognition Data
// captured from a SafeNet eToken Fusion (Thales-built, OS release
// date 2017-11-30, GP 2.2.1, JavaCard v3, SCP03 only) on
// 2026-05-07 via scpctl probe. It exercises the post-fix
// classification because it carries the same Card Identification
// Scheme OID (1.2.840.114283.3) as YubiKey but is unambiguously
// not a YubiKey.
//
// Differences from realYubiKeyCRD that the classifier must use to
// distinguish the two:
//   - Tag 60 (GP version) is 2.2.1, not 2.3.1 (informational, not
//     used by classifier — versions can collide across vendors).
//   - Tag 64 (SCP) carries SCP03 i=0x10 only, with no SCP11. The
//     SafeNet does not advertise SCP11; YubiKey 5.7+ advertises
//     both. classifyByCRD requires SCP11 in the SCPs list.
//   - Tag 65 (Card Configuration Details) is present
//     (1.2.840.114283.5.7.2.0.0). YubiKey CRD does not include
//     this tag.
//   - Tag 66 inner (Card Chip Details) is present
//     (1.3.6.1.4.1.42.2.110.1.3 = JavaCard v3). YubiKey CRD does
//     not include this tag. classifyByCRD treats presence of this
//     OID as a positive non-YubiKey signal.
var realSafeNetEtokenFusionCRD = mustHex(
	"664E734C" +
		"06072A864886FC6B01" + // GP RID
		"600C060A2A864886FC6B02020201" + // GP 2.2.1
		"630906072A864886FC6B03" + // Card_IDS = 1.2.840.114283.3
		"640B06092A864886FC6B040310" + // SCP03 i=0x10
		"650D060B2A864886FC6B0507020000" + // Card Configuration Details
		"660C060A2B060104012A026E0103") // Card Chip Details: JavaCard v3

// TestProbe_SafeNetEtokenFusionClassifiesAsStandard pins the bug
// fix that motivated tightening the classifier. Pre-fix, the
// SafeNet's CRD classified as yubikey-sd because it carries the
// same Card_IDS OID 1.2.840.114283.3. Post-fix, the explicit
// CardChipDetailsOID and the absence of SCP11 in the advertised
// SCPs both push it to standard-sd.
func TestProbe_SafeNetEtokenFusionClassifiesAsStandard(t *testing.T) {
	tr := &scriptedTransmitter{
		selectSW:   0x9000,
		selectData: realSafeNetEtokenFusionCRD,
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "standard-sd" {
		t.Errorf("expected standard-sd for SafeNet eToken Fusion, got %v", res.Profile)
	}
	if res.CardInfo == nil {
		t.Fatal("CardInfo should be populated for SafeNet CRD (parses successfully)")
	}
	if !res.CardInfo.CardIdentificationOID.Equal(asn1.ObjectIdentifier{1, 2, 840, 114283, 3}) {
		t.Errorf("SafeNet CardIdentificationOID = %v, want 1.2.840.114283.3 "+
			"(this test relies on the OID-collision scenario; if the captured "+
			"OID has changed, the test premise no longer holds)",
			res.CardInfo.CardIdentificationOID)
	}
	// Pin the load-bearing distinguishing signals so a future
	// fixture update can't silently drop them.
	if len(res.CardInfo.CardChipDetailsOID) == 0 {
		t.Error("SafeNet CardChipDetailsOID should be present (JavaCard v3)")
	}
	for _, s := range res.CardInfo.SCPs {
		if s.Version == 0x11 {
			t.Errorf("SafeNet should NOT advertise SCP11; SCPs=%+v", res.CardInfo.SCPs)
		}
	}
}

// TestClassifyByCRD_TableDriven covers the classifier's signal
// matrix directly so each rule has a pinned test independent of
// the Probe wrapper.
func TestClassifyByCRD_TableDriven(t *testing.T) {
	parse := func(b []byte) *cardrecognition.CardInfo {
		info, err := cardrecognition.Parse(b)
		if err != nil {
			t.Fatalf("parse fixture: %v", err)
		}
		return info
	}

	cases := []struct {
		name    string
		info    *cardrecognition.CardInfo
		want    string
		comment string
	}{
		{
			name:    "nil_info",
			info:    nil,
			want:    "standard-sd",
			comment: "no CRD reachable; defensive default",
		},
		{
			name:    "yubikey_5.7.4",
			info:    parse(realYubiKeyCRD),
			want:    "yubikey-sd",
			comment: "Card_IDS present, no chip details, SCP11 advertised",
		},
		{
			name:    "safenet_etoken_fusion",
			info:    parse(realSafeNetEtokenFusionCRD),
			want:    "standard-sd",
			comment: "Card_IDS present (collision with YubiKey), but chip details set and no SCP11",
		},
		{
			name:    "synthetic_no_yubikey_oid",
			info:    parse(nonYubiKeyCRD),
			want:    "standard-sd",
			comment: "Card_IDS arc differs from GP-standard 1.2.840.114283.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := profile.ClassifyByCRD(tc.info)
			if got == nil {
				t.Fatalf("ClassifyByCRD returned nil")
			}
			if got.Name() != tc.want {
				t.Errorf("Name = %q, want %q (%s)", got.Name(), tc.want, tc.comment)
			}
		})
	}
}

// leAwareTransport models a real card's behavior: GET DATA without
// an Le byte (case 1, Le=-1 in apdu.Command) returns SW=9000 with
// an empty body — the card is told "no response data expected" and
// honors that. GET DATA with Le=0 (case 2 short, "send up to 256")
// returns the full CRD.
//
// This pins the wire-shape bug surfaced during YubiKey 5.7.4
// hardware verification: profile.Probe was constructing GET DATA
// with Le=-1 (no Le byte), the YubiKey returned 9000 with no body,
// CardInfo stayed nil, and Probe fell through to Standard for
// every real YubiKey. The fix uses Le=0 (or apdu.NewSelect /
// apdu.NewGetData which set Le=0 by default).
type leAwareTransport struct {
	selectSW   uint16
	selectData []byte
	crdData    []byte
}

func (l *leAwareTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	// For SELECT (case 4: data + Le): the Le byte is the LAST
	// byte if and only if encoded length == 5 + len(Data). When
	// Le=-1 was used, Encode emits no Le byte and the encoded
	// length is exactly 5 + len(Data). When Le=0 was used,
	// Encode emits Le=0x00 and the encoded length is one byte
	// longer.
	hasLe := false
	if cmd.INS == 0xA4 { // SELECT: data present
		hasLe = len(encoded) > 5+len(cmd.Data)
	} else { // GET DATA: no data
		hasLe = len(encoded) > 4
	}

	if !hasLe {
		// Card sees case-1 / case-3 APDU — "no response
		// expected" — and returns empty body.
		return &apdu.Response{
			SW1: byte(l.selectSW >> 8),
			SW2: byte(l.selectSW),
		}, nil
	}

	switch cmd.INS {
	case 0xA4:
		return &apdu.Response{
			SW1:  byte(l.selectSW >> 8),
			SW2:  byte(l.selectSW),
			Data: l.selectData,
		}, nil
	case 0xCA:
		return &apdu.Response{
			SW1:  0x90,
			SW2:  0x00,
			Data: l.crdData,
		}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}

// TestProbe_EncodesGetDataWithLeByte is the regression test for
// the YubiKey 5.7.4 hardware bug where Probe always returned
// standard-sd because GET DATA was sent without an Le byte. With
// the fix, the GET DATA fallback uses Le=0 and the card returns
// the full CRD; Probe correctly classifies as yubikey-sd.
func TestProbe_EncodesGetDataWithLeByte(t *testing.T) {
	tr := &leAwareTransport{
		selectSW:   0x9000,
		selectData: nil, // SELECT FCI body empty — matches YubiKey behavior
		crdData:    realYubiKeyCRD,
	}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Profile == nil || res.Profile.Name() != "yubikey-sd" {
		t.Errorf("expected yubikey-sd (Le=0 wire form), got %v", res.Profile)
	}
	if res.CardInfo == nil {
		t.Fatal("CardInfo should be populated when GET DATA returns CRD")
	}
}

// chained61xxTransmitter models the response shape that broke
// profile.Probe pre-#146: SELECT returns SW=61xx (FCI is xx bytes,
// fetch via GET RESPONSE) instead of SW=9000 plus FCI inline. The
// follow-up GET RESPONSE returns the FCI body under SW=9000. This
// is the wire shape some Thales/Gemalto cards emit when the host
// doesn't supply Le=00 in the SELECT trailer or when the underlying
// PC/SC layer doesn't auto-follow the chain.
type chained61xxTransmitter struct {
	fci []byte
	// Counters so tests can assert the chain was actually followed.
	selectCalls  int
	getRespCalls int
}

func (s *chained61xxTransmitter) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4: // SELECT
		s.selectCalls++
		l := len(s.fci)
		if l > 0xFF {
			l = 0xFF
		}
		return &apdu.Response{SW1: 0x61, SW2: byte(l)}, nil
	case 0xC0: // GET RESPONSE
		s.getRespCalls++
		return &apdu.Response{
			SW1: 0x90, SW2: 0x00,
			Data: append([]byte(nil), s.fci...),
		}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}

// TestProbe_Follows61xxChainOnSelect is the regression for the
// SELECT-with-61xx response pattern. Pre-#146 profile.Probe used
// bare t.Transmit and would have stopped at the 61xx response
// without fetching the FCI; post-#146 it routes through
// apdu.TransmitWithChaining and the chain is followed transparently.
//
// The fixture FCI is the same SCP01-only CRD captured from the
// ML840 hardware investigation, so a successful chain follow
// ends up with profile = standard-sd and SCPs[0].Version = 0x01.
func TestProbe_Follows61xxChainOnSelect(t *testing.T) {
	ml840CRD := mustHex(
		"664C" +
			"734A" +
			"06072A864886FC6B01" + // GP RID
			"600C060A2A864886FC6B02020101" + // GP 2.1.1
			"630906072A864886FC6B03" + // Card_IDS
			"640B06092A864886FC6B040105" + // SCP01 i=05
			"650B06092B8510864864020103" + // Card config
			"660C060A2B060104012A026E0102") // JavaCard v2

	tr := &chained61xxTransmitter{fci: ml840CRD}
	res, err := profile.Probe(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("Probe should follow 61xx chain on SELECT; got err = %v", err)
	}
	if tr.selectCalls != 1 {
		t.Errorf("selectCalls = %d, want 1", tr.selectCalls)
	}
	if tr.getRespCalls != 1 {
		t.Errorf("getRespCalls = %d, want 1 (the chain follow)", tr.getRespCalls)
	}
	if res.CardInfo == nil {
		t.Fatal("CardInfo should be populated after chain follow")
	}
	if len(res.CardInfo.SCPs) != 1 || res.CardInfo.SCPs[0].Version != 0x01 {
		t.Errorf("SCPs = %+v, want one entry with Version=0x01", res.CardInfo.SCPs)
	}
}
