package profile

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
)

func TestYubiKeyVersion_AtLeast(t *testing.T) {
	v := YubiKeyVersion{Major: 5, Minor: 7, Patch: 2}
	cases := []struct {
		major, minor, patch byte
		want                bool
	}{
		{5, 7, 2, true},
		{5, 7, 1, true},
		{5, 7, 3, false},
		{5, 6, 9, true},
		{5, 8, 0, false},
		{4, 9, 9, true},
		{6, 0, 0, false},
	}
	for _, c := range cases {
		got := v.AtLeast(c.major, c.minor, c.patch)
		if got != c.want {
			t.Errorf("v=%s AtLeast(%d.%d.%d) = %v, want %v",
				v, c.major, c.minor, c.patch, got, c.want)
		}
	}
}

func TestParseYubiKeyVersion(t *testing.T) {
	v, err := ParseYubiKeyVersion([]byte{5, 7, 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.String() != "5.7.2" {
		t.Errorf("got %s, want 5.7.2", v)
	}

	if _, err := ParseYubiKeyVersion([]byte{5, 7}); err == nil {
		t.Error("expected error on 2-byte input")
	}
	if _, err := ParseYubiKeyVersion(nil); err == nil {
		t.Error("expected error on nil input")
	}
}

func TestStandardPIVProfile_Capabilities(t *testing.T) {
	p := NewStandardPIVProfile()
	if p.Name() != "standard-piv" {
		t.Errorf("Name = %q", p.Name())
	}

	caps := p.Capabilities()
	if !caps.StandardPIV {
		t.Error("StandardPIV should be true")
	}

	// Standard PIV must not claim YubiKey extensions.
	yubiKeyOnly := []struct {
		name string
		got  bool
	}{
		{"KeyImport", caps.KeyImport},
		{"Reset", caps.Reset},
		{"Attestation", caps.Attestation},
		{"PINPolicy", caps.PINPolicy},
		{"TouchPolicy", caps.TouchPolicy},
		{"ProtectedManagementKey", caps.ProtectedManagementKey},
		{"SCP11bPIV", caps.SCP11bPIV},
		{"KeyMove", caps.KeyMove},
	}
	for _, x := range yubiKeyOnly {
		if x.got {
			t.Errorf("StandardPIV must not claim %s", x.name)
		}
	}

	// Standard algorithms only: RSA-2048, P-256, P-384.
	if caps.SupportsAlgorithm(piv.AlgorithmEd25519) {
		t.Error("StandardPIV must not advertise Ed25519")
	}
	if caps.SupportsAlgorithm(piv.AlgorithmX25519) {
		t.Error("StandardPIV must not advertise X25519")
	}
	for _, a := range []piv.Algorithm{
		piv.AlgorithmRSA2048,
		piv.AlgorithmECCP256,
		piv.AlgorithmECCP384,
	} {
		if !caps.SupportsAlgorithm(a) {
			t.Errorf("StandardPIV must advertise %s", a)
		}
	}

	// Attestation slot is YubiKey-only.
	if caps.SupportsSlot(piv.SlotYubiKeyAttestation) {
		t.Error("StandardPIV must not include attestation slot")
	}

	// Default management-key algorithm is 3DES per SP 800-78-4.
	if caps.DefaultMgmtKeyAlg != piv.ManagementKeyAlg3DES {
		t.Errorf("DefaultMgmtKeyAlg = %s, want 3DES", caps.DefaultMgmtKeyAlg)
	}
}

func TestYubiKeyProfile_5_7_2_Capabilities(t *testing.T) {
	p := NewYubiKeyProfile()
	caps := p.Capabilities()
	if caps.StandardPIV {
		t.Error("YubiKey profile is not StandardPIV")
	}

	for _, want := range []struct {
		name string
		got  bool
	}{
		{"KeyImport", caps.KeyImport},
		{"Reset", caps.Reset},
		{"Attestation", caps.Attestation},
		{"PINPolicy", caps.PINPolicy},
		{"TouchPolicy", caps.TouchPolicy},
		{"ProtectedManagementKey", caps.ProtectedManagementKey},
		{"SCP11bPIV (5.7+)", caps.SCP11bPIV},
		{"KeyMove (5.7+)", caps.KeyMove},
	} {
		if !want.got {
			t.Errorf("YubiKey 5.7.2 should claim %s", want.name)
		}
	}

	// 5.7+ supports Ed25519/X25519.
	if !caps.SupportsAlgorithm(piv.AlgorithmEd25519) {
		t.Error("YubiKey 5.7+ should advertise Ed25519")
	}
	if !caps.SupportsAlgorithm(piv.AlgorithmX25519) {
		t.Error("YubiKey 5.7+ should advertise X25519")
	}

	// 5.4.2+ default management key is AES-192.
	if caps.DefaultMgmtKeyAlg != piv.ManagementKeyAlgAES192 {
		t.Errorf("YubiKey 5.7.2 default mgmt key = %s, want AES-192",
			caps.DefaultMgmtKeyAlg)
	}

	// Attestation slot must be present.
	if !caps.SupportsSlot(piv.SlotYubiKeyAttestation) {
		t.Error("YubiKey profile must include attestation slot")
	}
}

func TestYubiKeyProfile_pre_5_7_NoEd25519_NoSCP11b(t *testing.T) {
	p := NewYubiKeyProfileVersion(YubiKeyVersion{5, 4, 3})
	caps := p.Capabilities()

	if caps.SupportsAlgorithm(piv.AlgorithmEd25519) {
		t.Error("pre-5.7 YubiKey must not advertise Ed25519")
	}
	if caps.SupportsAlgorithm(piv.AlgorithmX25519) {
		t.Error("pre-5.7 YubiKey must not advertise X25519")
	}
	if caps.SCP11bPIV {
		t.Error("pre-5.7 YubiKey must not advertise SCP11b at PIV applet")
	}
	if caps.KeyMove {
		t.Error("pre-5.7 YubiKey must not advertise key move")
	}

	// 5.4.2+ default is AES-192.
	if caps.DefaultMgmtKeyAlg != piv.ManagementKeyAlgAES192 {
		t.Errorf("5.4.3 default = %s, want AES-192", caps.DefaultMgmtKeyAlg)
	}
}

func TestYubiKeyProfile_pre_5_4_2_3DESDefault(t *testing.T) {
	p := NewYubiKeyProfileVersion(YubiKeyVersion{5, 4, 1})
	caps := p.Capabilities()

	if caps.DefaultMgmtKeyAlg != piv.ManagementKeyAlg3DES {
		t.Errorf("5.4.1 default = %s, want 3DES", caps.DefaultMgmtKeyAlg)
	}
}

func TestProbedProfile_Naming(t *testing.T) {
	v := YubiKeyVersion{5, 7, 2}
	pr := &ProbeResult{
		Profile:   NewYubiKeyProfileVersion(v),
		YubiKeyFW: &v,
	}
	probed := NewProbedProfile(pr)
	want := "probed:yubikey-5.7.2"
	if probed.Name() != want {
		t.Errorf("Name = %q, want %q", probed.Name(), want)
	}
}

func TestProbedProfile_NilFallsBackToStandard(t *testing.T) {
	p := NewProbedProfile(nil)
	if p.Name() != "standard-piv" {
		t.Errorf("nil ProbeResult should fall back to standard-piv, got %q",
			p.Name())
	}
}

// fakeTransmitter is a minimal mock for Probe tests. Each call pulls
// one response off the queue; if the queue is empty, the call returns
// an error.
type fakeTransmitter struct {
	responses []apduPair
	calls     []*apdu.Command
}

type apduPair struct {
	resp *apdu.Response
	err  error
}

func (f *fakeTransmitter) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	f.calls = append(f.calls, cmd)
	if len(f.responses) == 0 {
		return nil, errors.New("fakeTransmitter: queue empty")
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return r.resp, r.err
}

func TestProbe_YubiKey(t *testing.T) {
	tx := &fakeTransmitter{
		responses: []apduPair{
			// SELECT AID PIV success with empty response data.
			{resp: &apdu.Response{Data: nil, SW1: 0x90, SW2: 0x00}},
			// GET VERSION returns 5.7.2.
			{resp: &apdu.Response{Data: []byte{5, 7, 2}, SW1: 0x90, SW2: 0x00}},
		},
	}
	res, err := Probe(context.Background(), tx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if res.YubiKeyFW == nil {
		t.Fatal("YubiKeyFW should be populated")
	}
	if res.YubiKeyFW.String() != "5.7.2" {
		t.Errorf("firmware = %s, want 5.7.2", res.YubiKeyFW)
	}
	if res.Profile.Name() != "yubikey-5.7.2" {
		t.Errorf("Profile.Name = %q, want yubikey-5.7.2", res.Profile.Name())
	}

	// Verify the right APDUs were sent.
	if len(tx.calls) != 2 {
		t.Fatalf("expected 2 APDUs, got %d", len(tx.calls))
	}
	if tx.calls[0].INS != 0xA4 || tx.calls[0].P1 != 0x04 {
		t.Errorf("first APDU is not SELECT: INS=%02X P1=%02X",
			tx.calls[0].INS, tx.calls[0].P1)
	}
	if tx.calls[1].INS != 0xFD {
		t.Errorf("second APDU INS=%02X, want 0xFD (GET VERSION)",
			tx.calls[1].INS)
	}
}

func TestProbe_StandardPIV_When_GetVersion_6D00(t *testing.T) {
	tx := &fakeTransmitter{
		responses: []apduPair{
			{resp: &apdu.Response{Data: nil, SW1: 0x90, SW2: 0x00}},
			// GET VERSION not supported on this card.
			{resp: &apdu.Response{Data: nil, SW1: 0x6D, SW2: 0x00}},
		},
	}
	res, err := Probe(context.Background(), tx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if res.YubiKeyFW != nil {
		t.Errorf("YubiKeyFW should be nil on 6D00, got %v", res.YubiKeyFW)
	}
	if res.Profile.Name() != "standard-piv" {
		t.Errorf("Profile.Name = %q, want standard-piv", res.Profile.Name())
	}
}

func TestProbe_NoApplet(t *testing.T) {
	tx := &fakeTransmitter{
		responses: []apduPair{
			// Full AID: card has no PIV applet.
			{resp: &apdu.Response{Data: nil, SW1: 0x6A, SW2: 0x82}},
			// Truncated AID fallback: same card, same answer.
			{resp: &apdu.Response{Data: nil, SW1: 0x6A, SW2: 0x82}},
		},
	}
	_, err := Probe(context.Background(), tx)
	if err == nil {
		t.Fatal("expected error when SELECT returns 6A82")
	}
	if !errors.Is(err, ErrNoPIVApplet) {
		t.Errorf("expected ErrNoPIVApplet, got %v", err)
	}
}

func TestCapabilities_Helpers(t *testing.T) {
	c := Capabilities{
		Algorithms: []piv.Algorithm{piv.AlgorithmECCP256},
		Slots:      []piv.Slot{piv.SlotPIVAuthentication},
		MgmtKeyAlgs: []piv.ManagementKeyAlgorithm{
			piv.ManagementKeyAlgAES192,
		},
	}
	if !c.SupportsAlgorithm(piv.AlgorithmECCP256) {
		t.Error("expected SupportsAlgorithm(ECCP256) true")
	}
	if c.SupportsAlgorithm(piv.AlgorithmRSA2048) {
		t.Error("expected SupportsAlgorithm(RSA2048) false")
	}
	if !c.SupportsSlot(piv.SlotPIVAuthentication) {
		t.Error("expected SupportsSlot(9a) true")
	}
	if c.SupportsSlot(piv.SlotDigitalSignature) {
		t.Error("expected SupportsSlot(9c) false")
	}
	if !c.SupportsMgmtKeyAlg(piv.ManagementKeyAlgAES192) {
		t.Error("expected SupportsMgmtKeyAlg(AES192) true")
	}
	if c.SupportsMgmtKeyAlg(piv.ManagementKeyAlg3DES) {
		t.Error("expected SupportsMgmtKeyAlg(3DES) false")
	}
}

// TestProbe_Follows61xxChainOnSelect is the regression for the
// PIV SELECT 61xx response shape observed against a GoldKey
// Security PIV Token (ATR 3B941881B1807D1F0319C80050DC). Pre-fix,
// SELECT AID PIV returning SW=611E was reported as
// ErrNoPIVApplet because the bare Transmit didn't follow the
// chain. Post-fix, apdu.TransmitWithChaining fetches the 30-byte
// application property template via GET RESPONSE and Probe parses
// it normally. Same bug class as PR #144 / #146 in the Security
// Domain SELECT path.
func TestProbe_Follows61xxChainOnSelect(t *testing.T) {
	// Simulate a GoldKey-style response: SELECT AID PIV responds
	// with SW=611E (30 bytes available); GET RESPONSE returns a
	// minimal but parseable application property template (tag
	// 0x61 outer, tag 5FC107 version 010000 inner, padded to 30
	// bytes with extra 5FC102 application label bytes). The
	// content doesn't matter for the regression — only that the
	// chain is followed and Probe returns success rather than
	// ErrNoPIVApplet.
	appPropTemplate := []byte{
		0x61, 0x1C, // outer tag, length 28
		0x5F, 0xC1, 0x07, 0x03, 0x01, 0x00, 0x00, // PIV version 1.0.0
		0x5F, 0xC1, 0x02, 0x10, // application label, length 16
		'P', 'I', 'V', ' ', 'C', 'a', 'r', 'd', // 8 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pad to 16
		// total payload: 2 + 7 + 4 + 16 = 29 bytes? Let me count
		// outer header (2) + 5FC107 TLV (7) + 5FC102 TLV (20) = 29.
		// Add one filler byte to hit 30 to match SW=611E.
		0x00,
	}
	tx := &fakeTransmitter{
		responses: []apduPair{
			// SELECT AID PIV (full AID) returns SW=611E.
			{resp: &apdu.Response{Data: nil, SW1: 0x61, SW2: 0x1E}},
			// GET RESPONSE Le=0x1E returns the 30-byte template
			// with terminal 9000.
			{resp: &apdu.Response{Data: appPropTemplate, SW1: 0x90, SW2: 0x00}},
			// GET VERSION not supported (this isn't a YubiKey).
			{resp: &apdu.Response{Data: nil, SW1: 0x6D, SW2: 0x00}},
		},
	}
	res, err := Probe(context.Background(), tx)
	if err != nil {
		t.Fatalf("Probe should follow 61xx chain; got err = %v", err)
	}
	if res.Profile.Name() != "standard-piv" {
		t.Errorf("Profile.Name = %q, want standard-piv", res.Profile.Name())
	}
	// Confirm the chain was actually followed: SELECT + GET
	// RESPONSE + GET VERSION = 3 APDUs.
	if len(tx.calls) != 3 {
		t.Fatalf("expected 3 APDUs (SELECT + GET RESPONSE + GET VERSION); got %d", len(tx.calls))
	}
	if tx.calls[0].INS != 0xA4 {
		t.Errorf("first APDU INS=%02X, want 0xA4 (SELECT)", tx.calls[0].INS)
	}
	if tx.calls[1].INS != 0xC0 {
		t.Errorf("second APDU INS=%02X, want 0xC0 (GET RESPONSE)", tx.calls[1].INS)
	}
	if tx.calls[2].INS != 0xFD {
		t.Errorf("third APDU INS=%02X, want 0xFD (GET VERSION)", tx.calls[2].INS)
	}
}

// TestProbe_GoldKey_RealBytesSelectResponse pins the application
// property template captured from a GoldKey Security PIV Token
// (ATR 3B941881B1807D1F0319C80050DC) on May 2026. This is the
// first non-YubiKey real-bytes PIV SELECT response in the test
// suite. Its value is in the precise wire shape: a spec-conformant
// SP 800-73-4 §3.1.3 application property template that omits the
// optional PIV Version Number (tag 5FC107) and the optional
// application label (tag 5FC102), carrying only the AID and the
// coexistent tag allocation authority.
//
// The bytes:
//
//	61 1C                                                     -- outer template, 28 bytes
//	  4F 0B A000000308000010000100                            -- AID (full 11-byte PIV PIX)
//	  79 0D                                                   -- coexistent tag allocation authority, 13 bytes
//	    4F 0B A000000308000010000100                          -- the AID again (NIST conventional shape)
//
// Probe should classify this card as standard-piv (no GET VERSION
// support, so the YubiKey detection misses), populate
// SelectResponse with the raw 30 bytes, and return PIVVersion=nil
// (the optional tag 5FC107 is absent).
//
// This fixture catches regressions in two places: (1) a future
// change to the SELECT-response handling that drops bytes or
// mis-parses the outer template; (2) a future change to
// findAppPropertyVersion that synthesizes a version from absent
// tags. Both would be wrong against this real card.
func TestProbe_GoldKey_RealBytesSelectResponse(t *testing.T) {
	const goldKeyPIVSelectHex = "611c" +
		"4f0ba000000308000010000100" +
		"790d4f0ba000000308000010000100"

	raw, err := hex.DecodeString(goldKeyPIVSelectHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	tx := &fakeTransmitter{
		responses: []apduPair{
			// SELECT AID PIV returns the GoldKey-captured template.
			{resp: &apdu.Response{Data: raw, SW1: 0x90, SW2: 0x00}},
			// GET VERSION not supported (this is not a YubiKey).
			{resp: &apdu.Response{Data: nil, SW1: 0x6D, SW2: 0x00}},
		},
	}
	res, err := Probe(context.Background(), tx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if res.Profile.Name() != "standard-piv" {
		t.Errorf("Profile.Name = %q, want standard-piv", res.Profile.Name())
	}
	if res.YubiKeyFW != nil {
		t.Errorf("YubiKeyFW should be nil on a non-YubiKey card; got %+v", res.YubiKeyFW)
	}
	if !bytes.Equal(res.SelectResponse, raw) {
		t.Errorf("SelectResponse = %X, want %X", res.SelectResponse, raw)
	}
	if res.PIVVersion != nil {
		t.Errorf("PIVVersion should be nil on a card that omits tag 5FC107; got %X",
			res.PIVVersion)
	}
}

// TestProbe_FeitianPIVKey_RealBytesSelectResponse pins the
// application property template captured from a Feitian-built
// Taglio PIVKey (ATR 3B9F958131FE9F006646530510001171DF000000000002,
// reader "FeiTian.Ltd USB Token 1.00") on May 2026. This is the
// second non-YubiKey real-bytes PIV SELECT in the test suite,
// alongside the GoldKey fixture.
//
// Its value is a third distinct response shape across our
// fixture set:
//
//	YubiKey 5.7+: 17-byte template, 6-byte truncated PIX,
//	              5-byte RID in the coexistent allocation tag.
//	GoldKey:      28-byte template, 11-byte full PIX,
//	              11-byte full PIX echoed in the coexistent tag.
//	Feitian:      22-byte template, 11-byte full PIX,
//	              5-byte RID in the coexistent tag (asymmetric).
//
// The bytes:
//
//	61 16                                                     -- outer template, 22 bytes
//	  4F 0B A000000308000010000100                            -- AID (full 11-byte PIV PIX)
//	  79 07                                                   -- coexistent tag allocation authority, 7 bytes
//	    4F 05 A000000308                                      -- RID only (NIST 5-byte RID)
//
// Probe should classify as standard-piv (no GET VERSION → not
// YubiKey), populate SelectResponse with the raw 24 bytes, and
// return PIVVersion=nil (the optional tag 5FC107 is absent).
//
// This card holds a real CA-signed PIV cert (PIVKey 905D0709...,
// signed by PIVKey Device Certificate Authority, valid through
// 2027-01-26) and the Feitian platform is widely deployed in
// federal contracting environments. Its presence in the fixture
// set is therefore meaningful coverage, not just a curiosity.
//
// Cross-vendor note: gppro (v25.10.20) cannot identify this card
// and emits 'Could not auto-detect ISD AID' against the SELECT
// response, because the Feitian's response to default-SELECT is
// the bare CRD (tag 0x66) rather than an FCI template (tag 0x6F)
// wrapping the CRD. scpctl's SD probe handles both shapes; this
// fixture exercises the bare-CRD path.
func TestProbe_FeitianPIVKey_RealBytesSelectResponse(t *testing.T) {
	const feitianPIVSelectHex = "6116" +
		"4f0ba000000308000010000100" +
		"79074f05a000000308"

	raw, err := hex.DecodeString(feitianPIVSelectHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if len(raw) != 24 {
		t.Fatalf("fixture: expected 24 bytes, got %d", len(raw))
	}

	tx := &fakeTransmitter{
		responses: []apduPair{
			// SELECT AID PIV returns the Feitian-captured template.
			{resp: &apdu.Response{Data: raw, SW1: 0x90, SW2: 0x00}},
			// GET VERSION not supported (Feitian is not a YubiKey).
			{resp: &apdu.Response{Data: nil, SW1: 0x6D, SW2: 0x00}},
		},
	}
	res, err := Probe(context.Background(), tx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if res.Profile.Name() != "standard-piv" {
		t.Errorf("Profile.Name = %q, want standard-piv", res.Profile.Name())
	}
	if res.YubiKeyFW != nil {
		t.Errorf("YubiKeyFW should be nil on a non-YubiKey card; got %+v", res.YubiKeyFW)
	}
	if !bytes.Equal(res.SelectResponse, raw) {
		t.Errorf("SelectResponse = %X, want %X", res.SelectResponse, raw)
	}
	if res.PIVVersion != nil {
		t.Errorf("PIVVersion should be nil on a card that omits tag 5FC107; got %X",
			res.PIVVersion)
	}
}

// TestYubiKeyVersion_IsROCAAffected pins the affected-firmware
// range from Yubico Security Advisory YSA-2017-01: 4.2.6 inclusive
// through 4.3.4 inclusive. Edge cases on both sides of the range
// must report false. Anything outside major version 4 reports
// false unconditionally.
func TestYubiKeyVersion_IsROCAAffected(t *testing.T) {
	cases := []struct {
		v    YubiKeyVersion
		want bool
		why  string
	}{
		// Affected range edges.
		{YubiKeyVersion{4, 2, 6}, true, "lower edge inclusive (4.2.6)"},
		{YubiKeyVersion{4, 3, 4}, true, "upper edge inclusive (4.3.4)"},
		// Real-world capture from this commit's motivating run.
		{YubiKeyVersion{4, 3, 1}, true, "captured in the wild May 2026"},
		// Just outside on both sides.
		{YubiKeyVersion{4, 2, 5}, false, "just below lower edge (4.2.5)"},
		{YubiKeyVersion{4, 3, 5}, false, "just above upper edge (4.3.5, the fix)"},
		// Inside major 4 but minor outside the affected window.
		{YubiKeyVersion{4, 0, 0}, false, "4.0 predates affected range"},
		{YubiKeyVersion{4, 1, 9}, false, "4.1 predates affected range"},
		{YubiKeyVersion{4, 4, 0}, false, "4.4+ never shipped but should report false"},
		// Other major versions.
		{YubiKeyVersion{3, 9, 9}, false, "major 3 unaffected"},
		{YubiKeyVersion{5, 0, 0}, false, "major 5 unaffected"},
		{YubiKeyVersion{5, 7, 4}, false, "current firmware unaffected"},
	}
	for _, tc := range cases {
		got := tc.v.IsROCAAffected()
		if got != tc.want {
			t.Errorf("YubiKeyVersion%v.IsROCAAffected() = %v, want %v (%s)",
				tc.v, got, tc.want, tc.why)
		}
	}
}
