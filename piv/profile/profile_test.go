package profile

import (
	"context"
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
