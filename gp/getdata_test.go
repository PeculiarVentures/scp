package gp_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
)

// scriptedTx answers GET DATA APDUs from a precomputed tag→response
// map. Anything not in the map returns SW=6A88 (referenced data not
// found). Captured CPLC/IIN/CIN/KDD/SSC bytes from a real SafeNet
// eToken Fusion drive the happy-path tests.
type scriptedTx struct {
	responses map[uint16]apdu.Response
	calls     []*apdu.Command
}

func (s *scriptedTx) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	s.calls = append(s.calls, cmd)
	if cmd.INS != 0xCA {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	tag := uint16(cmd.P1)<<8 | uint16(cmd.P2)
	if r, ok := s.responses[tag]; ok {
		return &r, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// safeNetCPLCWithHeader is the GET DATA tag 0x9F7F response captured
// from a real SafeNet eToken Fusion (Thales-built, 2026-05-07).
const safeNetCPLCWithHeader = "9F7F2A" +
	"4090" + "7861" + "1291" +
	"7334" + "0100" + "3223" +
	"AA074538" + "2882" +
	"1292" + "3223" +
	"3293" + "3223" +
	"3294" + "3223" +
	"00009004" + "0000" + "0000" + "00000000"

// TestReadCPLC_SafeNet replays the SafeNet GET DATA response and
// asserts the parsed CPLC matches the bytes gppro decoded.
func TestReadCPLC_SafeNet(t *testing.T) {
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x9F7F: {Data: mustHex(t, safeNetCPLCWithHeader), SW1: 0x90, SW2: 0x00},
	}}

	d, err := gp.ReadCPLC(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadCPLC: %v", err)
	}
	if d == nil {
		t.Fatal("ReadCPLC returned nil data on 9000 response")
	}
	if d.SerialNumberHex() != "AA074538" {
		t.Errorf("SerialNumberHex = %q, want AA074538", d.SerialNumberHex())
	}
	if d.ICFabricatorCode() != 0x4090 {
		t.Errorf("ICFabricatorCode = 0x%04X, want 0x4090", d.ICFabricatorCode())
	}
}

// TestReadCPLC_NotPresent confirms that a card returning 6A88 for
// CPLC produces (nil, nil) — the probe-friendly "skipped" shape.
func TestReadCPLC_NotPresent(t *testing.T) {
	tt := &scriptedTx{responses: nil} // empty map → all tags → 6A88

	d, err := gp.ReadCPLC(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadCPLC: %v", err)
	}
	if d != nil {
		t.Errorf("expected nil CPLC on 6A88, got %+v", d)
	}
}

// TestReadCPLC_WrongLengthIsParseError covers the case where a card
// returns 9000 to GET DATA 9F7F but the response is the wrong
// length (corrupted card state, or a non-CPLC response confusingly
// returned at this tag). ReadCPLC must surface the parse error
// rather than treating it as not-present.
func TestReadCPLC_WrongLengthIsParseError(t *testing.T) {
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x9F7F: {Data: []byte{0x9F, 0x7F, 0x10, 0xAA, 0xBB}, SW1: 0x90, SW2: 0x00},
	}}

	_, err := gp.ReadCPLC(context.Background(), tt)
	if err == nil {
		t.Fatal("ReadCPLC should fail on truncated CPLC, got nil err")
	}
	if !strings.Contains(err.Error(), "parse CPLC") {
		t.Errorf("err should mention parse CPLC; got %v", err)
	}
}

// TestReadIIN_SafeNet replays the SafeNet's IIN response. The
// response is the IIN tag 0x42 + length 0x08 + 8 bytes of ASCII
// "GEMALTO " (with trailing space). Verbatim from the gppro trace.
func TestReadIIN_SafeNet(t *testing.T) {
	// 4208 47454D414C544F20  -> 42 08 "GEMALTO "
	iinBytes := mustHex(t, "420847454D414C544F20")
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x0042: {Data: iinBytes, SW1: 0x90, SW2: 0x00},
	}}

	got, err := gp.ReadIIN(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadIIN: %v", err)
	}
	if string(got) != string(iinBytes) {
		t.Errorf("ReadIIN = %X, want %X", got, iinBytes)
	}
	// Sanity: the IIN value (after the 2-byte tag+length header)
	// should ASCII-decode to "GEMALTO ".
	if len(got) >= 2 && string(got[2:]) != "GEMALTO " {
		t.Errorf("IIN value %q does not match expected ASCII %q",
			string(got[2:]), "GEMALTO ")
	}
}

// TestReadIIN_NotPresent confirms 6A88 produces (nil, nil).
func TestReadIIN_NotPresent(t *testing.T) {
	tt := &scriptedTx{responses: nil}
	got, err := gp.ReadIIN(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadIIN: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil IIN on 6A88, got %X", got)
	}
}

// TestReadCIN_SafeNet replays the SafeNet's CIN response.
func TestReadCIN_SafeNet(t *testing.T) {
	cinBytes := mustHex(t, "450A409078612882AA074538")
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x0045: {Data: cinBytes, SW1: 0x90, SW2: 0x00},
	}}
	got, err := gp.ReadCIN(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadCIN: %v", err)
	}
	if string(got) != string(cinBytes) {
		t.Errorf("ReadCIN = %X, want %X", got, cinBytes)
	}
}

// TestReadKDD_SafeNet replays KDD bytes captured from a real card.
func TestReadKDD_SafeNet(t *testing.T) {
	kddBytes := mustHex(t, "CF0A4D003223AA0745382882")
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x00CF: {Data: kddBytes, SW1: 0x90, SW2: 0x00},
	}}
	got, err := gp.ReadKDD(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadKDD: %v", err)
	}
	if string(got) != string(kddBytes) {
		t.Errorf("ReadKDD = %X, want %X", got, kddBytes)
	}
}

// TestReadSSC_SafeNet replays the 5-byte SSC captured from a real
// card. The response shape is SSC tag 0xC1 + 1-byte length + 3
// bytes of counter (matches the gppro trace).
func TestReadSSC_SafeNet(t *testing.T) {
	sscBytes := mustHex(t, "C10300000F")
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x00C1: {Data: sscBytes, SW1: 0x90, SW2: 0x00},
	}}
	got, err := gp.ReadSSC(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadSSC: %v", err)
	}
	if string(got) != string(sscBytes) {
		t.Errorf("ReadSSC = %X, want %X", got, sscBytes)
	}
}

// TestReadCardCapabilities_Present pins the raw-bytes path. The
// fixture is a synthetic Card Capability Information blob shaped
// per GP §H.4: tag 67, length 12, sub-tags 64 (SCP options) and
// 65 (key info). Real cards in the test population (SafeNet
// eToken Fusion, YubiKey 5.x) return SW=6A88 for this tag, so
// the synthetic fixture is the only available regression target
// today; when a card that does answer 0x67 lands in the test
// matrix the synthetic fixture stays as the no-hardware coverage
// and a real-card fixture pins byte-exact decoding.
func TestReadCardCapabilities_Present(t *testing.T) {
	// Synthetic value: 67 0C 64 04 06 02 04 80 65 04 06 02 04 81
	//   67 0C        = Card Capability Information, 12 bytes
	//     64 04      = SCP options, 4 bytes
	//       06 02 04 80   = OID-shaped, 2 bytes (e.g. SCP02 marker)
	//     65 04      = key info, 4 bytes
	//       06 02 04 81   = OID-shaped, 2 bytes
	value := mustHex(t, "670C640406020480650406020481")
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x0067: {Data: value, SW1: 0x90, SW2: 0x00},
	}}
	got, err := gp.ReadCardCapabilities(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadCardCapabilities: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("ReadCardCapabilities = %X, want %X", got, value)
	}
}

// TestReadCardCapabilities_NotPresent confirms 6A88 produces
// (nil, nil) — the SafeNet and YubiKey path. Most cards in the
// wild fall here because Card Capability Information was added
// late in the GP spec timeline and not all card families ship
// it.
func TestReadCardCapabilities_NotPresent(t *testing.T) {
	tt := &scriptedTx{responses: nil}
	got, err := gp.ReadCardCapabilities(context.Background(), tt)
	if err != nil {
		t.Fatalf("ReadCardCapabilities: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on 6A88, got %X", got)
	}
}
func TestRead_AllSafeNet_OneCardOneCall(t *testing.T) {
	tt := &scriptedTx{responses: map[uint16]apdu.Response{
		0x9F7F: {Data: mustHex(t, safeNetCPLCWithHeader), SW1: 0x90, SW2: 0x00},
		0x0042: {Data: mustHex(t, "420847454D414C544F20"), SW1: 0x90, SW2: 0x00},
		0x0045: {Data: mustHex(t, "450A409078612882AA074538"), SW1: 0x90, SW2: 0x00},
		0x00CF: {Data: mustHex(t, "CF0A4D003223AA0745382882"), SW1: 0x90, SW2: 0x00},
		0x00C1: {Data: mustHex(t, "C10300000F"), SW1: 0x90, SW2: 0x00},
	}}

	if _, err := gp.ReadCPLC(context.Background(), tt); err != nil {
		t.Errorf("ReadCPLC: %v", err)
	}
	if _, err := gp.ReadIIN(context.Background(), tt); err != nil {
		t.Errorf("ReadIIN: %v", err)
	}
	if _, err := gp.ReadCIN(context.Background(), tt); err != nil {
		t.Errorf("ReadCIN: %v", err)
	}
	if _, err := gp.ReadKDD(context.Background(), tt); err != nil {
		t.Errorf("ReadKDD: %v", err)
	}
	if _, err := gp.ReadSSC(context.Background(), tt); err != nil {
		t.Errorf("ReadSSC: %v", err)
	}

	// Five GET DATA APDUs, no others. Order matches the call
	// order above so the slice can be inspected positionally
	// without sorting.
	if len(tt.calls) != 5 {
		t.Fatalf("want 5 GET DATA calls, got %d: %+v", len(tt.calls), tt.calls)
	}
	wantTags := []uint16{0x9F7F, 0x0042, 0x0045, 0x00CF, 0x00C1}
	for i, want := range wantTags {
		got := uint16(tt.calls[i].P1)<<8 | uint16(tt.calls[i].P2)
		if got != want {
			t.Errorf("call[%d] tag = 0x%04X, want 0x%04X", i, got, want)
		}
		if tt.calls[i].INS != 0xCA {
			t.Errorf("call[%d] INS = 0x%02X, want 0xCA (GET DATA)", i, tt.calls[i].INS)
		}
	}
}

// TestRead_TransportError_PropagatesUnchanged confirms that a real
// transport-level failure (not just an SW from the card) surfaces as
// a non-IsNotPresent error so callers can distinguish the two.
func TestRead_TransportError_PropagatesUnchanged(t *testing.T) {
	failing := &failingTx{err: errors.New("synthetic PC/SC error")}
	_, err := gp.ReadCPLC(context.Background(), failing)
	if err == nil {
		t.Fatal("ReadCPLC should fail when transport errors")
	}
	if gp.IsNotPresent(err) {
		t.Errorf("transport error must not look like 'not present'; got %v", err)
	}
}

type failingTx struct{ err error }

func (f *failingTx) Transmit(context.Context, *apdu.Command) (*apdu.Response, error) {
	return nil, f.err
}

// TestRead_NilTransport returns a clear error rather than panicking.
func TestRead_NilTransport(t *testing.T) {
	_, err := gp.ReadCPLC(context.Background(), nil)
	if err == nil {
		t.Fatal("ReadCPLC(nil) should fail")
	}
}
