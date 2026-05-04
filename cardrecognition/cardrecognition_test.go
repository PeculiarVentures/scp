package cardrecognition

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// nokia6131CRD is the Card Recognition Data emitted by a Nokia 6131
// NFC phone's GP applet, captured at 0x9000.blogspot.com/2009 and
// reproduced verbatim in the GP wiki examples. It exercises:
//   - GP version 2.1.1 (App-Tag-0 OID 1.2.840.114283.2.2.1.1)
//   - Card ID Scheme present (App-Tag-3)
//   - SCP02 with i=0x55 (App-Tag-4 OID 1.2.840.114283.4.2.85)
//   - inner Chip Details (App-Tag-6)
//
// This is a real card capture, not synthesized. If our parser
// produces output that contradicts the wiki annotation, the parser
// is wrong.
var nokia6131CRD = mustHex(
	"66 4C" +
		"  73 4A" +
		"    06 07 2A864886FC6B 01" +
		"    60 0C" +
		"      06 0A 2A864886FC6B 02 02 01 01" +
		"    63 09" +
		"      06 07 2A864886FC6B 03" +
		"    64 0B" +
		"      06 09 2A864886FC6B 04 02 55" +
		"    65 0B" +
		"      06 09 2B8510864864020103" +
		"    66 0C" +
		"      06 0A 2B060104012A026E0102",
)

func TestParse_Nokia6131(t *testing.T) {
	info, err := Parse(nokia6131CRD)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.GPVersion != "2.1.1" {
		t.Errorf("GPVersion = %q, want %q", info.GPVersion, "2.1.1")
	}
	if info.GPVersionOID != "1.2.840.114283.2.2.1.1" {
		t.Errorf("GPVersionOID = %q, want %q", info.GPVersionOID, "1.2.840.114283.2.2.1.1")
	}
	if info.SCP != 0x02 {
		t.Errorf("SCP = 0x%02X, want 0x02", info.SCP)
	}
	if info.SCPParameter != 0x55 {
		t.Errorf("SCPParameter = 0x%02X, want 0x55", info.SCPParameter)
	}
	if info.SCPVersionOID != "1.2.840.114283.4.2.85" {
		t.Errorf("SCPVersionOID = %q, want %q", info.SCPVersionOID, "1.2.840.114283.4.2.85")
	}
	if info.CardIDSchemeOID != "1.2.840.114283.3" {
		t.Errorf("CardIDSchemeOID = %q, want %q", info.CardIDSchemeOID, "1.2.840.114283.3")
	}
	if len(info.CardConfigurationDetails) == 0 {
		t.Error("CardConfigurationDetails is empty; tag 0x65 was present in input")
	}
	if len(info.ChipDetails) == 0 {
		t.Error("ChipDetails is empty; tag 0x66 (App-Tag-6) was present in input")
	}
	if len(info.UnknownTags) != 0 {
		t.Errorf("UnknownTags should be empty; got %v", info.UnknownTags)
	}
}

// TestParse_SCP03 verifies SCP03 with a typical i parameter.
// Synthetic — no real-card sample for GP 2.3 + SCP03 from the
// blogposts I had to work from. The OID bytes are computed against
// the GP spec definition (App-Tag-4 OID 1.2.840.114283.4.{scp}.{i}).
//
// SCP03 with i=0x70 = 1.2.840.114283.4.3.112
// 0x70 = 112; arc 112 fits in one byte (< 128), so DER is single-byte.
func TestParse_SCP03(t *testing.T) {
	// SCP03 with i=0x70 = OID 1.2.840.114283.4.3.112
	// OID DER value bytes: 2A864886FC6B 04 03 70  (9 bytes)
	// Wrap with universal OID tag: 06 09 ...      (11 bytes)
	// Wrap in App-Tag-4 (SCP):     64 0B ...      (13 bytes)
	// Plus CRD identifier OID:     06 07 2A864886FC6B 01  (9 bytes)
	// Inside 0x73:                                22 bytes -> 73 16
	// Outer envelope:                             24 bytes -> 66 18
	crd := mustHex(
		"66 18" +
			"  73 16" +
			"    06 07 2A864886FC6B 01" +
			"    64 0B" +
			"      06 09 2A864886FC6B 04 03 70",
	)

	info, err := Parse(crd)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SCP != 0x03 {
		t.Errorf("SCP = 0x%02X, want 0x03", info.SCP)
	}
	if info.SCPParameter != 0x70 {
		t.Errorf("SCPParameter = 0x%02X, want 0x70", info.SCPParameter)
	}
}

// TestParse_SCP11 verifies the parser handles SCP11. Synthetic OID
// 1.2.840.114283.4.17.0 (SCP=0x11, i=0x00).
func TestParse_SCP11(t *testing.T) {
	crd := mustHex(
		"66 18" +
			"  73 16" +
			"    06 07 2A864886FC6B 01" +
			"    64 0B" +
			"      06 09 2A864886FC6B 04 11 00",
	)
	info, err := Parse(crd)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SCP != 0x11 {
		t.Errorf("SCP = 0x%02X, want 0x11", info.SCP)
	}
	if info.SCPParameter != 0x00 {
		t.Errorf("SCPParameter = 0x%02X, want 0x00", info.SCPParameter)
	}
}

func TestParse_Empty(t *testing.T) {
	_, err := Parse(nil)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed for empty input; got %v", err)
	}
}

func TestParse_NoOuterTag(t *testing.T) {
	// Just an OID, not wrapped in 0x66.
	bad := mustHex("06 07 2A864886FC6B 01")
	_, err := Parse(bad)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed; got %v", err)
	}
}

func TestParse_NoCRDInside(t *testing.T) {
	// Outer 0x66 but no inner 0x73.
	bad := mustHex("66 09 06 07 2A864886FC6B 01")
	_, err := Parse(bad)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("expected ErrMalformed; got %v", err)
	}
}

func TestParse_UnknownTagsCollected(t *testing.T) {
	// Add a fake App-Tag-9 (0x69) which we don't recognize.
	crd := mustHex(
		"66 16" +
			"  73 14" +
			"    06 07 2A864886FC6B 01" +
			"    69 09" +
			"      06 07 2A864886FC6B 99",
	)
	info, err := Parse(crd)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := info.UnknownTags[0x69]; !ok {
		t.Errorf("UnknownTags[0x69] missing; got %v", info.UnknownTags)
	}
}

// fakeCard is a transport that returns a fixed response regardless
// of input. Used to verify Read() issues the correct GET DATA APDU
// and parses the response.
type fakeCard struct {
	resp []byte
	sw1  byte
	sw2  byte

	gotCmd []byte
}

func (f *fakeCard) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	enc, _ := cmd.Encode()
	f.gotCmd = enc
	return &apdu.Response{Data: f.resp, SW1: f.sw1, SW2: f.sw2}, nil
}
func (f *fakeCard) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (f *fakeCard) Close() error { return nil }

var _ transport.Transport = (*fakeCard)(nil)

// TestRead_IssuesCorrectAPDU verifies Read's wire format:
//   - CLA 0x80 (proprietary, GP convention)
//   - INS 0xCA (GET DATA)
//   - P1=0x00, P2=0x66 (tag for Card Data)
//   - Le present, requesting full response (0x00 = max for short encoding)
func TestRead_IssuesCorrectAPDU(t *testing.T) {
	card := &fakeCard{
		resp: nokia6131CRD,
		sw1:  0x90,
		sw2:  0x00,
	}
	info, err := Read(context.Background(), card)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.GPVersion != "2.1.1" {
		t.Errorf("GPVersion = %q, want %q", info.GPVersion, "2.1.1")
	}
	want := mustHex("80 CA 00 66 00")
	if string(card.gotCmd) != string(want) {
		t.Errorf("APDU mismatch:\n  got %x\n want %x", card.gotCmd, want)
	}
}

// TestRead_NotPresent verifies a card that returns 6A88/6A82 yields
// ErrNotPresent — the typical not-supported indicator.
func TestRead_NotPresent(t *testing.T) {
	card := &fakeCard{sw1: 0x6A, sw2: 0x88}
	_, err := Read(context.Background(), card)
	if !errors.Is(err, ErrNotPresent) {
		t.Errorf("expected ErrNotPresent; got %v", err)
	}
	if !strings.Contains(err.Error(), "6A88") {
		t.Errorf("error should include status word; got %v", err)
	}
}

func TestDecodeArcs_Multibyte(t *testing.T) {
	// 0x81 0x00 = (1<<7)|0 = 128. So arc 128 encoded.
	got := decodeArcs([]byte{0x81, 0x00})
	if len(got) != 1 || got[0] != 128 {
		t.Errorf("decodeArcs(81 00) = %v, want [128]", got)
	}
	// 0x82 0x80 0x00 = ((2<<7)|0)<<7 = absurdly wrong
	// Actually: cur=0; byte=0x82, cur=(0<<7)|2=2, continuation;
	//          byte=0x80, cur=(2<<7)|0=256, continuation;
	//          byte=0x00, cur=(256<<7)|0=32768, terminal => 32768.
	got = decodeArcs([]byte{0x82, 0x80, 0x00})
	if len(got) != 1 || got[0] != 32768 {
		t.Errorf("decodeArcs(82 80 00) = %v, want [32768]", got)
	}
}

func TestDecodeArcs_Truncated(t *testing.T) {
	// Continuation bit on final byte = malformed.
	got := decodeArcs([]byte{0x81})
	if got != nil {
		t.Errorf("decodeArcs with trailing continuation should be nil; got %v", got)
	}
}

// --- helpers ---

// mustHex parses a hex string with arbitrary whitespace into bytes.
func mustHex(s string) []byte {
	cleaned := strings.NewReplacer(" ", "", "\t", "", "\n", "").Replace(s)
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		panic("mustHex: " + err.Error())
	}
	return out
}
