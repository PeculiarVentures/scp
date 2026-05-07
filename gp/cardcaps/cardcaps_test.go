package cardcaps_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/gp/cardcaps"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// safeNetTokenJCCardCapabilitiesHex is the GET DATA tag 0x67 response
// captured from a SafeNet Token JC (Athena IDProtect platform, GP
// 2.3, SCP03 i=0x10) on 2026-05-08. gppro v25.10.20 emits a warning
// "Bogus data detected, fixing double tag" against these bytes and
// proceeds to decode them; the doubled-67 wrapper is the source of
// the warning. This fixture exercises that wrapper-stripping path
// plus the structural decode of the inner entries.
//
// gppro's decoded interpretation of the same bytes:
//
//	Supports SCP01 i=05 i=15
//	Supports SCP02 i=05 i=15 i=45 i=55
//	Supports SCP03 i=00 i=10 with AES-128 AES-196 AES-256
//	Supported DOM privileges: SecurityDomain, DAPVerification, ...
//	Supported APP privileges: CardLock, ...
//	Supported LFDB hash: SHA-1, SHA-256, SHA-384, SHA-512
//	Supported Token Verification ciphers: ...
//	Supported Receipt Generation ciphers: ...
//	Supported DAP Verification ciphers: ...
const safeNetTokenJCCardCapabilitiesHex = "673E673C" +
	"A00780010181020515" + // SCP01 i=05 i=15
	"A009800102810405154555" + // SCP02 i=05 i=15 i=45 i=55
	"A00A80010381020010820107" + // SCP03 i=00 i=10, key sizes bitmap=07 (AES-128/192/256)
	"8103FFFE80" + // DOM privileges bitmap (16 bits set)
	"82031E0600" + // APP privileges bitmap (6 bits set)
	"830401020304" + // LFDB hash IDs: SHA-1, SHA-256, SHA-384, SHA-512
	"85023B00" + // Token Verification ciphers
	"86023C00" + // Receipt Generation ciphers
	"87023F00" // DAP Verification ciphers

// TestParse_SafeNetTokenJC_RealCard pins the structural decode
// against the real-card fixture and cross-validates the SCP entries
// against gppro's text decode of the same bytes.
func TestParse_SafeNetTokenJC_RealCard(t *testing.T) {
	d, err := cardcaps.Parse(mustHex(t, safeNetTokenJCCardCapabilitiesHex))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(d.SCPEntries) != 3 {
		t.Fatalf("SCPEntries len = %d, want 3", len(d.SCPEntries))
	}

	// SCP01 entry. gppro: "Supports SCP01 i=05 i=15".
	e1 := d.SCPEntries[0]
	if e1.Version != 0x01 {
		t.Errorf("SCP01.Version = 0x%02X, want 0x01", e1.Version)
	}
	if string(e1.IValues) != string([]byte{0x05, 0x15}) {
		t.Errorf("SCP01.IValues = %X, want 0515", e1.IValues)
	}
	if e1.KeySizes != nil {
		t.Errorf("SCP01.KeySizes should be nil; got %X", e1.KeySizes)
	}

	// SCP02 entry. gppro: "Supports SCP02 i=05 i=15 i=45 i=55".
	e2 := d.SCPEntries[1]
	if e2.Version != 0x02 {
		t.Errorf("SCP02.Version = 0x%02X, want 0x02", e2.Version)
	}
	if string(e2.IValues) != string([]byte{0x05, 0x15, 0x45, 0x55}) {
		t.Errorf("SCP02.IValues = %X, want 05154555", e2.IValues)
	}

	// SCP03 entry. gppro: "Supports SCP03 i=00 i=10 with AES-128 AES-196 AES-256".
	// (gppro labels the AES-192 size as "AES-196" — typo in gppro.)
	e3 := d.SCPEntries[2]
	if e3.Version != 0x03 {
		t.Errorf("SCP03.Version = 0x%02X, want 0x03", e3.Version)
	}
	if string(e3.IValues) != string([]byte{0x00, 0x10}) {
		t.Errorf("SCP03.IValues = %X, want 0010", e3.IValues)
	}
	// Key-size bitmap is 0x07 = bits 0,1,2 set = AES-128, AES-192,
	// AES-256. The accessors should reflect that.
	if !e3.HasAES128() {
		t.Error("SCP03 should advertise AES-128")
	}
	if !e3.HasAES192() {
		t.Error("SCP03 should advertise AES-192")
	}
	if !e3.HasAES256() {
		t.Error("SCP03 should advertise AES-256")
	}

	// SCP01 / SCP02 entries don't carry KeySizes, so the AES
	// accessors return false for them.
	if e1.HasAES128() {
		t.Error("SCP01 KeySizes is nil; HasAES128 should be false")
	}

	// Hash algorithms: SHA-1, SHA-256, SHA-384, SHA-512.
	wantHashes := []cardcaps.HashAlgorithm{
		cardcaps.HashSHA1,
		cardcaps.HashSHA256,
		cardcaps.HashSHA384,
		cardcaps.HashSHA512,
	}
	if len(d.HashAlgorithms) != len(wantHashes) {
		t.Fatalf("HashAlgorithms len = %d, want %d", len(d.HashAlgorithms), len(wantHashes))
	}
	for i, want := range wantHashes {
		if d.HashAlgorithms[i] != want {
			t.Errorf("HashAlgorithms[%d] = %v, want %v", i, d.HashAlgorithms[i], want)
		}
	}

	// Privilege and cipher bitmaps surface as raw bytes — no
	// semantic decode shipped today. Just assert the bytes match
	// the input so a regression on naming would be caught.
	if string(d.DOMPrivileges) != string([]byte{0xFF, 0xFE, 0x80}) {
		t.Errorf("DOMPrivileges = %X, want FFFE80", d.DOMPrivileges)
	}
	if string(d.APPPrivileges) != string([]byte{0x1E, 0x06, 0x00}) {
		t.Errorf("APPPrivileges = %X, want 1E0600", d.APPPrivileges)
	}
	if string(d.TokenVerificationCiphers) != string([]byte{0x3B, 0x00}) {
		t.Errorf("TokenVerificationCiphers = %X, want 3B00", d.TokenVerificationCiphers)
	}
	if string(d.ReceiptGenerationCiphers) != string([]byte{0x3C, 0x00}) {
		t.Errorf("ReceiptGenerationCiphers = %X, want 3C00", d.ReceiptGenerationCiphers)
	}
	if string(d.DAPVerificationCiphers) != string([]byte{0x3F, 0x00}) {
		t.Errorf("DAPVerificationCiphers = %X, want 3F00", d.DAPVerificationCiphers)
	}

	if len(d.Unknown) != 0 {
		t.Errorf("no unknown sub-tags expected; got %+v", d.Unknown)
	}
}

// TestHashAlgorithm_String pins the rendered names so the operator-
// facing surface stays stable across releases. Unknown values
// surface in "unknown(0xNN)" form rather than crashing or empty-
// stringing.
func TestHashAlgorithm_String(t *testing.T) {
	cases := []struct {
		h    cardcaps.HashAlgorithm
		want string
	}{
		{cardcaps.HashSHA1, "SHA-1"},
		{cardcaps.HashSHA256, "SHA-256"},
		{cardcaps.HashSHA384, "SHA-384"},
		{cardcaps.HashSHA512, "SHA-512"},
		{cardcaps.HashAlgorithm(0xAB), "unknown(0xAB)"},
	}
	for _, c := range cases {
		if got := c.h.String(); got != c.want {
			t.Errorf("HashAlgorithm(%X).String() = %q, want %q", byte(c.h), got, c.want)
		}
	}
}

// TestParse_AcceptsBareInnerTemplate confirms Parse works against the
// inner template form (no outer doubled-67 wrapper). Some firmware
// might emit just the inner template; the parser should handle both
// shapes identically.
func TestParse_AcceptsBareInnerTemplate(t *testing.T) {
	full := mustHex(t, safeNetTokenJCCardCapabilitiesHex)
	// Strip the outer 67 3E to get the inner 67 3C ... payload.
	bare := full[2:]

	d, err := cardcaps.Parse(bare)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(d.SCPEntries) != 3 {
		t.Errorf("bare-form parse produced %d SCP entries; want 3", len(d.SCPEntries))
	}
}

// TestParse_AcceptsRawPayload confirms Parse works against the raw
// payload without any 67 wrapper. Used for callers that have already
// stripped the GET DATA wrapper themselves.
func TestParse_AcceptsRawPayload(t *testing.T) {
	full := mustHex(t, safeNetTokenJCCardCapabilitiesHex)
	// Strip both 67 LL headers to get the raw sub-tag stream.
	raw := full[4:]

	d, err := cardcaps.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(d.SCPEntries) != 3 {
		t.Errorf("raw-payload parse produced %d SCP entries; want 3", len(d.SCPEntries))
	}
}

// TestParse_RejectsTruncatedInput pins the error path for malformed
// input. A length byte that exceeds the remaining buffer should
// produce ErrTruncated rather than panicking or silently dropping.
func TestParse_RejectsTruncatedInput(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"tag-only", []byte{0x67}},
		{"length-overrun", []byte{0x67, 0x10, 0xAA, 0xBB}}, // says 16 bytes but has 2
		{"sub-tag-overrun", mustHex(t, "67048103FF")},      // outer says 4 bytes but inner 81 says length 3 with only 1 byte
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := cardcaps.Parse(c.input)
			if err == nil {
				t.Fatal("expected error on truncated input; got nil")
			}
			if !errors.Is(err, cardcaps.ErrTruncated) && !errors.Is(err, cardcaps.ErrInvalidWrapper) {
				t.Errorf("err should be ErrTruncated or ErrInvalidWrapper; got %v", err)
			}
		})
	}
}

// TestParse_UnknownSubTagSurfacesAsUnknown confirms unrecognized
// sub-tags don't get silently dropped — they surface via the
// Unknown slice so an operator can see what the card emitted.
func TestParse_UnknownSubTagSurfacesAsUnknown(t *testing.T) {
	// Construct a minimal Card Capability with one known sub-tag
	// (83 02 01 02) and one made-up sub-tag (FF 02 AB CD). Outer
	// length 0x08 covers both inner TLVs.
	input := mustHex(t, "6708"+"83020102"+"FF02ABCD")

	d, err := cardcaps.Parse(input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(d.HashAlgorithms) != 2 {
		t.Errorf("HashAlgorithms = %v, want [01 02]", d.HashAlgorithms)
	}
	if len(d.Unknown) != 1 {
		t.Fatalf("Unknown len = %d, want 1", len(d.Unknown))
	}
	if d.Unknown[0].Tag != 0xFF {
		t.Errorf("Unknown.Tag = 0x%02X, want 0xFF", d.Unknown[0].Tag)
	}
	if string(d.Unknown[0].Value) != string([]byte{0xAB, 0xCD}) {
		t.Errorf("Unknown.Value = %X, want ABCD", d.Unknown[0].Value)
	}
}
