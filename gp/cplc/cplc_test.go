package cplc_test

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/gp/cplc"
)

// safeNetEtokenFusionCPLC is the CPLC blob captured from a SafeNet
// eToken Fusion (Thales-built, OS release date 2017-11-30) on
// 2026-05-07. Includes the 9F 7F 2A tag/length header so the test
// also exercises the TLV-stripping path of Parse.
//
// Decoded fields per gppro's interpretation of the same bytes:
//
//	ICFabricator             = 4090
//	ICType                   = 7861
//	OperatingSystemID        = 1291
//	OperatingSystemReleaseDate = 7334  (Y=7 DDD=334 -> 2017-11-30)
//	OperatingSystemReleaseLevel = 0100
//	ICFabricationDate        = 3223   (Y=3 DDD=223 -> 2023-08-11)
//	ICSerialNumber           = AA074538
//	ICBatchIdentifier        = 2882
//	ICModuleFabricator       = 1292
//	ICModulePackagingDate    = 3223   (2023-08-11)
//	ICCManufacturer          = 3293
//	ICEmbeddingDate          = 3223   (2023-08-11)
//	ICPrePersonalizer        = 3294
//	ICPrePersonalizationEquipmentDate = 3223 (2023-08-11)
//	ICPrePersonalizationEquipmentID   = 00009004
//	ICPersonalizer           = 0000  (uninitialized)
//	ICPersonalizationDate    = 0000  (uninitialized)
//	ICPersonalizationEquipmentID = 00000000 (uninitialized)
const safeNetEtokenFusionCPLCHex = "9F7F2A" +
	"4090" +
	"7861" +
	"1291" +
	"7334" + "0100" +
	"3223" +
	"AA074538" +
	"2882" +
	"1292" + "3223" +
	"3293" + "3223" +
	"3294" + "3223" +
	"00009004" +
	"0000" + "0000" + "00000000"

// safeNetEtokenFusion2CPLCHex is a second SafeNet eToken Fusion CPLC
// blob captured 2026-05-08 from a different physical card than the
// first fixture above. The two cards have the same OS family (1291,
// Thales-built) but differ in chip variant (ICType 7897 vs 7861), OS
// release date (2017-03-31 vs 2017-11-30), OS release level (0400 vs
// 0100), production dates (2022-01-04 vs 2023-08-11), ICC manufacturer
// (6153 vs 3293), and pre-personalizer (6155 vs 3294). Pinning both
// confirms the parser handles the encoding surface a single Thales
// build produces consistently across vendor-code variation, two
// different decade-resolved years (Y=2 -> 2022, Y=3 -> 2023), and
// two different valid BCD day-of-year values.
//
// Decoded fields per gppro's interpretation of the same bytes:
//
//	ICFabricator             = 4090
//	ICType                   = 7897
//	OperatingSystemID        = 1291
//	OperatingSystemReleaseDate = 7090  (Y=7 DDD=090 -> 2017-03-31)
//	OperatingSystemReleaseLevel = 0400
//	ICFabricationDate        = 2004   (Y=2 DDD=004 -> 2022-01-04)
//	ICSerialNumber           = 32196A53
//	ICBatchIdentifier        = A152
//	ICModuleFabricator       = 1292
//	ICModulePackagingDate    = 2004   (2022-01-04)
//	ICCManufacturer          = 6153
//	ICEmbeddingDate          = 2004   (2022-01-04)
//	ICPrePersonalizer        = 6155
//	ICPrePersonalizationEquipmentDate = 2004 (2022-01-04)
//	ICPrePersonalizationEquipmentID   = 00000002
//	ICPersonalizer           = 0000  (uninitialized)
//	ICPersonalizationDate    = 0000  (uninitialized)
//	ICPersonalizationEquipmentID = 00000000 (uninitialized)
const safeNetEtokenFusion2CPLCHex = "9F7F2A" +
	"4090" +
	"7897" +
	"1291" +
	"7090" + "0400" +
	"2004" +
	"32196A53" +
	"A152" +
	"1292" + "2004" +
	"6153" + "2004" +
	"6155" + "2004" +
	"00000002" +
	"0000" + "0000" + "00000000"

// yubiKey5CPLC is the CPLC blob captured from a YubiKey 5C NFC
// firmware 5.7.4 on 2026-05-07. The post-fabrication date fields
// hold per-card serial-derived bytes that don't decode as valid
// BCD; gppro itself prints "Invalid CPLC date" warnings for them.
// The fixture exercises the parser's tolerance of malformed dates.
const yubiKey5CPLCHex = "9F7F2A" +
	"4090" +
	"332B" +
	"F917" +
	"8ED7" + "A0F2" +
	"EA2B" +
	"BD969B1A" +
	"F95C" +
	"A7DA" + "23EB" +
	"E2FF" + "57CA" +
	"47F7" + "E746" +
	"933E485C" +
	"0571" + "CE68" +
	"51809F60"

// fixedClock returns a func that always returns the given time.
// Lets tests pin date resolution against a stable clock reference
// so year-of-decade Y values resolve deterministically.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// TestParse_SafeNet exercises the full happy path against real-card
// CPLC bytes. Fixed the clock at 2026-05-07 so date resolution is
// deterministic regardless of when the test runs.
func TestParse_SafeNet(t *testing.T) {
	clock := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	d, err := cplc.Parse(mustHex(t, safeNetEtokenFusionCPLCHex), fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Vendor codes (2-byte fields).
	for _, c := range []struct {
		name string
		got  [2]byte
		want [2]byte
	}{
		{"ICFabricator", d.ICFabricator, [2]byte{0x40, 0x90}},
		{"ICType", d.ICType, [2]byte{0x78, 0x61}},
		{"OperatingSystemID", d.OperatingSystemID, [2]byte{0x12, 0x91}},
		{"OperatingSystemReleaseLevel", d.OperatingSystemReleaseLevel, [2]byte{0x01, 0x00}},
		{"ICBatchIdentifier", d.ICBatchIdentifier, [2]byte{0x28, 0x82}},
		{"ICModuleFabricator", d.ICModuleFabricator, [2]byte{0x12, 0x92}},
		{"ICCManufacturer", d.ICCManufacturer, [2]byte{0x32, 0x93}},
		{"ICPrePersonalizer", d.ICPrePersonalizer, [2]byte{0x32, 0x94}},
		{"ICPersonalizer", d.ICPersonalizer, [2]byte{0x00, 0x00}},
	} {
		if c.got != c.want {
			t.Errorf("%s = %X, want %X", c.name, c.got, c.want)
		}
	}

	// Serial / equipment IDs (4-byte fields).
	if d.ICSerialNumber != [4]byte{0xAA, 0x07, 0x45, 0x38} {
		t.Errorf("ICSerialNumber = %X, want AA074538", d.ICSerialNumber)
	}
	if d.ICPrePersonalizationEquipmentID != [4]byte{0x00, 0x00, 0x90, 0x04} {
		t.Errorf("ICPrePersonalizationEquipmentID = %X, want 00009004",
			d.ICPrePersonalizationEquipmentID)
	}
	if d.ICPersonalizationEquipmentID != [4]byte{0x00, 0x00, 0x00, 0x00} {
		t.Errorf("ICPersonalizationEquipmentID = %X, want 00000000",
			d.ICPersonalizationEquipmentID)
	}

	// Convenience accessors.
	if got := d.SerialNumberHex(); got != "AA074538" {
		t.Errorf("SerialNumberHex = %q, want AA074538", got)
	}
	if got := d.ICFabricatorCode(); got != 0x4090 {
		t.Errorf("ICFabricatorCode = 0x%04X, want 0x4090", got)
	}

	// Dates.
	wantOSReleaseDate := time.Date(2017, 11, 30, 0, 0, 0, 0, time.UTC)
	if !d.OperatingSystemReleaseDate.Valid {
		t.Errorf("OperatingSystemReleaseDate.Valid = false, want true")
	}
	if got := d.OperatingSystemReleaseDate.Time(); !got.Equal(wantOSReleaseDate) {
		t.Errorf("OperatingSystemReleaseDate = %s, want %s", got, wantOSReleaseDate)
	}

	wantFabDate := time.Date(2023, 8, 11, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		got  cplc.DateField
	}{
		{"ICFabricationDate", d.ICFabricationDate},
		{"ICModulePackagingDate", d.ICModulePackagingDate},
		{"ICEmbeddingDate", d.ICEmbeddingDate},
		{"ICPrePersonalizationEquipmentDate", d.ICPrePersonalizationEquipmentDate},
	} {
		if !c.got.Valid {
			t.Errorf("%s.Valid = false, want true (raw=%X)", c.name, c.got.Raw)
			continue
		}
		if got := c.got.Time(); !got.Equal(wantFabDate) {
			t.Errorf("%s = %s, want %s", c.name, got, wantFabDate)
		}
	}

	// Personalization date is uninitialized (all zeros) so should
	// be Valid=false.
	if d.ICPersonalizationDate.Valid {
		t.Errorf("ICPersonalizationDate should be invalid (uninitialized 0000), got %+v",
			d.ICPersonalizationDate)
	}
	if d.ICPersonalizationDate.Format() != "0000 (raw)" {
		t.Errorf("ICPersonalizationDate.Format() = %q, want %q",
			d.ICPersonalizationDate.Format(), "0000 (raw)")
	}
}

// TestParse_YubiKey_TolerantOfMalformedDates exercises the parser
// against YubiKey 5.7.4 CPLC bytes where most date fields contain
// random per-card serial bytes rather than valid BCD dates. Parse
// must succeed; date fields must report Valid=false; raw bytes
// must round-trip.
func TestParse_YubiKey_TolerantOfMalformedDates(t *testing.T) {
	clock := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	d, err := cplc.Parse(mustHex(t, yubiKey5CPLCHex), fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// ICFabricator should still parse — same Infineon-or-similar
	// code as the SafeNet (4090).
	if d.ICFabricator != [2]byte{0x40, 0x90} {
		t.Errorf("ICFabricator = %X, want 4090", d.ICFabricator)
	}

	// Every date field should be Valid=false but with Raw populated.
	for _, c := range []struct {
		name string
		got  cplc.DateField
	}{
		{"OperatingSystemReleaseDate", d.OperatingSystemReleaseDate},
		{"ICFabricationDate", d.ICFabricationDate},
		{"ICModulePackagingDate", d.ICModulePackagingDate},
		{"ICEmbeddingDate", d.ICEmbeddingDate},
		{"ICPrePersonalizationEquipmentDate", d.ICPrePersonalizationEquipmentDate},
		{"ICPersonalizationDate", d.ICPersonalizationDate},
	} {
		if c.got.Valid {
			t.Errorf("%s.Valid = true on YubiKey CPLC, want false (these fields are random per-card serial bytes)", c.name)
		}
		if c.got.Raw == ([2]byte{}) {
			t.Errorf("%s.Raw should be populated even when invalid", c.name)
		}
	}
}

// TestParse_SafeNet_SecondCard exercises the parser against a second
// physical SafeNet eToken Fusion's CPLC. The two cards differ in
// chip variant, OS release level, ICC manufacturer, pre-personalizer,
// and every production date, so the test covers a different point in
// the input space than TestParse_SafeNet without changing any parser
// invariant. Both Y=2 (resolves to 2022) and Y=7 (resolves to 2017)
// are exercised against a 2026 clock, and DDD=004 (January 4) and
// DDD=090 (March 31) both decode without error.
func TestParse_SafeNet_SecondCard(t *testing.T) {
	clock := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)
	d, err := cplc.Parse(mustHex(t, safeNetEtokenFusion2CPLCHex), fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Spot-check the vendor codes that differ from the first fixture.
	if d.ICType != [2]byte{0x78, 0x97} {
		t.Errorf("ICType = %X, want 7897 (this card's chip variant)", d.ICType)
	}
	if d.ICCManufacturer != [2]byte{0x61, 0x53} {
		t.Errorf("ICCManufacturer = %X, want 6153", d.ICCManufacturer)
	}
	if d.ICPrePersonalizer != [2]byte{0x61, 0x55} {
		t.Errorf("ICPrePersonalizer = %X, want 6155", d.ICPrePersonalizer)
	}
	if d.OperatingSystemReleaseLevel != [2]byte{0x04, 0x00} {
		t.Errorf("OperatingSystemReleaseLevel = %X, want 0400", d.OperatingSystemReleaseLevel)
	}
	if d.ICSerialNumber != [4]byte{0x32, 0x19, 0x6A, 0x53} {
		t.Errorf("ICSerialNumber = %X, want 32196A53", d.ICSerialNumber)
	}

	// Date resolution.
	wantOSReleaseDate := time.Date(2017, 3, 31, 0, 0, 0, 0, time.UTC)
	if !d.OperatingSystemReleaseDate.Valid {
		t.Fatal("OperatingSystemReleaseDate should be valid")
	}
	if got := d.OperatingSystemReleaseDate.Time(); !got.Equal(wantOSReleaseDate) {
		t.Errorf("OS release date = %s, want %s", got, wantOSReleaseDate)
	}

	wantFabDate := time.Date(2022, 1, 4, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		got  cplc.DateField
	}{
		{"ICFabricationDate", d.ICFabricationDate},
		{"ICModulePackagingDate", d.ICModulePackagingDate},
		{"ICEmbeddingDate", d.ICEmbeddingDate},
		{"ICPrePersonalizationEquipmentDate", d.ICPrePersonalizationEquipmentDate},
	} {
		if !c.got.Valid {
			t.Errorf("%s should be valid (raw=%X)", c.name, c.got.Raw)
			continue
		}
		if got := c.got.Time(); !got.Equal(wantFabDate) {
			t.Errorf("%s = %s, want %s", c.name, got, wantFabDate)
		}
	}

	// Personalization fields are uninitialized on this card too.
	if d.ICPersonalizationDate.Valid {
		t.Errorf("ICPersonalizationDate should be invalid (uninitialized)")
	}
	if d.ICPersonalizationEquipmentID != [4]byte{0, 0, 0, 0} {
		t.Errorf("ICPersonalizationEquipmentID = %X, want 00000000", d.ICPersonalizationEquipmentID)
	}
}

// TestParse_AcceptsRawPayload pins that the 42-byte payload form
// (no 9F 7F 2A header) parses identically to the wrapped form.
func TestParse_AcceptsRawPayload(t *testing.T) {
	clock := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	full := mustHex(t, safeNetEtokenFusionCPLCHex)
	payload := full[3:] // strip 9F7F2A
	if len(payload) != cplc.PayloadLength {
		t.Fatalf("test setup: payload len = %d, want %d", len(payload), cplc.PayloadLength)
	}

	wrapped, err := cplc.Parse(full, fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse(wrapped): %v", err)
	}
	bare, err := cplc.Parse(payload, fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse(bare): %v", err)
	}

	// Spot-check a couple of fields plus the dates that the
	// year-of-decade resolution touches.
	if wrapped.ICSerialNumber != bare.ICSerialNumber {
		t.Errorf("serial mismatch wrapped=%X bare=%X",
			wrapped.ICSerialNumber, bare.ICSerialNumber)
	}
	if wrapped.OperatingSystemReleaseDate != bare.OperatingSystemReleaseDate {
		t.Errorf("OS release date mismatch wrapped=%+v bare=%+v",
			wrapped.OperatingSystemReleaseDate, bare.OperatingSystemReleaseDate)
	}
}

// TestParse_RejectsWrongLength covers length validation. 0, 41, 43,
// 44 (which would be a TLV with the wrong header), and 100 bytes
// all fail; the error wraps ErrInvalidLength or ErrMalformedTLV.
func TestParse_RejectsWrongLength(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"empty", nil, cplc.ErrInvalidLength},
		{"41 bytes", make([]byte, 41), cplc.ErrInvalidLength},
		{"43 bytes", make([]byte, 43), cplc.ErrInvalidLength},
		{"45 bytes wrong header", make([]byte, 45), cplc.ErrMalformedTLV},
		{"100 bytes", make([]byte, 100), cplc.ErrInvalidLength},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := cplc.Parse(c.input, nil)
			if err == nil {
				t.Fatalf("Parse(%d bytes) returned nil err, want %v", len(c.input), c.wantErr)
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("err = %v, want errors.Is = %v", err, c.wantErr)
			}
		})
	}
}

// TestParse_NilNowDefaultsToTimeNow confirms the now=nil branch
// uses time.Now without panicking. Doesn't assert specific year
// resolution because that depends on the wall clock.
func TestParse_NilNowDefaultsToTimeNow(t *testing.T) {
	d, err := cplc.Parse(mustHex(t, safeNetEtokenFusionCPLCHex), nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// OS release date Y=7. With time.Now somewhere in 2020s, this
	// resolves to 2007 or 2017; either is acceptable, test just
	// asserts Valid.
	if !d.OperatingSystemReleaseDate.Valid {
		t.Errorf("OS release date should resolve to a valid year against time.Now")
	}
}

// TestDecodeDate_LeapDay366 pins the leap-year guard. Day 366 in
// 2020 (leap) is valid; same encoded date in 2019 (non-leap) is not.
func TestDecodeDate_LeapDay366(t *testing.T) {
	// YDDD = 0366. Y=0, day 366. With clock in 2024, the most
	// recent year ending in 0 is 2020 (leap), so day 366 is valid.
	leap := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	d, err := cplc.Parse(buildCPLCWithOSReleaseDate(t, [2]byte{0x03, 0x66}), fixedClock(leap))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !d.OperatingSystemReleaseDate.Valid {
		t.Errorf("YDDD=0366 in 2020 (leap) should be valid; got %+v", d.OperatingSystemReleaseDate)
	}

	// YDDD = 0366 with clock at June 1 2020. The encoded date
	// would resolve to 2020-12-31 against the initial year
	// resolution (Y=0, current year 2020). But Dec 31 is later in
	// the year than June 1, so the future-date walk-back fires
	// and the year goes back to 2010. 2010 is not a leap year,
	// so day=366 is invalid in the walked-back year and the
	// field is rejected. This case demonstrates the heuristic
	// won't produce a future-relative-to-clock date even when
	// year-digit equals current-year's last digit.
	exact := time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)
	d2, _ := cplc.Parse(buildCPLCWithOSReleaseDate(t, [2]byte{0x03, 0x66}), fixedClock(exact))
	if d2.OperatingSystemReleaseDate.Valid {
		t.Errorf("YDDD=0366 with clock=2020-06-01 should walk back to 2010 (non-leap) and be invalid; got %+v",
			d2.OperatingSystemReleaseDate)
	}

	// YDDD = 0366 with clock in 2025. Most recent year ending in
	// 0 not after 2025 is 2020 — still leap, still valid.
	post := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	d3, _ := cplc.Parse(buildCPLCWithOSReleaseDate(t, [2]byte{0x03, 0x66}), fixedClock(post))
	if !d3.OperatingSystemReleaseDate.Valid {
		t.Errorf("YDDD=0366 with clock=2025 should resolve to leap-year 2020 and be valid")
	}

	// Y=9, day 366. Most recent year ending in 9 not after 2024
	// is 2019 (non-leap). Should be Valid=false.
	d4, _ := cplc.Parse(buildCPLCWithOSReleaseDate(t, [2]byte{0x09, 0x66}), fixedClock(leap))
	if d4.OperatingSystemReleaseDate.Valid {
		t.Errorf("YDDD=9366 with clock=2024 should resolve to non-leap 2019 and be invalid")
	}
}

// TestDecodeDate_RejectsBadBCD covers the non-BCD-nibble path.
func TestDecodeDate_RejectsBadBCD(t *testing.T) {
	clock := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	// 0xAB has nibble A=10 which isn't a decimal digit.
	d, err := cplc.Parse(buildCPLCWithOSReleaseDate(t, [2]byte{0xAB, 0x12}), fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d.OperatingSystemReleaseDate.Valid {
		t.Errorf("non-BCD digit should produce Valid=false; got %+v", d.OperatingSystemReleaseDate)
	}
	// Raw must still round-trip so callers can inspect the bytes.
	if d.OperatingSystemReleaseDate.Raw != [2]byte{0xAB, 0x12} {
		t.Errorf("Raw not preserved on invalid date; got %X", d.OperatingSystemReleaseDate.Raw)
	}
}

// buildCPLCWithOSReleaseDate produces a 45-byte CPLC blob (TLV form)
// with the given 2 bytes at the OS-release-date position and the
// rest of the payload zero. Used to exercise specific date-decoding
// edge cases without authoring a full hex literal each time.
func buildCPLCWithOSReleaseDate(t *testing.T, dateBytes [2]byte) []byte {
	t.Helper()
	out := make([]byte, 0, cplc.PayloadLength+3)
	out = append(out, 0x9F, 0x7F, 0x2A)
	// Offsets: [0..6] = ICFabricator, ICType, OS ID. Date at [6..8].
	for i := 0; i < cplc.PayloadLength; i++ {
		switch i {
		case 6:
			out = append(out, dateBytes[0])
		case 7:
			out = append(out, dateBytes[1])
		default:
			out = append(out, 0x00)
		}
	}
	return out
}

// ml840CPLCHex is the CPLC blob captured from a Thales-built GP 2.1.1
// card with ATR 3B7F96000080318065B0850300EF120FFE829000, presented
// as "ML840" during May 2026 hardware investigation. This card uses
// a different chip generation from the SafeNet eToken Fusion family
// (ICType 7164 vs Fusion's 7861/7897), runs SCP01 only rather than
// SCP03, and has a fabrication date Y=6 D=160 captured during 2026.
//
// Useful as a third real-card CPLC fixture because:
//
//   - ICType 7164 broadens the chip-variant coverage beyond the
//     Fusion family.
//   - The fabrication date Y=6 D=160 exercises the future-date
//     walk-back rule introduced in PR #147. The initial year
//     resolution lands on the current year (2026), but the
//     encoded day-of-year (160 = June 8) is later than today's
//     day-of-year (May 8 = 128 in 2026), so the heuristic walks
//     back a decade to 2016. This matches gppro v25.10.20's
//     interpretation of the same bytes against this card and
//     against the contemporary OS release date (2022-06-21).
//   - The OS release date Y=2 D=172 exercises the previous-decade
//     branch (year != currentYear) and agrees with gppro's
//     interpretation (2022-06-21).
//
// Bytes captured from gppro v25.10.20 GET DATA tag 9F7F response.
const ml840CPLCHex = "9F7F2A" +
	"4090" + // IC fabricator (NXP)
	"7164" + // IC type
	"1291" + // OS ID
	"2172" + // OS release date Y=2 D=172
	"0300" + // OS release level
	"6160" + // IC fabrication date Y=6 D=160
	"2F05211A" + // IC serial
	"254F" + // IC batch
	"1292" + // IC module fabricator
	"6160" + // IC module packaging date
	"5003" + // ICC manufacturer
	"6160" + // IC embedding date
	"5004" + // IC pre-personalizer
	"6160" + // IC pre-personalization equipment date
	"00000047" + // IC pre-personalization equipment ID
	"0000" + // IC personalizer (zero, unprovisioned)
	"0000" + // IC personalization date (zero, unprovisioned)
	"00000000" // IC personalization equipment ID (zero, unprovisioned)

// TestParse_ML840 exercises the parser against the third real-card
// CPLC fixture. Spot-checks the chip-variant codes that differ from
// the SafeNet fixtures, plus the future-date walk-back rule
// introduced in PR #147: when the year-digit matches the current
// year's last digit and the encoded day-of-year is later in the
// year than today, the heuristic walks back a decade. For ML840
// against a 2026 clock this resolves Y=6 D=160 to 2016-06-08
// (gppro's interpretation) rather than 2026-06-09 (the older
// without-context heuristic).
func TestParse_ML840(t *testing.T) {
	clock := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)
	d, err := cplc.Parse(mustHex(t, ml840CPLCHex), fixedClock(clock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if d.ICType != [2]byte{0x71, 0x64} {
		t.Errorf("ICType = %X, want 7164 (ML840 chip variant)", d.ICType)
	}
	if d.ICCManufacturer != [2]byte{0x50, 0x03} {
		t.Errorf("ICCManufacturer = %X, want 5003", d.ICCManufacturer)
	}
	if d.ICSerialNumber != [4]byte{0x2F, 0x05, 0x21, 0x1A} {
		t.Errorf("ICSerialNumber = %X, want 2F05211A", d.ICSerialNumber)
	}

	// Fabrication date Y=6 D=160. Initial year resolution lands
	// on 2026 (current year ends in 6). Encoded day-of-year 160
	// (June 8 in 2016, June 9 in 2026 since 2026 is not leap) is
	// later than clock.YearDay() = 128 (May 8), so the future-date
	// walk-back fires and the year goes back to 2016. 2016 is leap
	// so day 160 = June 8.
	wantFabDate := time.Date(2016, 6, 8, 0, 0, 0, 0, time.UTC)
	if !d.ICFabricationDate.Valid {
		t.Fatal("ICFabricationDate should be valid")
	}
	if got := d.ICFabricationDate.Time(); !got.Equal(wantFabDate) {
		t.Errorf("ICFabricationDate = %s, want %s", got, wantFabDate)
	}

	// OS release date Y=2 D=172. Year resolution lands on 2022
	// (year != currentYear, walk-back doesn't apply). DDD=172 =
	// day-of-year 172 = June 21. This case agrees with gppro's
	// interpretation.
	wantOSReleaseDate := time.Date(2022, 6, 21, 0, 0, 0, 0, time.UTC)
	if !d.OperatingSystemReleaseDate.Valid {
		t.Fatal("OperatingSystemReleaseDate should be valid")
	}
	if got := d.OperatingSystemReleaseDate.Time(); !got.Equal(wantOSReleaseDate) {
		t.Errorf("OS release date = %s, want %s", got, wantOSReleaseDate)
	}

	// Personalizer fields are zero (this card was captured in an
	// unprovisioned state). The parser should leave the date
	// fields at Valid=false rather than synthesizing a date from
	// 0000 bytes.
	if d.ICPersonalizationDate.Valid {
		t.Errorf("ICPersonalizationDate should be invalid (zero bytes); got %s",
			d.ICPersonalizationDate.Time())
	}
}

// TestDecodeDate_FutureWalkBack pins the future-date walk-back rule
// independently of the ML840 fixture. The rule is that when the
// initial year resolution lands on the current year and the encoded
// day-of-year is later in the year than today, the heuristic walks
// back a decade. CPLC dates describe past production events, so a
// resolved date in the future relative to clock is by construction
// the wrong interpretation.
func TestDecodeDate_FutureWalkBack(t *testing.T) {
	// May 8, 2026. clock.YearDay() = 128.
	clock := time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		raw      [2]byte
		wantYear int
		wantDay  int
		wantOK   bool
	}{
		{
			// Y=6 D=323 (Nov 19). Initial resolution: 2026.
			// 323 > 128, walk back to 2016.
			name:     "future_in_current_year_walks_back",
			raw:      [2]byte{0x63, 0x23},
			wantYear: 2016,
			wantDay:  323,
			wantOK:   true,
		},
		{
			// Y=6 D=001 (Jan 1). Initial resolution: 2026.
			// 1 < 128, no walk-back. Stays 2026.
			name:     "past_in_current_year_no_walk_back",
			raw:      [2]byte{0x60, 0x01},
			wantYear: 2026,
			wantDay:  1,
			wantOK:   true,
		},
		{
			// Y=6 D=128 (May 8). Same as today. day == clock.YearDay(),
			// not strictly greater, no walk-back. Stays 2026.
			name:     "today_no_walk_back",
			raw:      [2]byte{0x61, 0x28},
			wantYear: 2026,
			wantDay:  128,
			wantOK:   true,
		},
		{
			// Y=6 D=129 (May 9). One day after today. day > YearDay,
			// walk back to 2016.
			name:     "tomorrow_walks_back",
			raw:      [2]byte{0x61, 0x29},
			wantYear: 2016,
			wantDay:  129,
			wantOK:   true,
		},
		{
			// Y=2 D=323 (Nov 19, 2022). Initial resolution: 2022
			// (year != currentYear). Walk-back doesn't apply. Stays
			// at 2022 even though Nov 19 is after today's date in
			// the year (the rule only fires for current-year matches).
			name:     "previous_decade_unaffected",
			raw:      [2]byte{0x23, 0x23},
			wantYear: 2022,
			wantDay:  323,
			wantOK:   true,
		},
		{
			// Y=0 D=366 (Dec 31). Initial resolution: 2020 (Y=0,
			// most recent year ending in 0 not after 2026). Walk-back
			// doesn't apply since year (2020) != currentYear (2026).
			// 2020 is leap so day 366 is valid.
			name:     "leap_day_in_past_decade_valid",
			raw:      [2]byte{0x03, 0x66},
			wantYear: 2020,
			wantDay:  366,
			wantOK:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := cplc.Parse(buildCPLCWithOSReleaseDate(t, c.raw), fixedClock(clock))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := d.OperatingSystemReleaseDate
			if got.Valid != c.wantOK {
				t.Fatalf("Valid = %v, want %v; got=%+v", got.Valid, c.wantOK, got)
			}
			if !c.wantOK {
				return
			}
			if got.Year != c.wantYear {
				t.Errorf("Year = %d, want %d", got.Year, c.wantYear)
			}
			if got.Day != c.wantDay {
				t.Errorf("Day = %d, want %d", got.Day, c.wantDay)
			}
		})
	}
}
