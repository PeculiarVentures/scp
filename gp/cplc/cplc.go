// Package cplc parses Card Production Life Cycle data per
// GlobalPlatform Card Spec v2.3.1 §H.6.
//
// CPLC is a fixed 42-byte structure returned by GET DATA tag 0x9F7F.
// It records the chain of vendors and dates that produced and
// personalized a smart card: IC fabricator, IC type, OS provider, OS
// release date, IC fabrication date, serial number, batch ID, module
// fabricator, module packaging date, ICC manufacturer, embedding
// date, pre-personalizer, pre-personalization date and equipment ID,
// personalizer, personalization date and equipment ID. Reading CPLC
// is the standard way to identify a card's chip family and trace its
// production history without authenticating to the Security Domain.
//
// # Date encoding
//
// CPLC dates are 2-byte BCD values in the format YDDD where Y is the
// least-significant digit of the year and DDD is the day-of-year
// (001–366). The format does not encode a century or decade, so a Y
// value of 7 might mean 2017, 2027, 2007, etc. This package decodes Y
// to the most recent year ending in that digit that is not in the
// future relative to the runtime clock used at parse time. For a
// runtime call in 2026 with Y=7 it returns 2017; with Y=3 it returns
// 2023. Callers needing a different convention can read DateField.Raw
// and reinterpret. Parse takes a now func so tests can pin the clock.
//
// Cards do not always populate every date field. YubiKey 5.x firmware
// fills the post-fabrication date fields with random per-card serial
// bytes that don't decode as valid BCD. Parse marks such fields as
// Valid=false rather than rejecting the whole CPLC. All-zero date
// fields (uninitialized — common for the personalization slots on
// cards that never went through final personalization) decode as
// Valid=false too.
//
// # Vendor codes
//
// CPLC carries 2-byte vendor codes for fabricator, OS provider,
// module fabricator, ICC manufacturer, pre-personalizer, and
// personalizer. The codes are administered by EUROSMART and a
// definitive directory is not freely published. This package exposes
// the codes as raw [2]byte arrays without name resolution; callers
// who want vendor names can supply their own table. Avoiding a
// bundled lookup keeps the parser free of GPL-derived data and small.
package cplc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Tag is the GP Card Spec tag value for CPLC: 0x9F7F. GET DATA with
// P1=0x9F P2=0x7F returns the CPLC structure framed by this tag.
const Tag = 0x9F7F

// PayloadLength is the fixed length of the CPLC value field, in
// bytes. The full GET DATA response includes the 9F7F 2A tag/length
// header, making the response 45 bytes total when present.
const PayloadLength = 42

// Errors returned by Parse.
var (
	// ErrInvalidLength signals the input is not exactly 42 bytes
	// (payload form) or 45 bytes (full TLV form, 9F7F 2A + payload).
	ErrInvalidLength = errors.New("cplc: invalid length")

	// ErrMalformedTLV signals the input started with a tag/length
	// header but the header bytes did not match the expected
	// 9F 7F 2A sequence. Returned only when the input is 44 bytes
	// or longer; shorter inputs are treated as raw payload.
	ErrMalformedTLV = errors.New("cplc: malformed TLV header")
)

// Data is the parsed Card Production Life Cycle structure.
//
// Field order matches GP Card Spec v2.3.1 §H.6 Table H-3. All
// 2-byte vendor codes are exposed as [2]byte arrays so callers can
// compare against a known-vendor table without mediating an integer
// type. Equipment IDs and serial numbers retain their full byte
// width (4 bytes each).
type Data struct {
	ICFabricator                      [2]byte
	ICType                            [2]byte
	OperatingSystemID                 [2]byte
	OperatingSystemReleaseDate        DateField
	OperatingSystemReleaseLevel       [2]byte
	ICFabricationDate                 DateField
	ICSerialNumber                    [4]byte
	ICBatchIdentifier                 [2]byte
	ICModuleFabricator                [2]byte
	ICModulePackagingDate             DateField
	ICCManufacturer                   [2]byte
	ICEmbeddingDate                   DateField
	ICPrePersonalizer                 [2]byte
	ICPrePersonalizationEquipmentDate DateField
	ICPrePersonalizationEquipmentID   [4]byte
	ICPersonalizer                    [2]byte
	ICPersonalizationDate             DateField
	ICPersonalizationEquipmentID      [4]byte
}

// DateField is a 2-byte CPLC date in BCD format YDDD where Y is the
// last decimal digit of the year and DDD is the day-of-year (001 to
// 366). Raw is the 2-byte field as it appears in the CPLC. Year and
// Day are decoded values when Valid is true; both are zero otherwise.
//
// All-zero Raw is treated as "uninitialized" and produces Valid=false
// rather than a year-zero date. Non-BCD digits, day-of-year out of
// range (000 or >366), and other unparseable patterns also produce
// Valid=false with the original Raw bytes preserved for inspection.
type DateField struct {
	Raw   [2]byte
	Year  int
	Day   int
	Valid bool
}

// Time returns the DateField as a time.Time at midnight UTC on the
// decoded calendar date. Returns the zero time.Time when Valid is
// false. Callers wanting a different time zone should reinterpret
// from Year and Day directly.
func (d DateField) Time() time.Time {
	if !d.Valid {
		return time.Time{}
	}
	return time.Date(d.Year, 1, 1, 0, 0, 0, 0, time.UTC).
		AddDate(0, 0, d.Day-1)
}

// Format renders the DateField in YYYY-MM-DD form when Valid, or the
// raw two-byte hex when not.
func (d DateField) Format() string {
	if !d.Valid {
		return fmt.Sprintf("%02X%02X (raw)", d.Raw[0], d.Raw[1])
	}
	return d.Time().Format("2006-01-02")
}

// Parse decodes a CPLC structure.
//
// The input may be either the 42-byte payload (the value field after
// the 9F7F 2A tag/length header) or the full 45-byte TLV beginning
// with 9F 7F 2A. Parse strips the header if present.
//
// The now function is used to resolve the YDDD date encoding to a
// 4-digit year. A nil now means time.Now: the parser picks the most
// recent year ending in Y that is not after now. Tests should pass
// a fixed clock to keep results deterministic.
func Parse(b []byte, now func() time.Time) (*Data, error) {
	payload, err := stripTLV(b)
	if err != nil {
		return nil, err
	}
	if len(payload) != PayloadLength {
		return nil, fmt.Errorf("%w: got %d bytes, want %d (payload) or %d (with 9F7F2A header)",
			ErrInvalidLength, len(b), PayloadLength, PayloadLength+3)
	}
	if now == nil {
		now = time.Now
	}
	clock := now()

	d := &Data{}
	r := reader{buf: payload}
	r.read2(&d.ICFabricator)
	r.read2(&d.ICType)
	r.read2(&d.OperatingSystemID)
	d.OperatingSystemReleaseDate = decodeDate(r.next2(), clock)
	r.read2(&d.OperatingSystemReleaseLevel)
	d.ICFabricationDate = decodeDate(r.next2(), clock)
	r.read4(&d.ICSerialNumber)
	r.read2(&d.ICBatchIdentifier)
	r.read2(&d.ICModuleFabricator)
	d.ICModulePackagingDate = decodeDate(r.next2(), clock)
	r.read2(&d.ICCManufacturer)
	d.ICEmbeddingDate = decodeDate(r.next2(), clock)
	r.read2(&d.ICPrePersonalizer)
	d.ICPrePersonalizationEquipmentDate = decodeDate(r.next2(), clock)
	r.read4(&d.ICPrePersonalizationEquipmentID)
	r.read2(&d.ICPersonalizer)
	d.ICPersonalizationDate = decodeDate(r.next2(), clock)
	r.read4(&d.ICPersonalizationEquipmentID)

	return d, nil
}

// stripTLV returns the payload portion of a CPLC blob.
//
//   - 42 bytes: returned unchanged (assumed payload).
//   - 45 bytes starting with 9F 7F 2A: the header is stripped and
//     the remaining 42 bytes returned.
//   - anything else: ErrInvalidLength or ErrMalformedTLV per shape.
//
// The 44-byte case (header bytes don't match) is reported as malformed
// rather than length-mismatched because its length suggests TLV intent
// — the operator is more likely to want to know the header was wrong
// than the length was off.
func stripTLV(b []byte) ([]byte, error) {
	switch len(b) {
	case PayloadLength:
		return b, nil
	case PayloadLength + 3:
		if b[0] != 0x9F || b[1] != 0x7F || b[2] != PayloadLength {
			return nil, fmt.Errorf("%w: wanted 9F 7F 2A, got %02X %02X %02X",
				ErrMalformedTLV, b[0], b[1], b[2])
		}
		return b[3:], nil
	default:
		return b, nil // fall through to length check in caller
	}
}

// decodeDate interprets a 2-byte CPLC date field. Returns Valid=true
// only for non-zero inputs whose nibbles are all decimal digits and
// whose day-of-year falls in [1, 366].
//
// The year-of-decade ambiguity is resolved against clock by picking
// the most recent year ending in Y that is not in the future relative
// to clock's current date. The rule has two parts:
//
//  1. Initial year resolution picks the most recent year whose last
//     digit equals the encoded year-digit and which is not greater
//     than clock's current year. For yearDigit=2 in 2026 this is
//     2022; for yearDigit=7 in 2026 this is 2017; for yearDigit=6
//     in 2026 this is 2026 (the current year itself).
//
//  2. Future-date walk-back. CPLC dates describe past production
//     events (chip fabrication, module packaging, OS release, etc.),
//     so a resolved date in the future relative to clock is by
//     construction the wrong interpretation. When the initial
//     resolution lands on the current year but the encoded
//     day-of-year is later in the year than today, the heuristic
//     walks back a decade. Without this, a chip whose CPLC says
//     fab-date Y=6 D=323 captured during May 2026 would render as
//     2026-11-19 (six months in the future); with this, the date
//     resolves to 2016-11-19, the more plausible past
//     interpretation.
//
// gppro's behavior on the same data is consistent with rule 2: it
// produces 2016-11-19 for the same bytes against a 2026 clock.
// Until this change our parser produced 2026-11-19, which was the
// "future date" divergence documented in the ML840 fixture comment
// in cplc_test.go.
func decodeDate(raw [2]byte, clock time.Time) DateField {
	d := DateField{Raw: raw}
	if raw[0] == 0 && raw[1] == 0 {
		return d
	}
	digits := [4]int{
		int(raw[0] >> 4),
		int(raw[0] & 0x0F),
		int(raw[1] >> 4),
		int(raw[1] & 0x0F),
	}
	for _, n := range digits {
		if n > 9 {
			return d // not BCD
		}
	}
	yearDigit := digits[0]
	day := digits[1]*100 + digits[2]*10 + digits[3]
	if day < 1 || day > 366 {
		return d
	}
	// Step 1: resolve the year. Walk back from clock's current year
	// until we land on a year ending in yearDigit and not after
	// clock.
	currentYear := clock.Year()
	year := currentYear - ((currentYear - yearDigit) % 10)

	// Step 2: future-date walk-back. If the initial resolution put
	// us on the current year but the encoded day-of-year is later
	// in the year than today, the date would be in the future. CPLC
	// dates are production events and can't be in the future, so
	// walk back a decade. See the function-level comment for the
	// motivating real-card example.
	if year == currentYear && day > clock.YearDay() {
		year -= 10
	}

	// Step 3: reject day=366 in non-leap years rather than silently
	// producing March 1 via time.Date's normalization. Note this
	// has to run after the walk-back: the walked-back year may
	// differ in leap status from the originally-resolved year, and
	// a day=366 date that's invalid against currentYear may be
	// valid against currentYear-10 (or vice versa).
	if day == 366 && !isLeap(year) {
		return d
	}
	d.Year = year
	d.Day = day
	d.Valid = true
	return d
}

// isLeap returns true if year is a Gregorian leap year.
func isLeap(year int) bool {
	if year%400 == 0 {
		return true
	}
	if year%100 == 0 {
		return false
	}
	return year%4 == 0
}

// reader is a tiny cursor over the CPLC payload. It avoids per-call
// length checks because Parse already validated the payload is
// exactly 42 bytes; the field layout is fixed and any bug in the
// layout would surface as a panic in tests, which is the right
// signal for a packaging error.
type reader struct {
	buf []byte
	off int
}

func (r *reader) next2() [2]byte {
	var out [2]byte
	copy(out[:], r.buf[r.off:r.off+2])
	r.off += 2
	return out
}

func (r *reader) read2(out *[2]byte) {
	*out = r.next2()
}

func (r *reader) read4(out *[4]byte) {
	copy(out[:], r.buf[r.off:r.off+4])
	r.off += 4
}

// SerialNumberHex renders the 4-byte IC serial number as 8 uppercase
// hex digits (no separator). Convenience for log lines.
func (d *Data) SerialNumberHex() string {
	return fmt.Sprintf("%02X%02X%02X%02X",
		d.ICSerialNumber[0], d.ICSerialNumber[1],
		d.ICSerialNumber[2], d.ICSerialNumber[3])
}

// ICFabricatorCode returns the 2-byte IC fabricator code as a uint16
// in big-endian order. Useful for callers that maintain a vendor
// lookup table keyed by uint16.
func (d *Data) ICFabricatorCode() uint16 {
	return binary.BigEndian.Uint16(d.ICFabricator[:])
}
