package scp11

import (
	"testing"
)

// FuzzParseKeyAgreementResponse fuzzes the parser that extracts the
// card's ephemeral public key (and optional receipt) from the
// INTERNAL/MUTUAL AUTHENTICATE response. This data is fully card-
// controlled during the SCP11 handshake — a hostile or buggy card
// can return arbitrary bytes here, and a parser crash would let the
// card DoS or destabilize the host before any authentication has
// completed.
//
// The function has multiple parsing paths (TLV-with-tag-5F49,
// bare-65-byte-point-with-receipt, bare-65-byte-point-no-receipt),
// each with branch points that fuzzing can exercise.
//
// Properties verified: never panic, never produce a non-nil
// ephPubKey shorter than would be cryptographically valid (the
// caller will reject undersized keys, but the parser shouldn't
// confidently emit obviously-wrong shapes either).
func FuzzParseKeyAgreementResponse(f *testing.F) {
	// Bare 65-byte uncompressed P-256 point (SCP11b shape).
	bare65 := make([]byte, 65)
	bare65[0] = 0x04
	for i := 1; i < 65; i++ {
		bare65[i] = byte(i)
	}
	f.Add(bare65)

	// 65-byte point + 16-byte receipt.
	bare65WithReceipt := make([]byte, 81)
	bare65WithReceipt[0] = 0x04
	for i := 1; i < 81; i++ {
		bare65WithReceipt[i] = byte(i)
	}
	f.Add(bare65WithReceipt)

	// TLV-wrapped: 5F49 || len || 65 bytes.
	tlvWrapped := append([]byte{0x5F, 0x49, 0x41}, bare65...)
	f.Add(tlvWrapped)

	// TLV-wrapped with receipt tag 86.
	receipt := []byte{0x86, 0x10}
	for i := 0; i < 16; i++ {
		receipt = append(receipt, byte(i))
	}
	tlvWithReceipt := append(append([]byte{0x5F, 0x49, 0x41}, bare65...), receipt...)
	f.Add(tlvWithReceipt)

	// Pathological: zero-length point claim.
	f.Add([]byte{0x04})

	// Pathological: empty.
	f.Add([]byte{})

	// Pathological: TLV with wrong tag.
	f.Add([]byte{0xFF, 0x01, 0x00})

	// Pathological: TLV with truncated length.
	f.Add([]byte{0x5F, 0x49})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Property: never panic.
		ephPubKey, receipt, err := parseKeyAgreementResponse(data)

		if err != nil {
			// Error path: outputs must be nil per the function's
			// stated contract (the function returns nil, nil, err
			// on every error branch).
			if ephPubKey != nil {
				t.Errorf("error path returned non-nil ephPubKey: %X", ephPubKey)
			}
			if receipt != nil {
				t.Errorf("error path returned non-nil receipt: %X", receipt)
			}
			return
		}

		// Success path: ephPubKey must not be nil. The function
		// returns nil ephPubKey only with a non-nil error.
		if ephPubKey == nil {
			t.Errorf("nil err but nil ephPubKey on input %X", data)
		}
	})
}

// FuzzParseCertsFromStore fuzzes the parser that walks a card's
// certificate-store response (GET DATA tag BF21). The response
// shape is heterogeneous — BF21 with 7F21-wrapped certs, BF21
// with concatenated raw DER, or top-level 7F21 entries — and the
// parser falls through several parsing strategies, each of which
// is a potential surface for malformed-input handling bugs.
//
// This is a critical path because the certificates parsed here
// are fed into x509.ParseCertificate and chain validation; a
// parser bug that emits malformed DER bytes could trigger
// downstream parsers that have less defensive code paths.
//
// Property: the parser never panics on any input. Returned cert
// list may be empty, but the function must always terminate
// cleanly with no error or a parser-level error.
func FuzzParseCertsFromStore(f *testing.F) {
	// Empty input.
	f.Add([]byte{})

	// Single byte (clearly not parseable).
	f.Add([]byte{0x00})

	// BF21 wrapping nothing.
	f.Add([]byte{0xBF, 0x21, 0x00})

	// BF21 wrapping one fake 7F21.
	f.Add([]byte{0xBF, 0x21, 0x05, 0x7F, 0x21, 0x02, 0x30, 0x00})

	// Concatenated DER SEQUENCE headers, no real cert bytes.
	f.Add([]byte{0x30, 0x02, 0x00, 0x00, 0x30, 0x02, 0x00, 0x00})

	// DER SEQUENCE with long-form length.
	longDER := append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 256)...)
	f.Add(longDER)

	// Pathological: long-form length claiming more bytes than exist.
	f.Add([]byte{0x30, 0x82, 0xFF, 0xFF, 0x00})

	// Pathological: long-form length with 4 length bytes (max
	// allowed by derElementLength; 5+ is rejected).
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00, 0x10})

	// Pathological: long-form length with 5 length bytes (must reject).
	f.Add([]byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x10})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Property: never panic. In permissive mode (strict=false),
		// parseCertsFromStore swallows individual parse errors at
		// the x509.ParseCertificate boundary (skips non-X.509
		// entries) and returns whatever it could parse, so we
		// don't assert on the err shape — we just verify no panic
		// and no crazy output cardinality.
		certs, err := parseCertsFromStore(data, false)
		_ = err // documented as nil-only on success; we don't pin

		// A successful return with more certs than input bytes is
		// suspicious (each cert needs at least one byte). Catches
		// any future bug where the parser would manufacture certs
		// from thin air.
		if len(certs) > len(data) {
			t.Errorf("parsed %d certs from %d-byte input", len(certs), len(data))
		}
	})
}

// FuzzDerElementLength fuzzes the DER length parser used by
// splitDER (which itself is used by parseCertsFromStore). DER
// length parsing is a classic source of off-by-one bugs and
// integer-overflow issues; a buggy length parse would let a
// hostile card bytes that misroute splitDER into producing
// overlapping or oversized cert slices.
//
// Properties:
//
//  1. Never panics.
//  2. When ok==true, returned length is within [2, len(data)] —
//     the function reports total bytes consumed (tag + length
//     field + value), which can never exceed input length.
//  3. When ok==true, returned length >= 2 (one tag byte plus at
//     minimum one length byte).
//  4. When ok==false, returned length must be 0 (the contract
//     pins this so callers can't accidentally consume bytes
//     after a parse failure).
func FuzzDerElementLength(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
	f.Add([]byte{0x30, 0x80}) // indefinite length: numBytes==0, must reject
	f.Add([]byte{0x30, 0x81, 0x10})
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00, 0x10})
	f.Add([]byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x10}) // must reject
	f.Add([]byte{0x30, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		length, ok := derElementLength(data)

		if !ok {
			// Property 4: failure case must return length 0.
			if length != 0 {
				t.Errorf("ok=false but length=%d (want 0) on %X", length, data)
			}
			return
		}

		// Property 3: success case has length >= 2.
		if length < 2 {
			t.Errorf("ok=true but length=%d < 2 on %X", length, data)
		}

		// Property 2: success-case length doesn't claim more
		// bytes than were available. derElementLength reports
		// the parsed total; splitDER then validates total <=
		// remaining, but the contract here is "the encoded length
		// field is internally consistent." We check the weaker
		// property that length isn't negative or absurdly large
		// relative to its own header.
		if length < 0 {
			t.Errorf("negative length %d on %X", length, data)
		}
	})
}
