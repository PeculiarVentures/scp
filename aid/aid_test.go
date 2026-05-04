package aid_test

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/scp/aid"
)

// TestLookup_WellKnown spot-checks well-known AIDs that show up in
// real card traces. Each one should resolve to a non-nil entry with
// the expected name. If any of these regress, an upstream change
// likely dropped or shadowed an entry.
func TestLookup_WellKnown(t *testing.T) {
	cases := []struct {
		name     string
		aid      []byte
		wantName string
		wantCat  aid.Category
	}{
		{
			"GP ISD",
			[]byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			"GP ISD (Issuer Security Domain)",
			aid.CategoryGP,
		},
		{
			"NIST PIV (full 11 bytes)",
			[]byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00},
			"NIST PIV",
			aid.CategoryPIV,
		},
		{
			"Yubico OTP",
			[]byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01},
			"Yubico OTP",
			aid.CategorySecurityKey,
		},
		{
			"FIDO2 / CTAP2",
			[]byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02},
			"FIDO2 / CTAP2",
			aid.CategoryFIDO,
		},
		{
			"OpenPGP",
			[]byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x01},
			"OpenPGP",
			aid.CategoryPKI,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := aid.Lookup(c.aid)
			if got == nil {
				t.Fatalf("Lookup(%X): nil, want %q", c.aid, c.wantName)
			}
			if got.Name != c.wantName {
				t.Errorf("Name = %q, want %q", got.Name, c.wantName)
			}
			if got.Category != c.wantCat {
				t.Errorf("Category = %q, want %q", got.Category, c.wantCat)
			}
			if !bytes.HasPrefix(c.aid, got.Prefix) {
				t.Errorf("returned entry's Prefix %X is not actually a prefix of %X",
					got.Prefix, c.aid)
			}
		})
	}
}

// TestLookup_LongestPrefixWins is the load-bearing semantic of this
// package. A SELECT for Mastercard PayPass M/Chip
// (A0 00 00 00 04 10 10 12 13) should resolve to the more specific
// "Mastercard PayPass M/Chip" entry, NOT to the shorter
// "Mastercard Credit/Debit" prefix that would also match. If this
// test fails, the longest-first sort at init time has regressed
// and downstream callers will see less specific identifications.
func TestLookup_LongestPrefixWins(t *testing.T) {
	mchipAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x12, 0x13}
	got := aid.Lookup(mchipAID)
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.Name != "Mastercard PayPass M/Chip" {
		t.Errorf("Name = %q, want %q (shorter prefix won — sort regression)",
			got.Name, "Mastercard PayPass M/Chip")
	}
}

// TestLookup_NoMatch confirms a non-AID byte sequence resolves to
// nil rather than a false-positive match.
func TestLookup_NoMatch(t *testing.T) {
	if got := aid.Lookup([]byte{0xDE, 0xAD, 0xBE, 0xEF}); got != nil {
		t.Errorf("Lookup(DEADBEEF) = %+v, want nil", got)
	}
	if got := aid.Lookup(nil); got != nil {
		t.Errorf("Lookup(nil) = %+v, want nil", got)
	}
	if got := aid.Lookup([]byte{}); got != nil {
		t.Errorf("Lookup([]) = %+v, want nil", got)
	}
}

// TestLookup_PartialPrefixDoesNotMatch confirms that an AID shorter
// than the registered prefix does NOT match. Lookup is "registered
// prefix is a prefix of input," not "input is a prefix of registered."
// The PIV AID has a 4-byte RID (A0 00 00 03) shared with many other
// applications; a 4-byte input must not resolve to PIV.
func TestLookup_PartialPrefixDoesNotMatch(t *testing.T) {
	got := aid.Lookup([]byte{0xA0, 0x00, 0x00, 0x03})
	if got != nil {
		t.Errorf("Lookup(A0000003) = %+v, want nil — no entry has only that prefix", got)
	}
}

// TestLookupHex confirms the hex-string convenience wrapper accepts
// realistic input including upper/lower case and embedded whitespace.
func TestLookupHex(t *testing.T) {
	cases := []string{
		"A000000151000000",
		"a000000151000000",
		"A0 00 00 01 51 00 00 00",
		"A0\t00\n00 01 51 00 00 00",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			got := aid.LookupHex(c)
			if got == nil || got.Name != "GP ISD (Issuer Security Domain)" {
				t.Errorf("LookupHex(%q) failed; got %+v", c, got)
			}
		})
	}

	// Bad hex returns nil, not a panic.
	if aid.LookupHex("nothex") != nil {
		t.Error("LookupHex(\"nothex\") should return nil")
	}
}

// TestAll_SortedLongestFirst documents the All() ordering invariant.
// Callers building UIs that show "more specific first" can rely on
// this without re-sorting.
func TestAll_SortedLongestFirst(t *testing.T) {
	all := aid.All()
	if len(all) == 0 {
		t.Fatal("All() returned empty")
	}
	for i := 1; i < len(all); i++ {
		if len(all[i].Prefix) > len(all[i-1].Prefix) {
			t.Errorf("All() not longest-first at index %d: %d-byte prefix follows %d-byte prefix",
				i, len(all[i].Prefix), len(all[i-1].Prefix))
		}
	}
}

// TestAll_ReturnsCopy guards against accidental aliasing — a caller
// mutating the returned slice should not corrupt the package-level
// registry. This is a defensive test; if anyone ever changes All()
// to return the internal slice directly, this test catches it.
func TestAll_ReturnsCopy(t *testing.T) {
	first := aid.All()
	if len(first) == 0 {
		t.Fatal("All() returned empty")
	}
	originalName := first[0].Name
	first[0].Name = "MUTATED"

	second := aid.All()
	if second[0].Name != originalName {
		t.Errorf("All() does not return a copy: mutating first[0].Name affected second[0].Name")
	}
}

// TestCategoryLabel covers each declared category and the fallback.
func TestCategoryLabel(t *testing.T) {
	cases := []struct {
		c    aid.Category
		want string
	}{
		{aid.CategoryPayment, "Payment / EMV"},
		{aid.CategoryPIV, "PIV / US Government"},
		{aid.CategoryFIDO, "FIDO / WebAuthn"},
		{aid.CategoryGP, "GlobalPlatform"},
		{aid.Category("unknown-future-category"), "unknown-future-category"},
	}
	for _, c := range cases {
		if got := aid.CategoryLabel(c.c); got != c.want {
			t.Errorf("CategoryLabel(%q) = %q, want %q", c.c, got, c.want)
		}
	}
}
