// Package aid provides a lookup table for SELECT-command Application
// Identifiers (AIDs), mapping AID prefixes to human-readable names and
// categories. Useful for annotating SELECT exchanges in trace files,
// CLI diagnostics, and any other context where "what applet is this
// AID?" needs a quick answer without making the caller maintain their
// own table.
//
// The lookup is prefix-based: the longest matching prefix wins. This
// matches industry convention (longer AIDs are more specific variants
// of broader application families) and means a registry of partial
// AIDs can still answer correctly when a card returns a more specific
// AID in its SELECT response.
//
// # Sources
//
// AID entries are curated from public specifications and several
// established databases:
//
//   - EMV/eID/OpenPGP/FIDO AIDs informed by card-spy handler
//     definitions (https://github.com/tomkp/card-spy).
//   - PIV/GP AIDs from the CardForensics knowledge base
//     (https://github.com/PeculiarVentures/cardforensics), which is
//     also a PeculiarVentures project.
//   - ISO 7816-5, EMV Book 1, NIST SP 800-73-4, FIDO Alliance specs.
//
// This is not an exhaustive list — it covers the AIDs that show up
// in practice when working with security-token, payment, and eID
// cards. Additions welcome; entries should cite a public source.
package aid

import (
	"bytes"
	"encoding/hex"
	"sort"
	"strings"
)

// Category is the broad classification of an AID.
type Category string

const (
	CategoryPayment     Category = "payment"
	CategoryPIV         Category = "piv"
	CategoryPKI         Category = "pki"
	CategoryFIDO        Category = "fido"
	CategoryGP          Category = "gp"
	CategoryEID         Category = "eid"
	CategoryHealth      Category = "health"
	CategorySecurityKey Category = "security-key"
)

// CategoryLabel returns a display-friendly label for the category, or
// the raw category string if no label is registered.
func CategoryLabel(c Category) string {
	switch c {
	case CategoryPayment:
		return "Payment / EMV"
	case CategoryPIV:
		return "PIV / US Government"
	case CategoryPKI:
		return "PKI / Certificates"
	case CategoryFIDO:
		return "FIDO / WebAuthn"
	case CategoryGP:
		return "GlobalPlatform"
	case CategoryEID:
		return "Electronic Identity"
	case CategoryHealth:
		return "Health Card"
	case CategorySecurityKey:
		return "Security Key"
	default:
		return string(c)
	}
}

// Entry is a single AID registry entry.
type Entry struct {
	// Prefix is the AID byte prefix this entry matches. A SELECT
	// command targeting any AID that begins with these bytes will
	// resolve to this entry, unless a longer prefix in the registry
	// also matches.
	Prefix []byte

	// Name is a human-readable identifier — for example,
	// "GP ISD (Issuer Security Domain)" or "NIST PIV".
	Name string

	// Category groups related entries.
	Category Category
}

// PrefixHex returns the entry's prefix as an uppercase hex string.
func (e Entry) PrefixHex() string {
	return strings.ToUpper(hex.EncodeToString(e.Prefix))
}

// Lookup returns the entry whose Prefix is the longest match for
// aidBytes. Returns nil when no entry matches. An empty input also
// returns nil.
func Lookup(aidBytes []byte) *Entry {
	if len(aidBytes) == 0 {
		return nil
	}
	// entries is pre-sorted longest-first, so the first match wins.
	for i := range entries {
		e := &entries[i]
		if len(aidBytes) >= len(e.Prefix) && bytes.HasPrefix(aidBytes, e.Prefix) {
			return e
		}
	}
	return nil
}

// LookupHex is a convenience wrapper around Lookup for callers that
// already have an AID as a hex string. Whitespace is tolerated;
// case is normalized.
func LookupHex(aidHex string) *Entry {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, aidHex)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil
	}
	return Lookup(b)
}

// All returns a copy of every registered entry. The returned slice
// is sorted longest-prefix-first to match Lookup's resolution order.
// Callers that want a different sort can re-sort the result; the
// internal copy is unaffected.
func All() []Entry {
	out := make([]Entry, len(entries))
	copy(out, entries)
	return out
}

// entries is the registry, sorted at package init by descending
// prefix length so longest-prefix-match is just "first match wins."
var entries []Entry

func init() {
	// Source data: each row pairs a hex prefix with a name and
	// category. Hex strings are decoded and validated at init; a
	// bad row would cause init to panic, which is correct — the
	// registry is package data, not user input.
	rows := []struct {
		Hex      string
		Name     string
		Category Category
	}{
		// EMV / Payment
		{"A0000000041010", "Mastercard Credit/Debit", CategoryPayment},
		{"A0000000043060", "Mastercard Maestro", CategoryPayment},
		{"A0000000042203", "Mastercard US Maestro", CategoryPayment},
		{"A00000000410101213", "Mastercard PayPass M/Chip", CategoryPayment},
		{"A00000000410101215", "Mastercard PayPass MStripe", CategoryPayment},
		{"A000000003101001", "Visa Credit", CategoryPayment},
		{"A000000003101002", "Visa Debit", CategoryPayment},
		{"A0000000031010", "Visa Credit/Debit", CategoryPayment},
		{"A0000000032010", "Visa Electron", CategoryPayment},
		{"A0000000033010", "Visa Interlink", CategoryPayment},
		{"A0000000038010", "Visa Plus", CategoryPayment},
		{"A0000000038002", "Visa Plus", CategoryPayment},
		{"A0000000039010", "Visa V Pay", CategoryPayment},
		{"A000000025010104", "American Express", CategoryPayment},
		{"A000000025010701", "American Express ExpressPay", CategoryPayment},
		{"A0000001523010", "Discover", CategoryPayment},
		{"A0000001524010", "Discover Common Debit", CategoryPayment},
		{"A0000000651010", "JCB", CategoryPayment},
		{"A0000002771010", "Interac", CategoryPayment},
		{"325041592E5359532E4444463031", "PSE (Payment System Environment)", CategoryPayment},
		{"325041592E5359532E444446303031", "PPSE (Proximity PSE)", CategoryPayment},

		// PIV / US Government
		{"A000000308000010000100", "NIST PIV", CategoryPIV},
		{"A00000030800001000", "NIST PIV", CategoryPIV},
		{"A000000308000010", "NIST PIV", CategoryPIV},

		// Yubico
		{"A000000527", "Yubico PIV", CategoryPIV},
		{"A0000005272101", "Yubico OTP", CategorySecurityKey},

		// OpenPGP
		{"D27600012401", "OpenPGP", CategoryPKI},

		// FIDO / WebAuthn
		{"A0000006472F0001", "FIDO U2F", CategoryFIDO},
		{"A0000006472F0002", "FIDO2 / CTAP2", CategoryFIDO},

		// GlobalPlatform
		{"A000000151000000", "GP ISD (Issuer Security Domain)", CategoryGP},
		{"A0000001510000", "GP Card Manager", CategoryGP},

		// eID
		{"A000000177504B43532D3135", "Belgian eID (BELPIC)", CategoryEID},
		{"E80704007F00070302", "German eID (nPA)", CategoryEID},
		{"A000000167455349474E", "German eSign", CategoryEID},
		{"D23300000045737445494420763335", "Estonian eID", CategoryEID},
		{"A000000077010800070000FE00000100", "Estonian eID Auth", CategoryEID},
		{"D2760001354B414E4D31", "Portuguese Citizen Card", CategoryEID},
		{"A00000006303100102", "Spanish DNIe Auth", CategoryEID},
		{"A0000000630310", "Spanish DNIe", CategoryEID},
		{"A0000000308001", "Italian CIE", CategoryEID},
		{"A0000000770101", "IAS-ECC", CategoryEID},

		// Gemalto / Thales
		{"A0000001520000", "Gemalto IDPrime", CategoryPKI},

		// Health
		{"D2760001448000", "German Health Card (eGK)", CategoryHealth},
		{"A0000000040000", "European Health Insurance (EHIC)", CategoryHealth},
	}

	entries = make([]Entry, 0, len(rows))
	for _, r := range rows {
		b, err := hex.DecodeString(r.Hex)
		if err != nil {
			panic("aid: invalid hex prefix " + r.Hex + ": " + err.Error())
		}
		entries = append(entries, Entry{Prefix: b, Name: r.Name, Category: r.Category})
	}
	// Longest-prefix-first so Lookup is just "first match wins."
	sort.SliceStable(entries, func(i, j int) bool {
		return len(entries[i].Prefix) > len(entries[j].Prefix)
	})
}
