package gp

import "encoding/hex"

// ISDCandidate names a Security Domain AID to probe during ISD
// discovery, paired with a citation for the source. The Source
// field is documentation, not metadata for the host: it exists so
// future additions to the list are reviewed for clean-room
// provenance (no GPL/AGPL/LGPL implementations consulted).
//
// AID may be nil to mean "no AID" — a SELECT with empty data,
// per ISO/IEC 7816-4 §5.3.1 default selection. Some cards
// already have the ISD selected on power-up and respond 9000 to
// a default SELECT; this is a useful sentinel to try last.
type ISDCandidate struct {
	AID    []byte
	Source string
}

// ISDDiscoveryAIDs is the ordered probe list for --discover-sd.
// Order reflects expected hit rate on cards we can validate
// against. New entries must cite a publicly available source
// (GP/ISO spec, vendor datasheet, integration guide) and must
// not be derived from GPL/AGPL/LGPL implementations.
//
// Today's list is intentionally small. Cards that need a
// different AID surface as 6A82 ("file not found") on every
// candidate, and the operator falls back to --sd-aid with the
// AID from the card's vendor documentation. As real-card
// validation discovers commonly-deployed AIDs, they can be
// added here so --discover-sd resolves them automatically.
var ISDDiscoveryAIDs = []ISDCandidate{
	{
		AID:    mustHexAID("A000000151000000"),
		Source: "GP Card Spec v2.3.1 §F.6 (default Issuer Security Domain AID)",
	},
	{
		AID:    mustHexAID("A0000001510000"),
		Source: "GP Card Spec v2.3.1 §F.6 (Card Manager AID, shorter form used by older cards)",
	},
	{
		AID: mustHexAID("A000000018434D00"),
		Source: "GemPlus / Gemalto / Thales Card Manager AID. " +
			"IIN prefix A0000000 18 is the GemPlus RID per ISO/IEC " +
			"7816-5 registration; suffix 434D00 (\"CM\\0\") is " +
			"\"Card Manager\" as used in GemXpresso, IDPrime, IDCore, " +
			"and SafeNet eToken Fusion firmware. Empirically " +
			"confirmed against a SafeNet eToken Fusion (Thales-built, " +
			"OS release date 2017-11-30), where the card returns FCI " +
			"naming this AID as the default-selected application. " +
			"Citation derived from ISO/IEC 7816-5 IIN registration " +
			"and the card's own SELECT response, not from any " +
			"GPL/AGPL/LGPL implementation.",
	},
	{
		AID:    nil,
		Source: "ISO/IEC 7816-4 §5.3.1 (default selection: SELECT with no AID; some cards auto-select the ISD on power-up)",
	},
}

// mustHexAID decodes the hex string at package init. Panic on a
// malformed literal would be a programmer error caught at the
// first build, not a runtime path; the panic shape is fine.
func mustHexAID(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("gp: ISDDiscoveryAIDs hex literal invalid: " + err.Error())
	}
	return b
}
