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
//
// Source field policy. Source is rendered into the operator-
// facing discovery output for every card the candidate is tried
// against. It identifies the AID itself — its registration and
// spec citation — not the card that happens to be in the reader.
// Per-vendor commentary (which firmwares historically advertise
// this AID, which cards we've observed using it) belongs in Go
// comments above the entry rather than in Source, because Source
// gets attached as a "detail" to every card that matches and
// reads as a finding about that specific card. An Oberthur card
// answering A000000018434D00 should not be reported with a
// Gemalto provenance footnote, even though the AID's RID
// component was originally registered to GemPlus.
var ISDDiscoveryAIDs = []ISDCandidate{
	{
		AID:    mustHexAID("A000000151000000"),
		Source: "GP Card Spec v2.3.1 §F.6 (default Issuer Security Domain AID)",
	},
	{
		AID:    mustHexAID("A0000001510000"),
		Source: "GP Card Spec v2.3.1 §F.6 (Card Manager AID)",
	},
	// AID A000000018434D00 has the GemPlus RID (A0000000 18, per
	// ISO/IEC 7816-5 IIN registration) and the conventional
	// "CM\0" suffix denoting Card Manager. Various vendors
	// historically built firmware that advertises this AID,
	// including but not limited to Thales-derived platforms
	// (e.g. SafeNet eToken Fusion, where we have empirical
	// confirmation). The Source string below does not name
	// specific vendor families because matching this AID does
	// not identify the card vendor — Oberthur and other vendors
	// have shipped cards that respond to it as well.
	//
	// Clean-room provenance: derived from ISO/IEC 7816-5 IIN
	// registration plus observed SELECT FCI responses. Not from
	// any GPL/AGPL/LGPL implementation.
	{
		AID:    mustHexAID("A000000018434D00"),
		Source: "AID with GemPlus RID per ISO/IEC 7816-5; \"CM\\0\" suffix denotes Card Manager",
	},
	{
		AID:    nil,
		Source: "ISO/IEC 7816-4 §5.3.1 (default selection: SELECT with empty AID)",
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
