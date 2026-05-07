package securitydomain

import (
	"bytes"
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// StatusScope identifies which subset of the card registry GetStatus
// queries. Maps to the P1 byte per GP §11.4.2.
type StatusScope byte

const (
	// StatusScopeISD selects the Issuer Security Domain only.
	StatusScopeISD StatusScope = 0x80

	// StatusScopeApplications selects Applications and SSDs.
	StatusScopeApplications StatusScope = 0x40

	// StatusScopeLoadFiles selects Executable Load Files only.
	StatusScopeLoadFiles StatusScope = 0x20

	// StatusScopeLoadFilesAndModules selects Executable Load Files
	// and their Executable Modules. The same load files appear as
	// in StatusScopeLoadFiles, but each entry's Modules field is
	// populated.
	StatusScopeLoadFilesAndModules StatusScope = 0x10
)

// String returns a short identifier for the scope.
func (s StatusScope) String() string {
	switch s {
	case StatusScopeISD:
		return "ISD"
	case StatusScopeApplications:
		return "Applications"
	case StatusScopeLoadFiles:
		return "LoadFiles"
	case StatusScopeLoadFilesAndModules:
		return "LoadFilesAndModules"
	default:
		return fmt.Sprintf("StatusScope(0x%02X)", byte(s))
	}
}

// RegistryEntry is one row of the card registry returned by GetStatus.
// Which fields are populated depends on Scope.
type RegistryEntry struct {
	// AID is the entry's primary AID. Always populated.
	AID []byte

	// Scope is the StatusScope that produced this entry. Knowing it
	// lets callers interpret Lifecycle (each scope has its own
	// lifecycle state machine per GP §5.3).
	Scope StatusScope

	// Lifecycle is the raw GP lifecycle byte. Use LifecycleString
	// for a human-readable interpretation.
	Lifecycle byte

	// Privileges is the decoded privilege set. Zero value when the
	// entry is a Load File or Module, which carry no privileges.
	Privileges Privileges

	// Version is the load file version. Populated only for
	// Load File scopes when the card returns tag 0xCE.
	Version []byte

	// AssociatedSDAID is the AID of the Security Domain associated
	// with this entry. Populated when the card returns tag 0xCC.
	AssociatedSDAID []byte

	// Modules holds Executable Module AIDs. Populated only when
	// Scope == StatusScopeLoadFilesAndModules.
	Modules [][]byte
}

// LifecycleString returns a human-readable interpretation of the
// lifecycle byte appropriate to this entry's Scope. Returns
// "unknown(0xXX)" if no interpretation matches.
func (e RegistryEntry) LifecycleString() string {
	switch e.Scope {
	case StatusScopeISD:
		switch e.Lifecycle {
		case 0x01:
			return "OP_READY"
		case 0x07:
			return "INITIALIZED"
		case 0x0F:
			return "SECURED"
		case 0x7F:
			return "CARD_LOCKED"
		case 0xFF:
			return "TERMINATED"
		}
	case StatusScopeApplications:
		// Applications per GP Card Spec §11.1.1 Table 11-1:
		//   0x03 INSTALLED
		//   0x07 SELECTABLE
		//   0x0F PERSONALIZED
		//   0x83 LOCKED (locked from INSTALLED)
		//   0x87 LOCKED (locked from SELECTABLE)
		//   0x8F LOCKED (locked from PERSONALIZED)
		//
		// LOCKED is encoded as the underlying state with bit 7
		// (0x80) set. We match only the three legitimate
		// locked-state encodings rather than any high-bit byte.
		// An earlier revision used `e.Lifecycle&0x80 != 0` which
		// would over-label values like 0x80 (no underlying state)
		// or 0xFF (TERMINATED on the ISD; nonsensical on an app
		// row but observed on cards in unusual states) as LOCKED.
		// GlobalPlatformPro uses the more precise predicate
		// `(v & 0x83) == 0x83` for the same reason; we extend
		// that to cover the SELECTABLE-derived (0x87) and
		// PERSONALIZED-derived (0x8F) locked states too.
		switch e.Lifecycle {
		case 0x03:
			return "INSTALLED"
		case 0x07:
			return "SELECTABLE"
		case 0x0F:
			return "PERSONALIZED"
		case 0x83, 0x87, 0x8F:
			return "LOCKED"
		}
	case StatusScopeLoadFiles, StatusScopeLoadFilesAndModules:
		// Executable Load Files: 0x01 LOADED is the only legal
		// runtime state per GP §5.3.3. Anything else is unusual
		// enough that the raw byte is more useful than a guess.
		if e.Lifecycle == 0x01 {
			return "LOADED"
		}
	}
	return fmt.Sprintf("unknown(0x%02X)", e.Lifecycle)
}

// Kind classifies a registry entry as one of "ISD", "SSD", "APP",
// "LOAD_FILE", or "MODULE". Distinct from Scope: Scope is the GET
// STATUS P1 byte that produced the entry (which lumps SSDs in with
// Applications because GP §11.4.2 doesn't give SSDs a separate
// scope), while Kind disambiguates by inspecting the entry's
// privileges. APP entries that carry the SecurityDomain privilege
// are GP-defined Supplementary Security Domains and should be
// labelled SSD in human-readable output.
//
// This is the same promotion GlobalPlatformPro performs in its
// GPRegistry.add() implementation: any entry returned in the
// Applications scope gets reclassified to SSD if the
// SecurityDomain privilege bit is set. Without this promotion, an
// operator looking at the registry can't tell at a glance which
// "applications" are actually SDs they could open authenticated
// sessions against.
//
// Per the third external review on feat/sd-keys-cli, Section 8
// (lifecycle rendering and registry entry classification).
func (e RegistryEntry) Kind() string {
	switch e.Scope {
	case StatusScopeISD:
		return "ISD"
	case StatusScopeApplications:
		// SSD promotion: an Applications-scope entry with the
		// SecurityDomain privilege bit is structurally a
		// Supplementary Security Domain. Match GlobalPlatformPro.
		if e.Privileges.SecurityDomain {
			return "SSD"
		}
		return "APP"
	case StatusScopeLoadFiles, StatusScopeLoadFilesAndModules:
		// Load File entries don't carry privileges (the
		// Privileges field is the zero value), so the SSD
		// promotion doesn't apply. Modules sit under their
		// parent Load File and aren't returned as top-level
		// entries by GET STATUS — when we expose them, they
		// come from RegistryEntry.Modules rather than as their
		// own entries — so MODULE is reserved for a future
		// expansion if/when we project modules as flat rows.
		return "LOAD_FILE"
	}
	return fmt.Sprintf("unknown(scope=0x%02X)", byte(e.Scope))
}

// Privileges represents the GP Table 6-1 privilege bits assigned to
// an Application or Security Domain.
type Privileges struct {
	// Byte 1
	SecurityDomain          bool // bit 8
	DAPVerification         bool // bit 7
	DelegatedManagement     bool // bit 6
	CardLock                bool // bit 5
	CardTerminate           bool // bit 4
	CardReset               bool // bit 3
	CVMManagement           bool // bit 2
	MandatedDAPVerification bool // bit 1

	// Byte 2
	TrustedPath          bool // bit 8
	AuthorizedManagement bool // bit 7
	TokenVerification    bool // bit 6
	GlobalDelete         bool // bit 5
	GlobalLock           bool // bit 4
	GlobalRegistry       bool // bit 3
	FinalApplication     bool // bit 2
	GlobalService        bool // bit 1

	// Byte 3
	ReceiptGeneration         bool // bit 8
	CipheredLoadFileDataBlock bool // bit 7
	ContactlessActivation     bool // bit 6
	ContactlessSelfActivation bool // bit 5
	// bits 4–1 are RFU per GP §6.6.1.
}

// ParsePrivileges decodes a 3-byte privilege string per GP Table 6-1.
// Returns ErrInvalidResponse if the input is not exactly 3 bytes; some
// older cards send 1 byte (legacy) — those callers should preprocess
// or reject up front.
func ParsePrivileges(b []byte) (Privileges, error) {
	if len(b) != 3 {
		return Privileges{}, fmt.Errorf("%w: privileges field must be 3 bytes (GP Table 6-1), got %d", ErrInvalidResponse, len(b))
	}
	return Privileges{
		SecurityDomain:          b[0]&0x80 != 0,
		DAPVerification:         b[0]&0x40 != 0,
		DelegatedManagement:     b[0]&0x20 != 0,
		CardLock:                b[0]&0x10 != 0,
		CardTerminate:           b[0]&0x08 != 0,
		CardReset:               b[0]&0x04 != 0,
		CVMManagement:           b[0]&0x02 != 0,
		MandatedDAPVerification: b[0]&0x01 != 0,

		TrustedPath:          b[1]&0x80 != 0,
		AuthorizedManagement: b[1]&0x40 != 0,
		TokenVerification:    b[1]&0x20 != 0,
		GlobalDelete:         b[1]&0x10 != 0,
		GlobalLock:           b[1]&0x08 != 0,
		GlobalRegistry:       b[1]&0x04 != 0,
		FinalApplication:     b[1]&0x02 != 0,
		GlobalService:        b[1]&0x01 != 0,

		ReceiptGeneration:         b[2]&0x80 != 0,
		CipheredLoadFileDataBlock: b[2]&0x40 != 0,
		ContactlessActivation:     b[2]&0x20 != 0,
		ContactlessSelfActivation: b[2]&0x10 != 0,
	}, nil
}

// Raw returns the 3-byte encoded form of the privilege set. Inverse
// of ParsePrivileges.
func (p Privileges) Raw() [3]byte {
	var r [3]byte
	if p.SecurityDomain {
		r[0] |= 0x80
	}
	if p.DAPVerification {
		r[0] |= 0x40
	}
	if p.DelegatedManagement {
		r[0] |= 0x20
	}
	if p.CardLock {
		r[0] |= 0x10
	}
	if p.CardTerminate {
		r[0] |= 0x08
	}
	if p.CardReset {
		r[0] |= 0x04
	}
	if p.CVMManagement {
		r[0] |= 0x02
	}
	if p.MandatedDAPVerification {
		r[0] |= 0x01
	}

	if p.TrustedPath {
		r[1] |= 0x80
	}
	if p.AuthorizedManagement {
		r[1] |= 0x40
	}
	if p.TokenVerification {
		r[1] |= 0x20
	}
	if p.GlobalDelete {
		r[1] |= 0x10
	}
	if p.GlobalLock {
		r[1] |= 0x08
	}
	if p.GlobalRegistry {
		r[1] |= 0x04
	}
	if p.FinalApplication {
		r[1] |= 0x02
	}
	if p.GlobalService {
		r[1] |= 0x01
	}

	if p.ReceiptGeneration {
		r[2] |= 0x80
	}
	if p.CipheredLoadFileDataBlock {
		r[2] |= 0x40
	}
	if p.ContactlessActivation {
		r[2] |= 0x20
	}
	if p.ContactlessSelfActivation {
		r[2] |= 0x10
	}
	return r
}

// Names returns the names of all set privileges, in stable order.
func (p Privileges) Names() []string {
	all := []struct {
		set  bool
		name string
	}{
		{p.SecurityDomain, "SecurityDomain"},
		{p.DAPVerification, "DAPVerification"},
		{p.DelegatedManagement, "DelegatedManagement"},
		{p.CardLock, "CardLock"},
		{p.CardTerminate, "CardTerminate"},
		{p.CardReset, "CardReset"},
		{p.CVMManagement, "CVMManagement"},
		{p.MandatedDAPVerification, "MandatedDAPVerification"},
		{p.TrustedPath, "TrustedPath"},
		{p.AuthorizedManagement, "AuthorizedManagement"},
		{p.TokenVerification, "TokenVerification"},
		{p.GlobalDelete, "GlobalDelete"},
		{p.GlobalLock, "GlobalLock"},
		{p.GlobalRegistry, "GlobalRegistry"},
		{p.FinalApplication, "FinalApplication"},
		{p.GlobalService, "GlobalService"},
		{p.ReceiptGeneration, "ReceiptGeneration"},
		{p.CipheredLoadFileDataBlock, "CipheredLoadFileDataBlock"},
		{p.ContactlessActivation, "ContactlessActivation"},
		{p.ContactlessSelfActivation, "ContactlessSelfActivation"},
	}
	out := make([]string, 0, len(all))
	for _, e := range all {
		if e.set {
			out = append(out, e.name)
		}
	}
	return out
}

// String returns a comma-separated list of set privilege names, or
// "(none)" if no privileges are set.
func (p Privileges) String() string {
	names := p.Names()
	if len(names) == 0 {
		return "(none)"
	}
	var buf bytes.Buffer
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(n)
	}
	return buf.String()
}

// GP §11.4.2 GET STATUS.
const (
	insGetStatus byte = 0xF2

	// P2 controls the response format and continuation flag.
	// Per GP Card Spec §11.4.2.1:
	//   b2: 0 = legacy "Application" response data structure
	//       1 = TLV response data structure
	//   b1: 0 = first or all occurrences
	//       1 = subsequent occurrences (continuation)
	//
	// This implementation REQUIRES the TLV format. The legacy
	// "Application" structure is not supported by design — see
	// GetStatus's docstring for the rationale.
	p2GetStatusTLVFirst byte = 0x02
	p2GetStatusTLVNext  byte = 0x03

	swMoreData uint16 = 0x6310

	// TLV tags inside the GET STATUS response template.
	tagRegistryEntry     tlv.Tag = 0xE3
	tagRegistryAID       tlv.Tag = 0x4F
	tagRegistryLCAndPriv tlv.Tag = 0x9F70 // lifecycle (1B) + privileges (3B)
	tagRegistryPrivOnly  tlv.Tag = 0xC5   // privileges (3B), legacy variant
	tagRegistryAssocSD   tlv.Tag = 0xCC
	tagRegistryVersion   tlv.Tag = 0xCE
	tagRegistryModule    tlv.Tag = 0x84
)

// GetStatus queries the card's GP registry per GP §11.4.2 and returns
// every entry matching the given scope.
//
// Format: TLV only. The request uses P2 = 0x02 (TLV first call) and
// P2 = 0x03 (TLV continuation). Cards that don't support the
// TLV-format request answer SW=6A86 ("incorrect parameters P1-P2")
// or SW=6D00 ("instruction not supported"); GetStatus surfaces
// those as APDUError with an explicit message naming the
// limitation. The pre-TLV "Application" response structure
// (P2 = 0x00) is intentionally NOT supported — this codebase has
// no users yet, so there is no installed base to preserve, and
// the byte-1-only privileges encoding (no AuthorizedManagement,
// no GlobalDelete, no contactless flags) would force SD/SSD
// classification logic to special-case "did this entry come from
// a card that knows about byte-2 flags?". That complexity is
// deferred until a concrete deployment surfaces a non-TLV card.
//
// The card may signal a multi-segment response with SW=6310 ("more
// data"); GetStatus issues continuation calls (P2 = 0x03) until
// the card responds 0x9000 or returns a non-success SW. SW=6A88
// ("referenced data not found") is treated as an empty registry —
// common when querying Load Files on a card with nothing
// installed beyond the ISD.
//
// The returned entries each carry the scope they were collected
// under, so RegistryEntry.LifecycleString and downstream consumers
// can interpret Lifecycle correctly.
func (s *Session) GetStatus(ctx context.Context, scope StatusScope) ([]RegistryEntry, error) {
	// "Match any AID" search criteria: tag 0x4F, length 0.
	criteria := []byte{0x4F, 0x00}

	var entries []RegistryEntry
	p2 := p2GetStatusTLVFirst
	for {
		cmd := &apdu.Command{
			CLA:  clsGP,
			INS:  insGetStatus,
			P1:   byte(scope),
			P2:   p2,
			Data: criteria,
			Le:   0, // 0 = max response length (256 short / 65536 extended)
		}
		resp, err := s.transmit(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("securitydomain: GET STATUS: %w", err)
		}
		sw := resp.StatusWord()
		switch {
		case resp.IsSuccess():
			parsed, err := parseStatusResponse(resp.Data, scope)
			if err != nil {
				return nil, err
			}
			entries = append(entries, parsed...)
			return entries, nil
		case sw == swMoreData:
			parsed, err := parseStatusResponse(resp.Data, scope)
			if err != nil {
				return nil, err
			}
			entries = append(entries, parsed...)
			p2 = p2GetStatusTLVNext
			continue
		case sw == 0x6A88:
			// Referenced data not found: empty registry for this scope.
			return nil, nil
		case sw == 0x6A86 || sw == 0x6D00:
			// Card rejected the TLV-format request. This is the
			// signal that we're talking to a pre-TLV card; we
			// don't fall back to legacy by design (see
			// GetStatus docstring).
			return nil, &APDUError{
				Operation: fmt.Sprintf("GET STATUS scope=%s: card refused TLV format (SW=%04X); legacy 'Application' format is not supported by this library — see securitydomain.GetStatus docstring", scope, sw),
				SW:        sw,
			}
		default:
			return nil, &APDUError{
				Operation: fmt.Sprintf("GET STATUS scope=%s", scope),
				SW:        sw,
			}
		}
	}
}

// parseStatusResponse decodes the TLV body of a GET STATUS response.
// The body is a sequence of 0xE3 templates per GP §11.4.2.2.
func parseStatusResponse(data []byte, scope StatusScope) ([]RegistryEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	nodes, err := tlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: GET STATUS TLV decode: %v", ErrInvalidResponse, err)
	}
	var entries []RegistryEntry
	for _, n := range nodes {
		if n.Tag != tagRegistryEntry {
			// GP §11.4.2.2 says the response is a sequence of 0xE3
			// templates. Anything else at the top level is malformed.
			return nil, fmt.Errorf("%w: GET STATUS: unexpected top-level tag 0x%X (want 0x%X)",
				ErrInvalidResponse, n.Tag, tagRegistryEntry)
		}
		entry, err := parseRegistryEntry(n, scope)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseRegistryEntry decodes one 0xE3 template into a RegistryEntry.
// The set of fields populated depends on which tags the card actually
// returned — only AID is mandatory; everything else is best-effort.
func parseRegistryEntry(node *tlv.Node, scope StatusScope) (RegistryEntry, error) {
	children, err := tlv.Decode(node.Value)
	if err != nil {
		return RegistryEntry{}, fmt.Errorf("%w: GET STATUS entry decode: %v", ErrInvalidResponse, err)
	}
	entry := RegistryEntry{Scope: scope}

	if aid := tlv.Find(children, tagRegistryAID); aid != nil {
		entry.AID = append([]byte(nil), aid.Value...)
	} else {
		return RegistryEntry{}, fmt.Errorf("%w: GET STATUS entry missing AID (tag 0x4F)", ErrInvalidResponse)
	}

	// GP carries lifecycle + privileges in two slightly different
	// shapes: combined under tag 0x9F70 (modern), or split with
	// lifecycle implicit and privileges under tag 0xC5 (legacy).
	// Try the modern form first.
	if combined := tlv.Find(children, tagRegistryLCAndPriv); combined != nil {
		switch len(combined.Value) {
		case 4:
			entry.Lifecycle = combined.Value[0]
			privs, err := ParsePrivileges(combined.Value[1:])
			if err != nil {
				return RegistryEntry{}, err
			}
			entry.Privileges = privs
		case 1:
			// Lifecycle only; privileges may be in a separate tag.
			entry.Lifecycle = combined.Value[0]
		default:
			return RegistryEntry{}, fmt.Errorf("%w: GET STATUS tag 0x9F70 length %d (want 1 or 4)",
				ErrInvalidResponse, len(combined.Value))
		}
	}
	if privOnly := tlv.Find(children, tagRegistryPrivOnly); privOnly != nil {
		// Legacy GP: tag 0xC5 carries privileges in either the
		// 3-byte canonical form (GP §6.6.1 Table 6-1) or, on
		// older Java Card platforms and reference test cards,
		// in a 1-byte form that encodes only the first byte of
		// the privilege set. GlobalPlatformPro tolerates both
		// shapes; we follow the same rule so the registry walk
		// against an old card surfaces AID + lifecycle even
		// when the privileges field is non-canonical.
		//
		// Per the third external review, Section 7 (GET STATUS
		// legacy/tagged parsing).
		switch len(privOnly.Value) {
		case 3:
			privs, err := ParsePrivileges(privOnly.Value)
			if err != nil {
				return RegistryEntry{}, err
			}
			entry.Privileges = privs
		case 1:
			// Legacy 1-byte form: only byte 1 of the
			// privilege set is present. Pad to 3 bytes
			// with zeros and parse to extract the byte-1
			// flags (SecurityDomain, DAPVerification,
			// etc.). Byte 2 + 3 flags are absent on these
			// cards so reading them as zero is correct.
			padded := []byte{privOnly.Value[0], 0x00, 0x00}
			privs, err := ParsePrivileges(padded)
			if err != nil {
				return RegistryEntry{}, err
			}
			entry.Privileges = privs
		case 0:
			// Empty privileges: card returned the tag with
			// no value. Leave Privileges at the zero value
			// (all flags false) and continue. Hard-failing
			// here would refuse to describe an entry that
			// happens to have no privileges set, which is
			// legitimate for some load-file / package
			// entries.
		default:
			// 2 bytes or 4+ bytes: shape we don't recognize.
			// Treat as soft warning by zero-valuing
			// Privileges rather than failing the entry.
			// Future work could surface the raw bytes via
			// a diagnostic field; today the AID + lifecycle
			// path is what the operator needs most.
		}
	}

	if assoc := tlv.Find(children, tagRegistryAssocSD); assoc != nil {
		entry.AssociatedSDAID = append([]byte(nil), assoc.Value...)
	}
	if version := tlv.Find(children, tagRegistryVersion); version != nil {
		entry.Version = append([]byte(nil), version.Value...)
	}
	if scope == StatusScopeLoadFilesAndModules {
		for _, m := range tlv.FindAll(children, tagRegistryModule) {
			entry.Modules = append(entry.Modules, append([]byte(nil), m.Value...))
		}
	}

	return entry, nil
}
