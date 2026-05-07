package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/cardrecognition"
	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/gp/cplc"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
	"github.com/PeculiarVentures/scp/transport"
)

// candidateAIDStr formats a gp.ISDCandidate's AID for human-
// readable report lines: an empty (default-SELECT) AID becomes
// "(default)", non-empty AIDs become uppercase hex.
func candidateAIDStr(c gp.ISDCandidate) string {
	if len(c.AID) == 0 {
		return "(default)"
	}
	return strings.ToUpper(hex.EncodeToString(c.AID))
}

// probeData is the JSON-friendly payload of the probe report. Strings
// for OIDs (decimal-dotted) so JSON output is human-readable without
// custom encoders.
type probeData struct {
	// Profile is the resolved card profile name ("yubikey-sd",
	// "standard-sd"). Comes from securitydomain/profile.classifyByCRD,
	// which requires three signals together: the GP-standard
	// Card_IDS OID 1.2.840.114283.3 present in the CRD, no
	// CardChipDetailsOID (cards that tag a chip platform — e.g.
	// SafeNet eToken Fusion emitting JavaCard v3 1.3.6.1.4.1.42.2.110.1.3
	// — fall through to standard-sd), and SCP11 advertised in the
	// SCPs list. The earlier classifier matched on Card_IDS OID
	// alone and was tightened after a SafeNet eToken Fusion was
	// observed emitting the same OID as YubiKey. Operators read
	// this field to confirm auto-detection landed where they
	// expected; automation reads it to decide whether YubiKey-
	// extension commands (GENERATE EC KEY, ATTEST, INS=0xFB
	// reset) are valid for the card.
	Profile string `json:"profile,omitempty"`

	GPVersion             string   `json:"gp_version,omitempty"`
	SCPVersion            string   `json:"scp_version,omitempty"`
	SCPParameter          string   `json:"scp_parameter,omitempty"`
	SCPs                  []string `json:"scps,omitempty"`
	CardIdentificationOID string   `json:"card_identification_oid,omitempty"`
	CardConfigDetailsOID  string   `json:"card_config_details_oid,omitempty"`
	CardChipDetailsOID    string   `json:"card_chip_details_oid,omitempty"`
	RawHex                string   `json:"raw_hex,omitempty"`

	// AuthMode reports which session auth mode was used for the
	// registry walk. Currently one of:
	//   - "none": OpenUnauthenticated (cmdProbe; cmdSDInfo without
	//     --scp03-* flags). Auth-required GET STATUS scopes appear
	//     as SKIP under --full.
	//   - "scp03": OpenSCP03 with the supplied keys. Auth-required
	//     scopes populate.
	//
	// Per the external review on feat/sd-keys-cli, Finding 9: makes
	// the auth posture of a probe report explicit, so an automated
	// consumer reading the JSON can tell at a glance whether the
	// SKIPped scopes are SKIPped because they're auth-gated and the
	// session was unauthenticated, or because the card refused even
	// the authenticated read. Future SCP11a/c paths will set this
	// to "scp11a" / "scp11c" once Finding 4 lands.
	AuthMode string `json:"auth_mode,omitempty"`

	// CardLocked reports whether the SELECT that opened the probe
	// session returned SW=6283 (CARD_LOCKED warning per GP §11.1.2).
	// True means the card's applet is in CARD_LOCKED lifecycle:
	// the SELECT structurally returned FCI but management
	// operations and authenticated reads may be rejected by the
	// card. The probe still proceeds with the read paths — failing
	// closed on a CARD_LOCKED card would refuse to describe it at
	// all, which is exactly the case where an operator most needs
	// information.
	//
	// Omitted from JSON when false (the typical case). Surfaces in
	// text output as a CARD_LOCKED warning line so an operator
	// sees it prominently.
	//
	// Per the third external review, Section 9 (locked-card SELECT).
	CardLocked bool `json:"card_locked,omitempty"`

	// KeyInfo is populated by 'sd info' (and other callers that set
	// probeOptions.fetchKeyInfo). Each entry is a human-readable
	// summary like 'KID=0x01 KVN=0xFF (3 components)'. Omitted from
	// JSON output when nil so the unauthenticated probe schema
	// (CRD plus the GP §H.6 / §H.4 unauthenticated identification
	// reads) stays stable for consumers that only ever see
	// cmdProbe; cmdSDInfo opts in to the additional KIT data.
	KeyInfo []string `json:"key_info,omitempty"`

	// Registry is populated by 'sd info --full'. Each scope has
	// its own slice; nil means that scope was not queried, an empty
	// slice means the card returned SW=6A88 (no entries) for it.
	// Per-entry detail is structured for JSON consumers; the
	// human-readable surface is the per-scope GET STATUS line in
	// Checks (count and a brief AID summary).
	Registry *registryDump `json:"registry,omitempty"`

	// CPLC, IIN, CIN, KDD, SSC are unauthenticated GET DATA
	// objects that a card may carry. Each is omitted from JSON
	// when the card returned 6A88 ("not present") so a consumer
	// can branch on field presence rather than checking for empty
	// strings. CPLC is a structured object; IIN/CIN/KDD/SSC are
	// hex-rendered raw bytes because their structures are vendor-
	// specific.
	//
	// CPLC fields trace the card's chip family, OS, and production
	// dates. YubiKey 5.x advertises CPLC but with random bytes in
	// the date fields (parser tolerates that, marks Valid=false).
	// SafeNet eToken Fusion advertises a fully populated CPLC.
	CPLC *cplcView `json:"cplc,omitempty"`
	IIN  string    `json:"iin,omitempty"`
	CIN  string    `json:"cin,omitempty"`
	KDD  string    `json:"kdd,omitempty"`
	SSC  string    `json:"ssc,omitempty"`

	// CardCapabilities is the raw hex of GET DATA tag 0x0067 (Card
	// Capability Information per GP Card Spec v2.3.1 §H.4) when the
	// card carries it. Most cards in the test population return
	// SW=6A88 here; this field stays empty for those. No structured
	// parsing yet — the value is the operator-visible counterpart of
	// what gppro shows for this tag, useful for cards we eventually
	// validate against. Parsing lands when there's a real-card
	// fixture to pin against.
	CardCapabilities string `json:"card_capabilities,omitempty"`
}

// cplcView is the JSON projection of cplc.Data. Vendor codes render
// as uppercase hex (matching the rest of the probe report's hex
// rendering); dates render in YYYY-MM-DD form when valid, or as
// "{raw-hex} (raw)" when the field is uninitialized or didn't
// decode as valid BCD.
type cplcView struct {
	ICFabricator                      string `json:"ic_fabricator"`
	ICType                            string `json:"ic_type"`
	OperatingSystemID                 string `json:"operating_system_id"`
	OperatingSystemReleaseDate        string `json:"operating_system_release_date"`
	OperatingSystemReleaseLevel       string `json:"operating_system_release_level"`
	ICFabricationDate                 string `json:"ic_fabrication_date"`
	ICSerialNumber                    string `json:"ic_serial_number"`
	ICBatchIdentifier                 string `json:"ic_batch_identifier"`
	ICModuleFabricator                string `json:"ic_module_fabricator"`
	ICModulePackagingDate             string `json:"ic_module_packaging_date"`
	ICCManufacturer                   string `json:"icc_manufacturer"`
	ICEmbeddingDate                   string `json:"ic_embedding_date"`
	ICPrePersonalizer                 string `json:"ic_pre_personalizer"`
	ICPrePersonalizationEquipmentDate string `json:"ic_pre_personalization_equipment_date"`
	ICPrePersonalizationEquipmentID   string `json:"ic_pre_personalization_equipment_id"`
	ICPersonalizer                    string `json:"ic_personalizer"`
	ICPersonalizationDate             string `json:"ic_personalization_date"`
	ICPersonalizationEquipmentID      string `json:"ic_personalization_equipment_id"`
}

// registryDump is the JSON shape of a --full GP registry walk.
// LoadFilesRequestedScope and LoadFilesActualScope let consumers
// detect when the LoadFilesAndModules->LoadFiles fallback fired:
// 'requested' is always 'load_files_and_modules' (the preferred
// path that includes module enumeration); 'actual' is whichever
// scope the card actually returned. When they differ, the
// returned LoadFiles entries lack module names, so JSON
// consumers can branch on the mismatch to avoid asserting
// module presence on cards that don't expose it.
type registryDump struct {
	ISD          []registryEntryView `json:"isd,omitempty"`
	Applications []registryEntryView `json:"applications,omitempty"`
	LoadFiles    []registryEntryView `json:"load_files,omitempty"`

	LoadFilesRequestedScope string `json:"load_files_requested_scope,omitempty"`
	LoadFilesActualScope    string `json:"load_files_actual_scope,omitempty"`
}

// registryEntryView is the JSON projection of a securitydomain.RegistryEntry.
// Bytes are rendered as uppercase hex; Lifecycle has both the parsed
// human form and the raw byte so callers can re-interpret if needed.
type registryEntryView struct {
	AID string `json:"aid"`

	// Kind classifies the entry as ISD, SSD, APP, or LOAD_FILE.
	// Distinct from Lifecycle (which describes the entry's
	// state) and from the surrounding registry slice (which
	// reflects the GET STATUS scope that produced the entry).
	// Promotion of APP-with-SecurityDomain-privilege to SSD
	// happens here, matching GlobalPlatformPro's classification
	// (per the third external review on feat/sd-keys-cli,
	// Section 8). An operator scanning JSON can tell at a glance
	// which Applications-scope rows are actually SDs they could
	// open management sessions against.
	Kind            string   `json:"kind"`
	Lifecycle       string   `json:"lifecycle"`
	LifecycleByte   string   `json:"lifecycle_byte"`
	Privileges      []string `json:"privileges,omitempty"`
	Version         string   `json:"version,omitempty"`
	AssociatedSDAID string   `json:"associated_sd_aid,omitempty"`
	Modules         []string `json:"modules,omitempty"`
}

// cmdProbe opens an unauthenticated Security Domain session, fetches
// Card Recognition Data via GET DATA tag 0x66, parses it through the
// cardrecognition package, and prints the parsed capabilities.
//
// Probe is intentionally read-only and unauthenticated: it is the
// "before you decide what to authenticate as, here is what the card
// claims to be" step. CRD is treated as discovery input, not as
// proof of authorization. A card that lies about CRD is a card bug,
// not a CLI bug.
//
// References:
//   - GP Card Spec v2.3.1 §H.2/H.3 (Card Recognition Data structure)
//   - Yubico Python yubikit.securitydomain (CRD retrieval pattern)
func cmdProbe(ctx context.Context, env *runEnv, args []string) error {
	return runProbe(ctx, env, args, probeOptions{
		flagSetName:  "probe",
		reportLabel:  "probe",
		fetchKeyInfo: false,
	})
}

// probeOptions configures a runProbe invocation. Both cmdProbe and
// cmdSDInfo use the same underlying flow (open ISD unauthenticated,
// fetch and parse CRD); they differ in the report label, the help
// header on flag-set usage errors, and whether the Key Information
// Template is fetched.
type probeOptions struct {
	// flagSetName is what newSubcommandFlagSet displays in flag
	// usage errors. 'probe' for the legacy top-level subcommand,
	// 'sd info' for the new group-form.
	flagSetName string

	// reportLabel is what shows up in Report.Subcommand. The same
	// labels distinguish the two commands in JSON output and in
	// the human-readable header line.
	reportLabel string

	// fetchKeyInfo controls whether the Key Information Template
	// is fetched and reported. cmdProbe does not (the unauthenticated
	// identification surface — CRD plus CPLC, IIN, CIN, KDD, SSC,
	// Card Capabilities — is the probe scope). cmdSDInfo does,
	// because reporting card identity at the SD-info level should
	// include which key references the card has installed.
	fetchKeyInfo bool

	// allowFullStatus controls whether 'sd info --full' is reachable
	// from this entry point. cmdSDInfo sets it; cmdProbe does not,
	// keeping probe scoped to unauthenticated reads (the
	// authenticated GP registry walk lives behind --full and a
	// separate auth path).
	allowFullStatus bool
}

func runProbe(ctx context.Context, env *runEnv, args []string, opts probeOptions) error {
	fs := newSubcommandFlagSet(opts.flagSetName, env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	sdAIDFlag := registerSDAIDFlag(fs)
	discoverSD := fs.Bool("discover-sd", false,
		"Walk a curated list of candidate Security Domain AIDs (gp.ISDDiscoveryAIDs) and use the first one that responds 9000. Mutually exclusive with --sd-aid. Probes return SW=6A82 on absent AIDs; any other non-9000 SW aborts discovery. The chosen AID appears in the report so subsequent runs can pin it via --sd-aid.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	var fullMode *bool
	var scp03Flags *scp03KeyFlags
	if opts.allowFullStatus {
		fullMode = fs.Bool("full", false,
			"Walk the GP registry via GET STATUS (GP §11.4.2): "+
				"ISD, Applications + SSDs, Load Files + Modules. "+
				"Each scope reports separately; auth-required scopes "+
				"appear as SKIP on cards that refuse them over an "+
				"unauthenticated session. Pass --scp03-* to authenticate "+
				"the registry walk and replace SKIPs with populated entries.")
		// scp03Optional: --scp03-* flags are accepted but not required.
		// Without any of them, the session opens unauthenticated as
		// before. With any of them, the session authenticates over
		// SCP03 and the auth-required scopes (Applications + SSDs,
		// Load Files + Modules) populate instead of SKIP-ing.
		//
		// Per the external review on feat/sd-keys-cli, Finding 9:
		// 'sd info --full should let operators authenticate so the
		// auth-gated scopes populate rather than always SKIPping.
		// The unauthenticated default is correct for a probe, but
		// the SKIP shouldn't be the only way to see the registry.'
		scp03Flags = registerSCP03KeyFlags(fs, scp03Optional)
	}
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	// SCP03 flags only make sense with --full. The CRD + KIT fetches
	// are unauthenticated-mode-only (the card serves them over a
	// plain SELECT regardless of auth state), so authenticating just
	// for those reads would be wasted effort and would confuse the
	// SCP03-as-authenticated-registry-walk semantic. Reject the
	// combination loudly so 'sd info --scp03-keys-default' (without
	// --full) doesn't silently authenticate-and-do-nothing.
	if scp03Flags != nil && scp03Flags.anyFlagSet() && (fullMode == nil || !*fullMode) {
		return &usageError{
			msg: "--scp03-* flags require --full; SCP03 authentication " +
				"is meaningful only for the registry walk, not for " +
				"the unauthenticated CRD/KIT reads",
		}
	}

	sdAID, err := sdAIDFlag.Resolve()
	if err != nil {
		return err
	}
	if *discoverSD && sdAID != nil {
		return &usageError{msg: "--discover-sd and --sd-aid are mutually exclusive (pick one)"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: opts.reportLabel, Reader: *reader}

	var sd *securitydomain.Session
	var authMode string
	if *discoverSD {
		// Walk the curated AID list. Trace each SELECT attempt
		// into the report so an operator hitting a discovery
		// failure can see which AIDs were tried and what SW
		// each returned, rather than one aggregate error.
		var match gp.ISDCandidate
		trace := func(a securitydomain.DiscoveryAttempt) {
			label := candidateAIDStr(a.Candidate)
			detail := fmt.Sprintf("%s — %s", label, a.Candidate.Source)
			if a.Selected {
				report.Pass("discover ISD attempt", detail+" — SW=9000")
				return
			}
			swText := "transport-error"
			if a.SW != 0 {
				swText = fmt.Sprintf("SW=%04X", a.SW)
			}
			report.Skip("discover ISD attempt",
				fmt.Sprintf("%s — %s", detail, swText))
		}
		sd, match, err = securitydomain.DiscoverISD(ctx, t, gp.ISDDiscoveryAIDs, trace)
		if err != nil {
			report.Fail("discover ISD", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("discover ISD: %w", err)
		}
		report.Pass("discover ISD",
			fmt.Sprintf("matched %s — %s", candidateAIDStr(match), match.Source))
		authMode = "none"
	} else {
		sd, authMode, err = openProbeSession(ctx, t, scp03Flags, fullMode, sdAID, report)
		if err != nil {
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
	}
	defer sd.Close()

	// CARD_LOCKED warning surfaces immediately so it appears
	// before the per-step Pass/Fail lines and an operator sees
	// it prominently. The probe continues either way — failing
	// closed on CARD_LOCKED would refuse to describe the card,
	// which is exactly the case where the operator most needs
	// information about it.
	//
	// Per the third external review, Section 9.
	cardLocked := sd.CardLocked()
	if cardLocked {
		report.Skip("SELECT SD",
			"card returned SW=6283 (CARD_LOCKED, GP §11.1.2). FCI returned, "+
				"reads will be attempted, but management operations and "+
				"authenticated reads may be rejected by the card.")
	}

	raw, err := sd.GetCardRecognitionData(ctx)
	if err != nil {
		report.Fail("GET DATA tag 0x66", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("get CRD: %w", err)
	}
	if len(raw) == 0 {
		report.Skip("parse CRD", "card returned empty CRD")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}
	report.Pass("GET DATA tag 0x66", fmt.Sprintf("%d bytes", len(raw)))

	info, err := cardrecognition.Parse(raw)
	if err != nil {
		report.Fail("parse CRD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("parse CRD: %w", err)
	}
	report.Pass("parse CRD", "")

	data := &probeData{RawHex: hexEncode(raw), AuthMode: authMode, CardLocked: cardLocked}

	// Classify via profile.ClassifyByCRD so cmd probe and
	// profile.Probe agree on what counts as yubikey-sd. Computed
	// from the already-parsed CardInfo rather than re-running
	// profile.Probe to avoid duplicate SELECT + GET DATA round
	// trips, but the classification rule is the same.
	if prof := profile.ClassifyByCRD(info); prof != nil {
		data.Profile = prof.Name()
	} else {
		data.Profile = "standard-sd"
	}

	if len(info.GPVersion) > 0 {
		data.GPVersion = joinInts(info.GPVersion, ".")
	}
	if len(info.SCPs) > 0 {
		// JSON back-compat: scp_version and scp_parameter mirror
		// SCPs[0] for any consumer still parsing the old single-
		// SCP shape. The SCPs slice carries the full set.
		first := info.SCPs[0]
		data.SCPVersion = fmt.Sprintf("0x%02X", first.Version)
		// SCP11 v1.3 i-parameters can be 2 bytes; render the wider
		// form when needed so SCP02/03 stay 0xNN and SCP11 reports
		// 0xNNNN truthfully instead of being truncated to the low byte.
		if first.Parameter > 0xFF {
			data.SCPParameter = fmt.Sprintf("0x%04X", first.Parameter)
		} else {
			data.SCPParameter = fmt.Sprintf("0x%02X", first.Parameter)
		}
	}
	for _, s := range info.SCPs {
		data.SCPs = append(data.SCPs, formatSCP(s))
	}
	if len(info.CardIdentificationOID) > 0 {
		data.CardIdentificationOID = info.CardIdentificationOID.String()
	}
	if len(info.CardConfigDetailsOID) > 0 {
		data.CardConfigDetailsOID = info.CardConfigDetailsOID.String()
	}
	if len(info.CardChipDetailsOID) > 0 {
		data.CardChipDetailsOID = info.CardChipDetailsOID.String()
	}

	// Capability checks — strictly informational. The probe does not
	// authenticate or authorize anything; it just tells the user what
	// the card advertises so they can pick a smoke test sensibly.
	if data.GPVersion != "" {
		report.Pass("GP version", data.GPVersion)
	} else {
		report.Skip("GP version", "not advertised in CRD")
	}
	if len(info.SCPs) == 0 {
		report.Skip("SCP advertised", "no SCP element in CRD")
	} else {
		// One report line per advertised SCP. Cards that advertise
		// more than one (e.g. retail YubiKey 5.7+ ships SCP03 and
		// SCP11 together) get multiple PASS lines so the operator
		// can see exactly what's available without inspecting the
		// raw CRD bytes.
		for _, s := range info.SCPs {
			report.Pass("SCP advertised", formatSCP(s))
		}
	}

	// Optional unauthenticated GET DATA reads. Each tag is read
	// independently; cards differ widely in which they expose.
	// SafeNet/Gemalto/Thales cards return all five; YubiKey 5.x
	// returns only CPLC; some configurations return none. Not-
	// present (SW=6A88) is reported as SKIP rather than FAIL
	// because the absence of these objects is informational, not
	// a probe failure. Each read is gated by opts.fetchKeyInfo
	// (currently the only flag distinguishing the basic 'probe'
	// from the deeper 'sd info'); they're read on every probe so
	// the operator sees identification material for any card,
	// not just YubiKey-shaped ones.
	probeOptionalGetData(ctx, sd, data, report)

	// Key Information Template. Optional because many cards do not
	// implement GET DATA tag 0x00E0; fetch failures are reported as
	// SKIP rather than FAIL because absence of KIT is not a probe
	// failure. The KIT is the natural extension of 'sd info' beyond
	// raw CRD parsing because it tells the operator which keys the
	// card has installed (key references and component types) which
	// is the next thing they want to know after 'is this card
	// reachable'.
	if opts.fetchKeyInfo {
		keys, err := sd.GetKeyInformation(ctx)
		switch {
		case err != nil:
			report.Skip("GET DATA tag 0x00E0 (KIT)", err.Error())
		case len(keys) == 0:
			report.Skip("GET DATA tag 0x00E0 (KIT)", "card returned no key entries")
		default:
			summaries := make([]string, 0, len(keys))
			for _, k := range keys {
				// Each KeyInfo entry: 'KID=0x01 KVN=0xFF (3 components)'.
				summaries = append(summaries,
					fmt.Sprintf("KID=0x%02X KVN=0x%02X (%d components)",
						k.Reference.ID, k.Reference.Version, len(k.Components)))
			}
			report.Pass("GET DATA tag 0x00E0 (KIT)",
				fmt.Sprintf("%d key entries: %s",
					len(keys), strings.Join(summaries, "; ")))
			data.KeyInfo = summaries
		}
	}

	// Full GP registry walk via GET STATUS. Three scopes are issued:
	// ISD (P1=0x80), Applications + SSDs (P1=0x40), and Load Files +
	// Modules (P1=0x10) — the last one folds the Load Files-only
	// view in by including module AIDs, so a separate Load Files
	// (P1=0x20) call would be redundant.
	//
	// Real cards typically permit GET STATUS on the ISD without
	// authentication but require authentication for the other two
	// scopes. Auth-required scopes manifest as SW=6982 ("security
	// status not satisfied") which surfaces here as a SKIP rather
	// than a FAIL — the operator can see exactly which scopes need
	// an authenticated session if they want a full registry view.
	if opts.allowFullStatus && fullMode != nil && *fullMode {
		dump := &registryDump{}
		dump.ISD = walkRegistry(ctx, sd, securitydomain.StatusScopeISD, "ISD", report)
		dump.Applications = walkRegistry(ctx, sd, securitydomain.StatusScopeApplications, "Applications", report)
		dump.LoadFiles, dump.LoadFilesRequestedScope, dump.LoadFilesActualScope = walkLoadFiles(ctx, sd, report)
		if dump.LoadFilesRequestedScope != dump.LoadFilesActualScope {
			report.Pass("load files scope fallback",
				fmt.Sprintf("requested %s, card returned %s",
					dump.LoadFilesRequestedScope, dump.LoadFilesActualScope))
		}
		// Only attach Registry to Data if at least one scope produced
		// or attempted output; otherwise the JSON has a meaningless
		// empty registry object alongside the unrelated CRD fields.
		if dump.ISD != nil || dump.Applications != nil || dump.LoadFiles != nil {
			data.Registry = dump
		}
	}

	report.Data = data

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("%s reported failures", opts.reportLabel)
	}
	return nil
}

// openProbeSession is the auth-mode-aware Session opener for the
// probe / sd info family. Three branches:
//
//   - scp03Flags is nil (cmdProbe path, where allowFullStatus=false
//     and no SCP03 flag was registered): always unauthenticated.
//   - scp03Flags non-nil but no flag was set: unauthenticated, same
//     as the historical behavior. Auth-required GET STATUS scopes
//     under --full will SKIP as before.
//   - scp03Flags non-nil with at least one flag set AND --full: open
//     SCP03-authenticated. Auth-required scopes populate.
//
// Returns the session, the auth mode label ("none" or "scp03") for
// inclusion in JSON output, and any error. On error, the report is
// already populated with a Fail line so callers just need to Emit
// and return.
//
// sdAID targets a non-default Security Domain AID. nil/empty
// defaults to AIDSecurityDomain via the *WithAID variants — the
// historical behavior on every unauth code path.
//
// Per the external review on feat/sd-keys-cli, Findings 9 + 2.
func openProbeSession(
	ctx context.Context,
	t transport.Transport,
	scp03Flags *scp03KeyFlags,
	fullMode *bool,
	sdAID []byte,
	report *Report,
) (*securitydomain.Session, string, error) {
	// Decide auth mode. The --full + any-scp03-flag combination is
	// the only path that authenticates; cmdProbe (no scp03Flags) and
	// cmdSDInfo without the explicit auth flags both stay
	// unauthenticated.
	wantSCP03 := scp03Flags != nil && scp03Flags.anyFlagSet() &&
		fullMode != nil && *fullMode

	if !wantSCP03 {
		sd, err := securitydomain.OpenUnauthenticatedWithAID(ctx, t, sdAID)
		if err != nil {
			report.Fail("select ISD", err.Error())
			return nil, "none", fmt.Errorf("select ISD: %w", err)
		}
		report.Pass("select ISD", "")
		return sd, "none", nil
	}

	// Authenticated path. Build the SCP03 config from the flag
	// handle's optional-mode parser; this is the same applyToConfig
	// path the bootstrap commands use, so the same custom-key
	// validation (partial-triple rejection, hex parse errors,
	// vendor-profile coherence) applies here.
	cfg, err := scp03Flags.applyToConfigOptional()
	if err != nil {
		report.Fail("parse SCP03 flags", err.Error())
		return nil, "scp03", err
	}
	if cfg == nil {
		// applyToConfigOptional returns nil cfg when no flag was
		// set, which we already filtered out above. If we get here
		// it's a logic error in this function, not a card-side or
		// operator-side problem.
		report.Fail("open SCP03 SD", "internal: SCP03 flags requested but produced nil config")
		return nil, "scp03", fmt.Errorf("internal: SCP03 flags requested but produced nil config")
	}
	report.Pass("SCP03 keys", scp03Flags.describeKeys(cfg))

	// resolveProfile is a no-op for sd info's purposes (we don't
	// emit any vendor-specific APDUs in the probe path) but we run
	// it to surface profile-selection diagnostics and to keep the
	// session.SetProfile contract consistent across read paths.
	prof, _ := resolveProfile(ctx, t, scp03Flags, sdAID, report)

	sd, err := securitydomain.OpenSCP03WithAID(ctx, t, cfg, sdAID)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		return nil, "scp03", fmt.Errorf("open SCP03 SD: %w", err)
	}
	sd.SetProfile(prof)
	report.Pass("open SCP03 SD", "")
	return sd, "scp03", nil
}

// probeOptionalGetData performs the five unauthenticated GET DATA
// reads (CPLC, IIN, CIN, KDD, SSC) against the open SD session and
// populates the corresponding probeData fields and report lines.
// Reads that return SW=6A88 (not present) appear as SKIP; reads
// that succeed appear as PASS with a short summary; reads that
// fail with anything else appear as SKIP with the SW for triage.
//
// The reads are independent. A card that supports CPLC but not
// IIN gets one PASS line and one SKIP. None of these reads are
// required for the probe to be useful — they're informational
// identification material that exists across the GP card population
// in varying combinations (SafeNet/IDPrime/IDCore advertise all
// five; YubiKey 5.x advertises only CPLC; some cards advertise
// none).
//
// The function reads through the SD session so that an authenticated
// probe (e.g. cmdProbe with SCP03 keys supplied) can still see
// values gated behind the auth wall. For unauthenticated probes
// the session's Transmit routes through the raw transport.
func probeOptionalGetData(ctx context.Context, sd *securitydomain.Session, data *probeData, report *Report) {
	// CPLC.
	if cdata, err := gp.ReadCPLC(ctx, sd); err != nil {
		report.Skip("GET DATA tag 0x9F7F (CPLC)", err.Error())
	} else if cdata == nil {
		report.Skip("GET DATA tag 0x9F7F (CPLC)", "not present (SW=6A88)")
	} else {
		data.CPLC = cplcViewFrom(cdata)
		report.Pass("GET DATA tag 0x9F7F (CPLC)",
			fmt.Sprintf("IC fabricator=0x%04X serial=%s", cdata.ICFabricatorCode(), cdata.SerialNumberHex()))
	}

	// IIN, CIN, KDD, SSC, Card Capabilities — opaque bytes,
	// hex-rendered.
	for _, c := range []struct {
		name string
		tag  string
		read func(context.Context, gp.Transmitter) ([]byte, error)
		set  func(*probeData, string)
	}{
		{"IIN", "0x0042", gp.ReadIIN, func(d *probeData, s string) { d.IIN = s }},
		{"CIN", "0x0045", gp.ReadCIN, func(d *probeData, s string) { d.CIN = s }},
		{"KDD", "0x00CF", gp.ReadKDD, func(d *probeData, s string) { d.KDD = s }},
		{"SSC", "0x00C1", gp.ReadSSC, func(d *probeData, s string) { d.SSC = s }},
		{"Card Capabilities", "0x0067", gp.ReadCardCapabilities, func(d *probeData, s string) { d.CardCapabilities = s }},
	} {
		raw, err := c.read(ctx, sd)
		label := fmt.Sprintf("GET DATA tag %s (%s)", c.tag, c.name)
		switch {
		case err != nil:
			report.Skip(label, err.Error())
		case raw == nil:
			report.Skip(label, "not present (SW=6A88)")
		default:
			c.set(data, hexEncode(raw))
			report.Pass(label, fmt.Sprintf("%d bytes", len(raw)))
		}
	}
}

// cplcViewFrom projects a *cplc.Data into the JSON-friendly cplcView.
// Vendor codes render as 4-digit uppercase hex; equipment IDs as
// 8-digit uppercase hex; dates via the DateField.Format helper which
// produces YYYY-MM-DD when valid and "{raw-hex} (raw)" otherwise.
func cplcViewFrom(d *cplc.Data) *cplcView {
	hex2 := func(b [2]byte) string { return fmt.Sprintf("%02X%02X", b[0], b[1]) }
	hex4 := func(b [4]byte) string { return fmt.Sprintf("%02X%02X%02X%02X", b[0], b[1], b[2], b[3]) }
	return &cplcView{
		ICFabricator:                      hex2(d.ICFabricator),
		ICType:                            hex2(d.ICType),
		OperatingSystemID:                 hex2(d.OperatingSystemID),
		OperatingSystemReleaseDate:        d.OperatingSystemReleaseDate.Format(),
		OperatingSystemReleaseLevel:       hex2(d.OperatingSystemReleaseLevel),
		ICFabricationDate:                 d.ICFabricationDate.Format(),
		ICSerialNumber:                    hex4(d.ICSerialNumber),
		ICBatchIdentifier:                 hex2(d.ICBatchIdentifier),
		ICModuleFabricator:                hex2(d.ICModuleFabricator),
		ICModulePackagingDate:             d.ICModulePackagingDate.Format(),
		ICCManufacturer:                   hex2(d.ICCManufacturer),
		ICEmbeddingDate:                   d.ICEmbeddingDate.Format(),
		ICPrePersonalizer:                 hex2(d.ICPrePersonalizer),
		ICPrePersonalizationEquipmentDate: d.ICPrePersonalizationEquipmentDate.Format(),
		ICPrePersonalizationEquipmentID:   hex4(d.ICPrePersonalizationEquipmentID),
		ICPersonalizer:                    hex2(d.ICPersonalizer),
		ICPersonalizationDate:             d.ICPersonalizationDate.Format(),
		ICPersonalizationEquipmentID:      hex4(d.ICPersonalizationEquipmentID),
	}
}

// hexEncode formats a byte slice as uppercase hex without spaces.
func hexEncode(b []byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hexDigits[v>>4]
		out[2*i+1] = hexDigits[v&0x0F]
	}
	return string(out)
}

// joinInts is strings.Join for []int — saves importing strconv per
// element across the file.
func joinInts(xs []int, sep string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, sep)
}

// formatSCP renders one SCPInfo in the report-line shape, e.g.
// "SCP03 i=0x60" or "SCP11 i=0x0D86". The version byte is
// rendered using GP's BCD-ish convention (0x10 = SCP10,
// 0x11 = SCP11, etc.) so users see the labels they recognize.
// i-parameters that don't fit one byte render as four hex digits.
func formatSCP(s cardrecognition.SCPInfo) string {
	var label string
	switch s.Version {
	case 0x02, 0x03, 0x10, 0x11:
		// BCD-ish: high nibble * 10 + low nibble = decimal label.
		label = fmt.Sprintf("SCP%X%X", (s.Version>>4)&0x0F, s.Version&0x0F)
	default:
		label = fmt.Sprintf("SCP(0x%02X)", s.Version)
	}
	if s.Parameter > 0xFF {
		return fmt.Sprintf("%s i=0x%04X", label, s.Parameter)
	}
	return fmt.Sprintf("%s i=0x%02X", label, s.Parameter)
}

// walkRegistry issues GET STATUS for one scope and produces both a
// human-readable PASS/SKIP line on report and a structured slice of
// registryEntryView for JSON output.
//
// Returns nil when the call fails (after recording a SKIP), an empty
// non-nil slice when the card returned no entries (SW=6A88), or a
// populated slice when entries were returned.
func walkRegistry(ctx context.Context, sd *securitydomain.Session, scope securitydomain.StatusScope, label string, report *Report) []registryEntryView {
	return walkRegistryFetched(label, report, func() ([]securitydomain.RegistryEntry, string, error) {
		entries, err := sd.GetStatus(ctx, scope)
		return entries, "", err
	})
}

// walkLoadFiles walks the Executable Load Files scope with the
// LoadFilesAndModules -> LoadFiles fallback (see
// securitydomain.GetStatusLoadFiles). The report check name is
// always "GET STATUS scope=LoadFiles"; the detail string mentions
// "modules omitted" when the card forced the fallback so the
// operator can tell module names are absent from this card's
// response rather than just absent from the data.
//
// Returns (entries, requested-scope, actual-scope). The two scope
// strings let JSON consumers detect when the fallback fired:
// requested is always "load_files_and_modules"; actual is whichever
// scope the card returned. They differ on cards that reject
// LoadFilesAndModules with SW=6A86 / 6D00.
func walkLoadFiles(ctx context.Context, sd *securitydomain.Session, report *Report) ([]registryEntryView, string, string) {
	requested := scopeName(securitydomain.StatusScopeLoadFilesAndModules)
	actual := requested // overwritten by the fetcher below
	views := walkRegistryFetched("LoadFiles", report, func() ([]securitydomain.RegistryEntry, string, error) {
		res, err := sd.GetStatusLoadFiles(ctx)
		if err != nil {
			return nil, "", err
		}
		actual = scopeName(res.Scope)
		var note string
		if res.Scope == securitydomain.StatusScopeLoadFiles {
			note = "modules omitted (card rejected LoadFilesAndModules; fell back to LoadFiles-only)"
		}
		return res.Entries, note, nil
	})
	return views, requested, actual
}

// scopeName returns the snake-case JSON-friendly name of a
// StatusScope, used to populate registryDump's
// LoadFilesRequestedScope / LoadFilesActualScope fields. The
// names mirror the GP §11.4.2 scope identifiers so an operator
// reading the JSON sees the same vocabulary as the spec.
func scopeName(s securitydomain.StatusScope) string {
	switch s {
	case securitydomain.StatusScopeISD:
		return "isd"
	case securitydomain.StatusScopeApplications:
		return "applications"
	case securitydomain.StatusScopeLoadFiles:
		return "load_files"
	case securitydomain.StatusScopeLoadFilesAndModules:
		return "load_files_and_modules"
	default:
		return fmt.Sprintf("unknown_0x%02X", byte(s))
	}
}

// walkRegistryFetched is the shared shape for walkRegistry and
// walkLoadFiles: invoke the supplied fetcher, classify the
// result (skip/empty/populated), and translate to registry
// entry views. The fetch closure returns (entries, fallbackNote,
// err); the note is appended to the PASS detail when non-empty.
func walkRegistryFetched(label string, report *Report, fetch func() ([]securitydomain.RegistryEntry, string, error)) []registryEntryView {
	checkName := fmt.Sprintf("GET STATUS scope=%s", label)
	entries, note, err := fetch()
	if err != nil {
		// SW=6982 (security status not satisfied) is the common
		// authentication-required signal. Other SWs are reported
		// verbatim so the operator can debug. Augment with a
		// friendly hint when the SW matches a known card-behavior
		// pattern that's not actionable as-such — particularly
		// YubiKey, which returns 6A86/6D00/6982 across the GET
		// STATUS scopes by design (the SD doesn't expose the
		// registry over GP semantics; ykman uses out-of-band APIs
		// for the same data). The hint keeps operators from
		// chasing "did I authenticate wrong?" rabbit holes.
		detail := err.Error()
		if hint := getStatusSkipHint(err); hint != "" {
			detail = detail + " — " + hint
		}
		report.Skip(checkName, detail)
		return nil
	}
	if len(entries) == 0 {
		// Empty (SW=6A88) is a successful "card has nothing in this
		// scope" result, not an error. Record as PASS with a clear
		// detail so consumers don't confuse empty with skipped.
		detail := "no entries"
		if note != "" {
			detail = "no entries; " + note
		}
		report.Pass(checkName, detail)
		return []registryEntryView{}
	}

	// Human summary: count + a comma-separated AID list, truncated
	// for readability if there are many.
	aids := make([]string, 0, len(entries))
	for _, e := range entries {
		aids = append(aids, hexEncode(e.AID))
	}
	summary := fmt.Sprintf("%d entries: %s", len(entries), strings.Join(aids, ", "))
	if note != "" {
		summary += "; " + note
	}
	report.Pass(checkName, summary)

	views := make([]registryEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, projectRegistryEntry(e))
	}
	return views
}

// getStatusSkipHint returns a short, operator-friendly explanation
// for known SWs that surface as GET STATUS skips. Empty string
// means "no special hint, just show the raw error." The hints are
// observational — they describe what the card-side behavior
// commonly means in the field — not authoritative claims about
// card behavior.
func getStatusSkipHint(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "6A86"):
		return "card refuses this P1/P2 form (typical of cards that gate registry walks behind a non-GP API; e.g. YubiKey 5.7+)"
	case strings.Contains(msg, "6D00"):
		return "card refuses GET STATUS INS entirely on this scope (typical of cards that don't expose the GP registry; e.g. YubiKey 5.7+)"
	case strings.Contains(msg, "6982"):
		return "card requires a higher authentication level than the current session provides"
	case strings.Contains(msg, "6985"):
		return "card refuses GET STATUS in the current applet lifecycle (e.g. INITIALIZED → SECURED transition pending)"
	default:
		return ""
	}
}

// projectRegistryEntry converts a securitydomain.RegistryEntry to its
// JSON-friendly view. Bytes render as uppercase hex; lifecycle
// carries both the parsed name (LifecycleString) and the raw byte.
func projectRegistryEntry(e securitydomain.RegistryEntry) registryEntryView {
	v := registryEntryView{
		AID:           hexEncode(e.AID),
		Kind:          e.Kind(),
		Lifecycle:     e.LifecycleString(),
		LifecycleByte: fmt.Sprintf("0x%02X", e.Lifecycle),
	}
	if names := e.Privileges.Names(); len(names) > 0 {
		v.Privileges = names
	}
	if len(e.Version) > 0 {
		v.Version = hexEncode(e.Version)
	}
	if len(e.AssociatedSDAID) > 0 {
		v.AssociatedSDAID = hexEncode(e.AssociatedSDAID)
	}
	if len(e.Modules) > 0 {
		mods := make([]string, len(e.Modules))
		for i, m := range e.Modules {
			mods[i] = hexEncode(m)
		}
		v.Modules = mods
	}
	return v
}
