package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/cardrecognition"
	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/securitydomain"
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
	GPVersion             string `json:"gp_version,omitempty"`
	SCPVersion            string `json:"scp_version,omitempty"`
	SCPParameter          string `json:"scp_parameter,omitempty"`
	SCPs                  []string `json:"scps,omitempty"`
	CardIdentificationOID string   `json:"card_identification_oid,omitempty"`
	CardConfigDetailsOID  string   `json:"card_config_details_oid,omitempty"`
	CardChipDetailsOID    string   `json:"card_chip_details_oid,omitempty"`
	RawHex                string   `json:"raw_hex,omitempty"`

	// KeyInfo is populated by 'sd info' (and other callers that set
	// probeOptions.fetchKeyInfo). Each entry is a human-readable
	// summary like 'KID=0x01 KVN=0xFF (3 components)'. Omitted from
	// JSON output when nil so the probe's CRD-only schema stays
	// stable for consumers that only ever see cmdProbe.
	KeyInfo []string `json:"key_info,omitempty"`

	// Registry is populated by 'sd info --full'. Each scope has
	// its own slice; nil means that scope was not queried, an empty
	// slice means the card returned SW=6A88 (no entries) for it.
	// Per-entry detail is structured for JSON consumers; the
	// human-readable surface is the per-scope GET STATUS line in
	// Checks (count and a brief AID summary).
	Registry *registryDump `json:"registry,omitempty"`
}

// registryDump is the JSON shape of a --full GP registry walk.
type registryDump struct {
	ISD          []registryEntryView `json:"isd,omitempty"`
	Applications []registryEntryView `json:"applications,omitempty"`
	LoadFiles    []registryEntryView `json:"load_files,omitempty"`
}

// registryEntryView is the JSON projection of a securitydomain.RegistryEntry.
// Bytes are rendered as uppercase hex; Lifecycle has both the parsed
// human form and the raw byte so callers can re-interpret if needed.
type registryEntryView struct {
	AID             string   `json:"aid"`
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
		flagSetName: "probe",
		reportLabel: "probe",
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
	// is fetched and reported. cmdProbe does not (CRD is the
	// historical scope). cmdSDInfo does, because reporting card
	// identity at the SD-info level should include which key
	// references the card has installed.
	fetchKeyInfo bool

	// allowFullStatus controls whether 'sd info --full' is reachable
	// from this entry point. cmdSDInfo sets it; cmdProbe does not,
	// keeping the historical 'probe' surface CRD-only.
	allowFullStatus bool
}

func runProbe(ctx context.Context, env *runEnv, args []string, opts probeOptions) error {
	fs := newSubcommandFlagSet(opts.flagSetName, env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	sdAIDHex := fs.String("sd-aid", "",
		"Override the Security Domain AID, hex (5..16 bytes). Default is the GP ISD AID (A000000151000000). Use this for cards with a non-default ISD (some SafeNet/Fusion variants, custom JCOP installs).")
	discoverSD := fs.Bool("discover-sd", false,
		"Walk a curated list of candidate Security Domain AIDs (gp.ISDDiscoveryAIDs) and use the first one that responds 9000. Mutually exclusive with --sd-aid. Probes return SW=6A82 on absent AIDs; any other non-9000 SW aborts discovery. The chosen AID appears in the report so subsequent runs can pin it via --sd-aid.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	var fullMode *bool
	if opts.allowFullStatus {
		fullMode = fs.Bool("full", false,
			"Walk the GP registry via GET STATUS (GP §11.4.2): "+
				"ISD, Applications + SSDs, Load Files + Modules. "+
				"Each scope reports separately; auth-required scopes "+
				"appear as SKIP on cards that refuse them over an "+
				"unauthenticated session.")
	}
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	sdAID, err := decodeSDAIDFlag(*sdAIDHex)
	if err != nil {
		return &usageError{msg: err.Error()}
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
	if *discoverSD {
		var match gp.ISDCandidate
		sd, match, err = securitydomain.DiscoverISD(ctx, t, gp.ISDDiscoveryAIDs)
		if err != nil {
			report.Fail("discover ISD", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("discover ISD: %w", err)
		}
		report.Pass("discover ISD",
			fmt.Sprintf("matched %s — %s", candidateAIDStr(match), match.Source))
	} else {
		sd, err = securitydomain.OpenUnauthenticated(ctx, t, sdAID)
	}
	if err != nil {
		report.Fail("select ISD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("select ISD: %w", err)
	}
	defer sd.Close()
	report.Pass("select ISD", "")

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

	data := &probeData{RawHex: hexEncode(raw)}
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
		dump.LoadFiles = walkRegistry(ctx, sd, securitydomain.StatusScopeLoadFilesAndModules, "LoadFiles", report)
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
	checkName := fmt.Sprintf("GET STATUS scope=%s", label)
	entries, err := sd.GetStatus(ctx, scope)
	if err != nil {
		// SW=6982 (security status not satisfied) is the common
		// authentication-required signal. Other SWs are reported
		// verbatim so the operator can debug.
		report.Skip(checkName, err.Error())
		return nil
	}
	if len(entries) == 0 {
		// Empty (SW=6A88) is a successful "card has nothing in this
		// scope" result, not an error. Record as PASS with a clear
		// detail so consumers don't confuse empty with skipped.
		report.Pass(checkName, "no entries")
		return []registryEntryView{}
	}

	// Human summary: count + a comma-separated AID list, truncated
	// for readability if there are many.
	aids := make([]string, 0, len(entries))
	for _, e := range entries {
		aids = append(aids, hexEncode(e.AID))
	}
	summary := fmt.Sprintf("%d entries: %s", len(entries), strings.Join(aids, ", "))
	report.Pass(checkName, summary)

	views := make([]registryEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, projectRegistryEntry(e))
	}
	return views
}

// projectRegistryEntry converts a securitydomain.RegistryEntry to its
// JSON-friendly view. Bytes render as uppercase hex; lifecycle
// carries both the parsed name (LifecycleString) and the raw byte.
func projectRegistryEntry(e securitydomain.RegistryEntry) registryEntryView {
	v := registryEntryView{
		AID:           hexEncode(e.AID),
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
