package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/cardrecognition"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// probeData is the JSON-friendly payload of the probe report. Strings
// for OIDs (decimal-dotted) so JSON output is human-readable without
// custom encoders.
type probeData struct {
	GPVersion             string `json:"gp_version,omitempty"`
	SCPVersion            string `json:"scp_version,omitempty"`
	SCPParameter          string `json:"scp_parameter,omitempty"`
	CardIdentificationOID string `json:"card_identification_oid,omitempty"`
	CardConfigDetailsOID  string `json:"card_config_details_oid,omitempty"`
	CardChipDetailsOID    string `json:"card_chip_details_oid,omitempty"`
	RawHex                string `json:"raw_hex,omitempty"`

	// KeyInfo is populated by 'sd info' (and other callers that set
	// probeOptions.fetchKeyInfo). Each entry is a human-readable
	// summary like 'KID=0x01 KVN=0xFF (3 components)'. Omitted from
	// JSON output when nil so the probe's CRD-only schema stays
	// stable for consumers that only ever see cmdProbe.
	KeyInfo []string `json:"key_info,omitempty"`
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
}

func runProbe(ctx context.Context, env *runEnv, args []string, opts probeOptions) error {
	fs := newSubcommandFlagSet(opts.flagSetName, env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: opts.reportLabel, Reader: *reader}

	sd, err := securitydomain.OpenUnauthenticated(ctx, t)
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
	if info.SCPVersion != 0 {
		data.SCPVersion = fmt.Sprintf("0x%02X", info.SCPVersion)
		data.SCPParameter = fmt.Sprintf("0x%02X", info.SCPParameter)
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
	switch info.SCPVersion {
	case 0x02:
		report.Pass("SCP advertised", "SCP02 i="+data.SCPParameter)
	case 0x03:
		report.Pass("SCP advertised", "SCP03 i="+data.SCPParameter)
	case 0x11:
		report.Pass("SCP advertised", "SCP11 i="+data.SCPParameter)
	case 0:
		report.Skip("SCP advertised", "no SCP element in CRD")
	default:
		report.Skip("SCP advertised", fmt.Sprintf("unknown SCP version 0x%02X", info.SCPVersion))
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
