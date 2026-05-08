package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// gpRegistryData is the JSON payload of `gp registry`. Lean on the
// shared registryDump shape from cmd_probe.go so consumers parsing
// `sd info --full --json` and `gp registry --json` see structurally
// identical registry sections — only the surrounding subcommand
// label differs.
type gpRegistryData struct {
	Protocol string        `json:"protocol,omitempty"`
	Registry *registryDump `json:"registry,omitempty"`
}

// cmdGPRegistry opens an authenticated SCP03 session and walks the
// GP registry across three scopes:
//
//	StatusScopeISD                  Issuer Security Domain only.
//	StatusScopeApplications         Applications and SSDs.
//	StatusScopeLoadFilesAndModules  Executable Load Files plus the
//	                                Module list per package.
//
// The fourth defined StatusScope value, StatusScopeLoadFiles (load
// files only), is intentionally not walked: LoadFilesAndModules is
// a strict superset on every card we have observed, so issuing it
// separately would cost an APDU round-trip for no additional data.
// Adding it later if a real card is found that responds to one and
// not the other is a single-line change.
//
// Authentication uses the standard registerSCP03KeyFlags surface so
// the same key-input idioms (factory default, custom rotated keys,
// or single-key shorthand) work here as in bootstrap-oce and
// scp03-sd-read.
//
// Output mirrors `sd info --full` for the registry sections so
// scripts that already parse that JSON shape can switch to
// `gp registry` without parser changes. The label, the surrounding
// non-registry fields (no CRD fields here, just protocol), and the
// command help text are what differ.
func cmdGPRegistry(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("gp registry", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	sdAIDHex := fs.String("sd-aid", "",
		"Override the Security Domain AID, hex (5..16 bytes). Default is the GP ISD AID.")
	discoverSD := fs.Bool("discover-sd", false,
		"Walk a curated list of candidate Security Domain AIDs (gp.ISDDiscoveryAIDs) and use the first one that responds 9000, then open SCP03 against it. Mutually exclusive with --sd-aid. Useful for cards (SafeNet eToken, GemPlus / Thales-built JCOPs) whose ISD lives at A000000018434D00 or A0000001510000 rather than the GP default A000000151000000.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	// Generic GP commands gate on an explicit SCP03 key-set choice
	// rather than falling through to YubiKey factory defaults. The
	// gp group's audience may be pointing at a JCOP, SafeNet, or
	// other non-YubiKey GP card where 404142...4F is meaningless;
	// silently trying it as a default is operator-hygiene
	// surprising. Legacy YubiKey-flavored commands (test scp03-sd-
	// read, sd lock/unlock/terminate, bootstrap-*) keep the implicit
	// default for compatibility with their existing call sites.
	if !scp03Keys.explicitlyConfigured() {
		return &usageError{msg: "gp registry requires an explicit SCP03 key choice: pass " +
			"--scp03-keys-default for YubiKey/test-card factory keys, " +
			"--scp03-kvn with --scp03-key for single-key cards, or " +
			"--scp03-kvn with --scp03-{enc,mac,dek} for split-key cards"}
	}

	cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}
	sdAID, err := decodeSDAIDFlag(*sdAIDHex)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	if *discoverSD && sdAID != nil {
		return &usageError{msg: "--discover-sd and --sd-aid are mutually exclusive (pick one)"}
	}
	if sdAID != nil {
		cfg.SelectAID = sdAID
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "gp registry", Reader: *reader}
	data := &gpRegistryData{}
	report.Data = data
	report.Pass("SCP03 keys", scp03Keys.describeKeys(cfg))

	// Discovery walks SELECT-only first to find the SD AID, then
	// closes that session and opens SCP03 against the discovered
	// AID. Going through OpenSCP03WithAID directly would skip the
	// curated-AID walk and refuse against any card whose ISD is
	// not at A000000151000000.
	if *discoverSD {
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
		discoverySD, match, derr := securitydomain.DiscoverISD(ctx, t, gp.ISDDiscoveryAIDs, trace)
		if derr != nil {
			report.Fail("discover ISD", derr.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("discover ISD: %w", derr)
		}
		// Close the discovery session before opening SCP03 against
		// the same AID. Carrying the SELECT-only session through
		// to the SCP03 layer would feed an INITIALIZE UPDATE on a
		// transport that already has SD state; cleaner to start
		// fresh. The transport (`t`) stays open across both.
		discoverySD.Close()
		report.Pass("discover ISD",
			fmt.Sprintf("matched %s — %s", candidateAIDStr(match), match.Source))
		sdAID = append([]byte(nil), match.AID...)
		cfg.SelectAID = sdAID
	}

	sd, err := securitydomain.OpenSCP03WithAID(ctx, t, cfg, sdAID)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP03 SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP03 SD", scp03Keys.describeKeys(cfg))

	if !sd.IsAuthenticated() {
		// SCP03 Open should not return without authentication, but
		// pin the invariant explicitly. A non-authenticated session
		// cannot serve GET STATUS for the auth-required scopes.
		report.Fail("authenticated", "Session.IsAuthenticated() is false after OpenSCP03")
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("session not authenticated after OpenSCP03")
	}

	dump := &registryDump{}
	dump.ISD = walkRegistry(ctx, sd, securitydomain.StatusScopeISD, "ISD", report)
	dump.Applications = walkRegistry(ctx, sd, securitydomain.StatusScopeApplications, "Applications", report)
	dump.LoadFiles, dump.LoadFilesRequestedScope, dump.LoadFilesActualScope = walkLoadFiles(ctx, sd, report)
	if dump.LoadFilesRequestedScope != dump.LoadFilesActualScope {
		// Surface the scope mismatch as its own report line so
		// text-mode operators see it without having to read the
		// "modules omitted" note buried in the LoadFiles detail.
		// JSON consumers see it via the load_files_requested_scope
		// vs load_files_actual_scope fields on registryDump.
		report.Pass("load files scope fallback",
			fmt.Sprintf("requested %s, card returned %s",
				dump.LoadFilesRequestedScope, dump.LoadFilesActualScope))
	}
	if dump.ISD != nil || dump.Applications != nil || dump.LoadFiles != nil {
		data.Registry = dump
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("gp registry reported failures")
	}
	return nil
}
