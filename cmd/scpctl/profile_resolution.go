package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
	"github.com/PeculiarVentures/scp/transport"
)

// resolveProfile picks the active card profile for the current
// session. Three paths:
//
//   - --profile=yubikey-sd: returns profile.YubiKey() unconditionally.
//     No probe APDU; the operator pinned the choice.
//   - --profile=standard-sd: returns profile.Standard() unconditionally.
//     Same rationale.
//   - --profile=auto (default): runs profile.Probe on the raw
//     transport BEFORE any session open. Probe sends SELECT AID
//     followed by GET DATA tag 5FC109; success means YubiKey,
//     6A88 (or any other failure) means Standard. Probe runs
//     before session open because it sends raw APDUs that would
//     bypass any secure-channel framing if a session were already
//     active.
//
// On Probe failure (transport error rather than just SW reporting
// "no YubiKey object"), the helper falls back to profile.Standard().
//
// The fallback used to default to profile.YubiKey() for
// "backward compat," but the external review on feat/sd-keys-cli
// flagged this as dangerous: the new generic SD commands (sd
// keys list/export/delete/generate/import, sd allowlist) all use
// this resolver, none of them are legacy YubiKey-only flows that
// need that fallback, and silently treating a probe-failed card
// as a YubiKey enables YubiKey-specific behavior (factory SCP03
// keys, INS=0xF1) that's wrong for a non-YubiKey card.
//
// Standard-fallback is the safe choice: profile.Standard() refuses
// every YubiKey-extension operation host-side with a clear error,
// so a probe-glitched-but-actually-YubiKey card gets a diagnostic
// the operator can act on (rerun with --profile=yubikey-sd to
// confirm), while a genuinely-non-YubiKey card doesn't get
// Yubico-only commands sent to it.
//
// Returns the resolved profile and its Name() string, suitable
// for inclusion in JSON output.
func resolveProfile(
	ctx context.Context,
	t transport.Transport,
	scp03Flags *scp03KeyFlags,
	sdAID []byte,
	report *Report,
) (profile.Profile, string) {
	// Pinned choices: no probe, just return.
	if pinned := scp03Flags.effectiveProfileBeforeProbe(); pinned != nil {
		report.Pass("profile selection", fmt.Sprintf("pinned: %s", pinned.Name()))
		return pinned, pinned.Name()
	}

	// Auto: probe. The sdAID parameter targets a non-default ISD AID
	// when set; nil means probe.Probe defaults to AIDSecurityDomain
	// (the GP-standard ISD), which is the historical behavior.
	result, err := profile.Probe(ctx, t, sdAID)
	if err != nil {
		// Probe SELECT itself failed (transport error or no SD
		// reachable). Fall back to Standard rather than YubiKey
		// — the safer default for a card we couldn't classify.
		// See the function-level comment for rationale; this is
		// the external-review fix that closes the YubiKey-via-
		// fallback hole.
		report.Skip("profile selection",
			fmt.Sprintf("probe failed (%v); falling back to standard-sd "+
				"(pin --profile=yubikey-sd if the card is a YubiKey)", err))
		std := profile.Standard()
		return std, std.Name()
	}
	report.Pass("profile selection",
		fmt.Sprintf("auto-detected: %s", result.Profile.Name()))
	return result.Profile, result.Profile.Name()
}

// openSCP03WithProfile combines profile resolution and SCP03
// session open into one call so the six required-auth verbs
// don't repeat the resolve → open → SetProfile dance.
//
// Order of operations:
//
//  1. resolveProfile (probe via raw transport before any session
//     open, or honor the pinned --profile value)
//  2. OpenSCP03 (handshake + secure channel setup)
//  3. SetProfile on the resulting session
//
// Returns the open session, the resolved profile's Name() string
// for JSON output, and any error from session open. Callers are
// responsible for sd.Close() on success and for emitting their
// usual failure-side report entries on error.
func openSCP03WithProfile(
	ctx context.Context,
	t transport.Transport,
	scp03Cfg *scp03.Config,
	scp03Keys *scp03KeyFlags,
	sdAID []byte,
	report *Report,
) (*securitydomain.Session, string, error) {
	prof, profName := resolveProfile(ctx, t, scp03Keys, sdAID, report)
	sd, err := securitydomain.OpenSCP03WithAID(ctx, t, scp03Cfg, sdAID)
	if err != nil {
		return nil, profName, err
	}
	sd.SetProfile(prof)
	return sd, profName, nil
}

// openManagementSession is the auth-aware Session opener that all
// SCP-using management verbs (sd allowlist set/clear, sd keys
// delete/generate/import in three modes) call. Replaces calling
// openSCP03WithProfile directly; the dispatcher decides between
// SCP03 and SCP11 based on which flag group the operator
// populated.
//
// Auth mode selection:
//
//   - Neither --scp03-* nor --scp11-* flags set
//     -> open SCP03 with implicit factory keys (the historical
//     bootstrap-against-fresh-card path; describeKeys says
//     "factory").
//
//   - Only --scp03-* flags set (any of them, including
//     --scp03-keys-default)
//     -> open SCP03 with the supplied keys.
//
//   - Only --scp11-* flags set (any of them)
//     -> open SCP11a or SCP11c per --scp11-mode. Trust validation
//     comes from --scp11-trust-roots or --scp11-lab-skip-trust;
//     applyToConfig refuses to proceed without one.
//
//   - Both --scp03-* and --scp11-* flags set
//     -> usage error. The two are mutually exclusive auth
//     materials; trying to open both at once is an operator
//     mistake we surface loudly rather than silently picking one.
//
// Per the external review on feat/sd-keys-cli, Finding 4: the
// SCP03-only constraint on management verbs is removed; SCP11a and
// SCP11c are first-class auth modes for the same verbs. SCP11b
// remains rejected (the helper's variant() refuses --scp11-mode=b
// at parse time so the failure is fast and clear).
//
// Returns the open session, the profile name for JSON output, and
// any error. The caller is responsible for sd.Close() on success
// and for emitting their usual failure-side report entries on
// error.
func openManagementSession(
	ctx context.Context,
	t transport.Transport,
	scp03Keys *scp03KeyFlags,
	scp11Keys *scp11KeyFlags,
	sdAID []byte,
	report *Report,
) (*securitydomain.Session, string, error) {
	scp03Set := scp03Keys != nil && scp03Keys.anyFlagSet()
	scp11Set := scp11Keys != nil && scp11Keys.anyFlagSet()

	if scp03Set && scp11Set {
		return nil, "", &usageError{
			msg: "--scp03-* and --scp11-* flag groups are mutually " +
				"exclusive: pick one auth mode (SCP03 with shared keys, " +
				"or SCP11a/c with an OCE certificate). Both groups set " +
				"would be ambiguous about which authenticated session " +
				"the card should open.",
		}
	}

	// SCP11 path. variant() and applyToConfig do the validation;
	// applyToConfig returns *usageError on operator-side mistakes
	// (missing trust root, wrong --scp11-mode, missing OCE inputs).
	if scp11Set {
		cfg, err := scp11Keys.applyToConfig()
		if err != nil {
			report.Fail("parse SCP11 flags", err.Error())
			return nil, "", err
		}
		report.Pass("SCP11 keys", scp11Keys.describeKeys(cfg))

		// Profile resolution. resolveProfile probes the card via
		// the raw transport before any session opens, and the
		// probe doesn't touch SCP11 material at all, so we can
		// reuse the same helper that the SCP03 path uses. The
		// returned profile gates vendor extensions; same gating
		// applies regardless of auth mode.
		prof, profName := resolveProfile(ctx, t, scp03Keys, sdAID, report)

		sd, err := securitydomain.OpenSCP11WithAID(ctx, t, cfg, sdAID)
		if err != nil {
			report.Fail("open SCP11 session", err.Error())
			return nil, profName, fmt.Errorf("open SCP11: %w", err)
		}

		// SCP11a/c authenticate the OCE to the card; SCP11b does
		// not. The flag helper's variant() rejects --scp11-mode=b
		// at parse time, so reaching here under SCP11b would mean
		// the protocol layer regressed and silently downgraded.
		// Belt-and-braces: assert OCE auth on the way out so a
		// regression surfaces here, not at the first management
		// command. The same assertion in cmd_scp11a_sd_read
		// caught real downgrade bugs in earlier protocol-layer
		// changes.
		if !sd.OCEAuthenticated() {
			sd.Close()
			report.Fail("verify OCE auth",
				"session opened but is not OCE-authenticated; "+
					"library may have silently downgraded to SCP11b "+
					"(this is a hard failure, not a soft warn)")
			return nil, profName, fmt.Errorf("SCP11 session is not OCE-authenticated")
		}

		sd.SetProfile(prof)
		report.Pass("open SCP11 session", "")
		return sd, profName, nil
	}

	// SCP03 path (the historical default). Either --scp03-* flags
	// were set explicitly or no auth flags were set at all (the
	// implicit factory-key fallback). applyToConfig figures it out.
	cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		report.Fail("parse SCP03 flags", err.Error())
		return nil, "", err
	}
	report.Pass("SCP03 keys", scp03Keys.describeKeys(cfg))
	sd, profName, err := openSCP03WithProfile(ctx, t, cfg, scp03Keys, sdAID, report)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		return nil, profName, fmt.Errorf("open SCP03: %w", err)
	}
	report.Pass("open SCP03 session", "")
	return sd, profName, nil
}

// validateAuthFlags runs the dry-run-friendly validation of both
// flag groups: applyToConfigOptional on each, plus the mutual-
// exclusion check. Used by commands that have a dry-run path and
// want bad flag values to fail loudly before printing the dry-run
// preview, rather than silently succeeding and only failing later
// when the same flags drive openManagementSession.
//
// Returns nil if both groups are valid (or empty), *usageError if
// the cross-product is set, or whatever applyToConfigOptional
// returns from the offending side. Cheap to call multiple times;
// applyToConfigOptional doesn't touch I/O for either flag group
// (cert / key file reads happen only inside the active SCP11
// path's applyToConfig, which validateAuthFlags doesn't reach).
func validateAuthFlags(scp03Keys *scp03KeyFlags, scp11Keys *scp11KeyFlags) error {
	scp03Set := scp03Keys != nil && scp03Keys.anyFlagSet()
	scp11Set := scp11Keys != nil && scp11Keys.anyFlagSet()
	if scp03Set && scp11Set {
		return &usageError{
			msg: "--scp03-* and --scp11-* flag groups are mutually " +
				"exclusive: pick one auth mode",
		}
	}
	if _, err := scp03Keys.applyToConfigOptional(); err != nil {
		return err
	}
	if scp11Set {
		// applyToConfigOptional on the SCP11 side reads the key
		// and cert files from disk to validate them, which we
		// want — failing fast on a typo'd path is the whole
		// point of the dry-run pre-check.
		if _, err := scp11Keys.applyToConfigOptional(); err != nil {
			return err
		}
	}
	return nil
}
