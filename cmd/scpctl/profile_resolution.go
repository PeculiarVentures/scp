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
	report *Report,
) (profile.Profile, string) {
	// Pinned choices: no probe, just return.
	if pinned := scp03Flags.effectiveProfileBeforeProbe(); pinned != nil {
		report.Pass("profile selection", fmt.Sprintf("pinned: %s", pinned.Name()))
		return pinned, pinned.Name()
	}

	// Auto: probe.
	result, err := profile.Probe(ctx, t, nil)
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
	report *Report,
) (*securitydomain.Session, string, error) {
	prof, profName := resolveProfile(ctx, t, scp03Keys, report)
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		return nil, profName, err
	}
	sd.SetProfile(prof)
	return sd, profName, nil
}
