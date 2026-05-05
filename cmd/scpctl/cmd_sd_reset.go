package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type sdResetData struct {
	KeysBefore []string `json:"keys_before"`
	KeysAfter  []string `json:"keys_after,omitempty"`
	Reset      bool     `json:"reset_success"`
}

// cmdSDReset performs a factory reset of the card's Security Domain.
//
// Unlike PIV reset (which targets a single applet's slots, PIN, PUK,
// and management key), SD reset clears Security Domain key material
// and restores the factory SCP key set. PIV applet state is not
// affected — the two resets are independent operations on different
// applets.
//
// What the reset removes:
//   - Custom OCE / CA-KLOC keys installed at KID=0x10 (and 0x20–0x2F)
//   - Custom SCP11a SD keys at KID=0x11 (and 0x15 for SCP11c)
//   - Any custom SCP03 key sets
//   - Stored CA-IDENTIFIER (SKI) entries
//   - Stored allowlists
//
// What the reset restores:
//   - Factory SCP03 keys at KVN=0xFF (KID=0x01,0x02,0x03)
//   - Freshly-generated SCP11b key at KID=0x13/KVN=0x01
//
// The reset works by opening an unauthenticated SD session, then for
// each installed key sending up to 65 deliberately-wrong credentials
// until the card returns AUTH_METHOD_BLOCKED. Once every key is
// blocked, the card auto-restores factory state. This is the same
// algorithm yubikit's `ykman sd reset` uses; it does not require
// authentication, which means it works even when the card's
// factory SCP03 keys have been consumed by an earlier provisioning
// pass and no authentication path exists.
//
// Two separate confirmation gates per the scpctl parity spec:
//   - --confirm-reset-sd is required for the SD reset itself.
//   - --confirm-write is NOT sufficient on its own; the spec calls
//     out that overloading --confirm-write across applet/SD scopes
//     is a foot-gun and reset operations should each have their
//     own opt-in flag.
//
// Dry-run mode (default) reads the current key inventory and prints
// what *would* be removed, without sending any mutating APDUs.
func cmdSDReset(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd reset", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	confirm := fs.Bool("confirm-reset-sd", false,
		"Confirm Security Domain reset. Without this flag, sd reset runs in "+
			"dry-run mode and prints the current key inventory plus what would "+
			"be removed. Distinct from --confirm-write because SD reset and "+
			"PIV reset have different blast radii and overloading a single "+
			"flag across both is a foot-gun.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	report := &Report{Subcommand: "sd reset", Reader: *reader}
	data := &sdResetData{}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	// Read pre-reset key inventory. This is what the reset would
	// remove (or, in dry-run mode, what it WOULD remove). Doing
	// this before the dry-run check means the operator gets a
	// useful "what's on the card" answer even on dry-run.
	sdRead, err := securitydomain.OpenUnauthenticated(ctx, t)
	if err != nil {
		report.Fail("read pre-reset inventory", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("read pre-reset inventory: %w", err)
	}
	keysBefore, err := sdRead.GetKeyInformation(ctx)
	sdRead.Close()
	if err != nil {
		report.Fail("read pre-reset inventory", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("read pre-reset inventory: %w", err)
	}
	data.KeysBefore = describeKeys(keysBefore)
	report.Pass("read pre-reset inventory",
		fmt.Sprintf("%d key(s): %s", len(keysBefore), strings.Join(data.KeysBefore, "; ")))

	if !*confirm {
		report.Skip("SD reset",
			"dry-run; pass --confirm-reset-sd to actually reset. "+
				"This will block all installed keys with 65 wrong-credential attempts "+
				"each, then the card auto-restores factory SCP03 + SCP11b state. "+
				"PIV applet state is NOT affected.")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	// Destructive path. ResetSecurityDomain opens its own
	// unauthenticated session, runs the block-and-burn loop, and
	// closes — no need for the caller to pre-open or post-close.
	if err := securitydomain.ResetSecurityDomain(ctx, t); err != nil {
		report.Fail("SD reset", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("SD reset: %w", err)
	}
	data.Reset = true
	report.Pass("SD reset",
		"factory SCP03 keys restored at KVN=0xFF; SCP11b key regenerated at KID=0x13/KVN=0x01")

	// Post-reset inventory. The card should now show only the
	// factory key set: SCP03 (KID 0x01-0x03 at KVN=0xFF) and the
	// regenerated SCP11b at KID=0x13/KVN=0x01.
	sdAfter, err := securitydomain.OpenUnauthenticated(ctx, t)
	if err != nil {
		report.Fail("read post-reset inventory", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("read post-reset inventory: %w", err)
	}
	keysAfter, err := sdAfter.GetKeyInformation(ctx)
	sdAfter.Close()
	if err != nil {
		report.Fail("read post-reset inventory", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("read post-reset inventory: %w", err)
	}
	data.KeysAfter = describeKeys(keysAfter)
	report.Pass("read post-reset inventory",
		fmt.Sprintf("%d key(s): %s", len(keysAfter), strings.Join(data.KeysAfter, "; ")))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd reset reported failures")
	}
	return nil
}

func describeKeys(keys []securitydomain.KeyInfo) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("KID=0x%02X KVN=0x%02X",
			k.Reference.ID, k.Reference.Version))
	}
	return out
}
