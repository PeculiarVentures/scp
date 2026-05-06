package main

// `scpctl piv reset` — factory-reset the PIV applet.
//
// YubiKey-only. The card requires PIN AND PUK to BOTH be in a
// blocked state before it accepts the RESET command — this is
// a deliberate guard against accidental factory reset of a
// provisioned card. This verb performs the block-then-reset
// sequence end-to-end: authenticate, exhaust PIN attempts,
// exhaust PUK attempts, then issue RESET.
//
// After a successful reset:
//   PIN  -> 123456 (factory default)
//   PUK  -> 12345678 (factory default)
//   Mgmt -> 010203040506070801020304050607080102030405060708
//                  (factory default 3DES)
//   All slots empty, all certs cleared.
//
// Refused under StandardPIV — this is a Yubico extension,
// non-Yubico cards don't support it. The host-side gate
// returns ErrUnsupportedByProfile rather than letting a
// vendor-specific RESET INS go to the card.
//
// Split from cmd_piv_ops.go because the reset verb is its own
// top-level group (not under any of key/cert/object/mgmt)
// and the block-then-reset state machine is logically
// distinct from anything in those groups.
//
// The dispatcher in cmd_piv_ops.go routes here when the user
// invokes `scpctl piv reset` directly.

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/piv/session"
)

// cmdPIVGroupReset resets the PIV applet to factory state. YubiKey-only;
// refused under StandardPIV. YubiKey requires PIN and PUK to both be
// blocked before the applet accepts RESET; this command performs the
// block-then-reset sequence via piv/session.
//
// Reset is the most-destructive PIV operation: every slot keypair
// is erased, every certificate is dropped, PIN/PUK/management-key
// all return to factory defaults. A wrong-card reset is a card
// that has to be re-enrolled, with all of the trust-bootstrap cost
// that implies. So this command requires its own scope-correct
// confirmation flag: --confirm-reset-piv. Slot-scoped destructive
// operations (key generate, cert put, etc.) gate on --confirm-write;
// applet-scoped destructive operations (this one) gate on
// --confirm-reset-piv. SD reset, with its own different blast
// radius, gates on --confirm-reset-sd. An operator who pastes a
// stale command line with --confirm-write cannot accidentally turn
// a slot rotation into a full applet reset because --confirm-write
// alone no longer enables this path; it surfaces a deprecation
// SKIP and falls through to dry-run.
//
// Dry-run is the default. Without --confirm-reset-piv the command
// prints what it WOULD do, including the explicit note that SD
// state is not affected.
func cmdPIVGroupReset(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv reset", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	confirm := fs.Bool("confirm-reset-piv", false,
		"Confirm PIV applet reset. Without this flag, piv reset runs in "+
			"dry-run mode and prints what would happen. Distinct from "+
			"--confirm-write (which gates slot-scoped operations) because "+
			"PIV reset has applet-wide blast radius: ALL 24 slot keys, ALL "+
			"certificates, PIN, PUK, and management key are erased. For SD "+
			"reset (different applet), see 'scpctl sd reset'.")
	confirmWriteLegacy := fs.Bool("confirm-write", false,
		"DEPRECATED. Use --confirm-reset-piv instead. Kept so scripts that "+
			"pass --confirm-write don't crash on the unknown flag, but it no "+
			"longer enables the destructive path on its own — set "+
			"--confirm-reset-piv to actually mutate.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}

	report := &Report{Subcommand: "piv reset", Reader: *reader}

	// Stale-script safety: if --confirm-write is set without
	// --confirm-reset-piv, surface a clear deprecation SKIP and
	// fall through to dry-run rather than treating the old flag
	// as the new one.
	if *confirmWriteLegacy && !*confirm {
		report.Skip("--confirm-write (deprecated)",
			"--confirm-write no longer enables PIV reset on its own. "+
				"Pass --confirm-reset-piv to actually mutate. Treating this run as dry-run.")
	}

	if !*confirm {
		report.Skip("open SCP11b vs PIV", "dry-run; pass --confirm-reset-piv to actually open a session")
		report.Skip("PIV reset", "dry-run — would erase ALL 24 PIV slots, certs, and reset PIN/PUK/management key. Does NOT touch Security Domain state.")
		return report.Emit(env.out, *jsonMode)
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	sess, proceed, err := openPIVSession(ctx, t, chFlags, report)
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	if !proceed {
		return report.Emit(env.out, *jsonMode)
	}
	defer sess.Close()

	// YubiKey requires PIN and PUK to both be blocked before the
	// PIV applet accepts RESET. Without that precondition the card
	// returns SW=6985 ("conditions of use not satisfied"). This
	// command goes through piv/session, which exposes BlockPIN /
	// BlockPUK for the same sequence at the session abstraction
	// level.
	pinAttempts, err := sess.BlockPIN(ctx, 16)
	if err != nil {
		report.Fail("block PIN", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PIN: %w", err)
	}
	report.Pass("block PIN", fmt.Sprintf("blocked after %d wrong attempts", pinAttempts))

	pukAttempts, err := sess.BlockPUK(ctx, 16)
	if err != nil {
		report.Fail("block PUK", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PUK: %w", err)
	}
	report.Pass("block PUK", fmt.Sprintf("blocked after %d wrong attempts", pukAttempts))

	if err := sess.Reset(ctx, session.ResetOptions{}); err != nil {
		report.Fail("PIV reset", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("PIV reset", "applet returned to factory state (PIN=123456, PUK=12345678)")
	return report.Emit(env.out, *jsonMode)
}

