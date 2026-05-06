package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type sdUnlockData struct {
	LifecycleBefore string `json:"lifecycle_before,omitempty"`
	LifecycleAfter  string `json:"lifecycle_after,omitempty"`
	Unlocked        bool   `json:"unlocked"`
}

// cmdSDUnlock transitions the Issuer Security Domain from
// CARD_LOCKED back to SECURED via GP §11.1.10 SET STATUS.
//
// Unlock is the recovery path from a previous 'sd lock'. It uses
// the same SCP03 authentication the lock command did — the SD's
// keys keep working through CARD_LOCKED for exactly this purpose.
// If the SCP03 keys have been forgotten, the card is effectively
// permanently locked from the operator's perspective; there's no
// "factory reset out of CARD_LOCKED" path because reset itself
// requires authenticated access to the SD.
//
// Pre-flight check.
//
// Before opening the SCP03 session, unlock reads the current ISD
// lifecycle via an unauthenticated GET STATUS. If the card is
// already SECURED (or any non-LOCKED state that isn't TERMINATED),
// the destructive path is skipped — there's nothing to unlock. If
// the card is TERMINATED, unlock refuses outright; TERMINATED is
// not recoverable by any operation.
//
// Confirmation gating.
//
// --confirm-write, same as 'sd lock'. Unlock is reversible (a
// future 'sd lock' restores CARD_LOCKED), so a separate confirm
// flag would be over-engineering.
func cmdSDUnlock(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd unlock", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd unlock runs in "+
			"dry-run mode (validates inputs and reports the planned "+
			"transition without transmitting SET STATUS).")
	scp03Keys := registerSCP03KeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	report := &Report{Subcommand: "sd unlock", Reader: *reader}
	data := &sdUnlockData{}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	stateBefore, preErr := readISDLifecycle(ctx, t)
	if preErr == nil {
		data.LifecycleBefore = stateBefore.String()
		report.Pass("read pre-unlock state", stateBefore.String())

		switch stateBefore {
		case securitydomain.LifecycleSecured,
			securitydomain.LifecycleOPReady,
			securitydomain.LifecycleInitialized:
			report.Skip("unlock",
				fmt.Sprintf("card is %s, not CARD_LOCKED; no transition needed",
					stateBefore))
			_ = report.Emit(env.out, *jsonMode)
			return nil
		case securitydomain.LifecycleTerminated:
			report.Fail("unlock",
				"card is TERMINATED — irrecoverable, unlock has no effect")
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("sd unlock: card is TERMINATED")
		}
	} else {
		report.Skip("read pre-unlock state",
			fmt.Sprintf("%v (proceeding without pre-check)", preErr))
	}

	if !*confirm {
		report.Skip("unlock",
			"dry-run; pass --confirm-write to actually transition the ISD "+
				"from CARD_LOCKED to SECURED.")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd unlock: open SCP03: %w", err)
	}
	if err := sd.SetISDLifecycle(ctx, securitydomain.LifecycleSecured); err != nil {
		sd.Close()
		report.Fail("unlock", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd unlock: SET STATUS: %w", err)
	}
	sd.Close()
	data.Unlocked = true
	report.Pass("unlock",
		"ISD transitioned to SECURED via SET STATUS (P1=0x80 P2=0x0F)")

	stateAfter, postErr := readISDLifecycle(ctx, t)
	if postErr == nil {
		data.LifecycleAfter = stateAfter.String()
		report.Pass("read post-unlock state", stateAfter.String())
	} else {
		report.Skip("read post-unlock state",
			fmt.Sprintf("%v (unlock SUCCESS, post-check unavailable)", postErr))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd unlock reported failures")
	}
	return nil
}
