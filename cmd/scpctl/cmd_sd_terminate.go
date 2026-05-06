package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type sdTerminateData struct {
	LifecycleBefore string `json:"lifecycle_before,omitempty"`
	LifecycleAfter  string `json:"lifecycle_after,omitempty"`
	Terminated      bool   `json:"terminated"`
}

// cmdSDTerminate transitions the Issuer Security Domain to the
// TERMINATED lifecycle state via GP §11.1.10 SET STATUS. This is
// IRREVERSIBLE: a TERMINATED card cannot be recovered by any
// operation — no reset, no re-personalization, no manufacturer
// recovery short of chip replacement. GP-conformant cards reject
// every non-SELECT command after TERMINATED.
//
// Use cases.
//
// Terminate is the credential-destruction step in a card
// decommissioning workflow. Lock is appropriate for "freeze pending
// investigation"; terminate is appropriate for "this card must
// never authenticate again" — lost / compromised / end-of-life.
// PIV applet state is reachable on a TERMINATED card to the same
// extent as any other applet (i.e. not at all post-terminate); for
// PIV-only revocation without bricking the SD, use 'piv reset'.
//
// Confirmation gating — DELIBERATELY DIFFERENT.
//
// --confirm-write is NOT sufficient for terminate. The flag is
// --confirm-terminate-card, modeled on 'sd reset's --confirm-reset-sd
// pattern. Two reasons:
//
//   - Terminate's blast radius is permanent, not just destructive.
//     Overloading --confirm-write across reversible (lock) and
//     irreversible (terminate) operations would mean a single
//     careless invocation of one command-line incantation could
//     brick a card. Distinct flags force the operator to type the
//     specific consequence into the command.
//
//   - Audit trails get clearer evidence of intent. A shell history
//     showing --confirm-terminate-card is unambiguous; --confirm-write
//     could mean any of half a dozen things.
//
// Pre-flight check.
//
// Before the SCP03 session, terminate reads the ISD lifecycle via
// an unauthenticated GET STATUS. If the card is already TERMINATED,
// the command short-circuits as a no-op (the transition is
// idempotent and TERMINATED→TERMINATED is meaningless). For any
// other current state, the command proceeds — terminate is legal
// from SECURED, CARD_LOCKED, OP_READY, and INITIALIZED on
// GP-conformant cards.
func cmdSDTerminate(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd terminate", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	confirm := fs.Bool("confirm-terminate-card", false,
		"Confirm IRREVERSIBLE card termination. Without this flag, "+
			"sd terminate runs in dry-run mode and prints what would "+
			"happen. Distinct from --confirm-write because terminate "+
			"is permanent: a TERMINATED card cannot be recovered by "+
			"any operation. Modeled on 'sd reset's --confirm-reset-sd "+
			"pattern — overloading a single confirm flag across "+
			"reversible and irreversible operations is a foot-gun.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	report := &Report{Subcommand: "sd terminate", Reader: *reader}
	data := &sdTerminateData{}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	stateBefore, preErr := readISDLifecycle(ctx, t)
	if preErr == nil {
		data.LifecycleBefore = stateBefore.String()
		report.Pass("read pre-terminate state", stateBefore.String())

		if stateBefore == securitydomain.LifecycleTerminated {
			report.Skip("terminate",
				"card is already TERMINATED; no transition needed")
			_ = report.Emit(env.out, *jsonMode)
			return nil
		}
	} else {
		report.Skip("read pre-terminate state",
			fmt.Sprintf("%v (proceeding without pre-check)", preErr))
	}

	if !*confirm {
		report.Skip("terminate",
			"dry-run; pass --confirm-terminate-card to PERMANENTLY "+
				"terminate the card. This is IRREVERSIBLE — a TERMINATED "+
				"card cannot be recovered by any operation. PIV applet "+
				"state becomes inaccessible. Use --confirm-terminate-card "+
				"only when the card must never authenticate again "+
				"(decommission, compromise, end-of-life).")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd terminate: open SCP03: %w", err)
	}
	if err := sd.SetISDLifecycle(ctx, securitydomain.LifecycleTerminated); err != nil {
		sd.Close()
		report.Fail("terminate", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd terminate: SET STATUS: %w", err)
	}
	sd.Close()
	data.Terminated = true
	report.Pass("terminate",
		"ISD transitioned to TERMINATED via SET STATUS (P1=0x80 P2=0xFF). "+
			"This is permanent.")

	// Post-flight check — best effort. On a TERMINATED card the
	// SELECT might still work (some cards permit SELECT against
	// the ISD even post-terminate so an operator can confirm
	// state) but GET STATUS may not. A failure here is expected;
	// it just means the card is correctly refusing operations
	// after termination.
	stateAfter, postErr := readISDLifecycle(ctx, t)
	if postErr == nil {
		data.LifecycleAfter = stateAfter.String()
		report.Pass("read post-terminate state", stateAfter.String())
	} else {
		report.Skip("read post-terminate state",
			fmt.Sprintf("%v (terminate SUCCESS — post-check unavailable, "+
				"which is expected on a TERMINATED card)", postErr))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd terminate reported failures")
	}
	return nil
}
