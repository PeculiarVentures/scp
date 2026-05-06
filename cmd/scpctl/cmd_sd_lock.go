package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type sdLockData struct {
	LifecycleBefore string `json:"lifecycle_before,omitempty"`
	LifecycleAfter  string `json:"lifecycle_after,omitempty"`
	Locked          bool   `json:"locked"`
	// LastSW carries the raw card-side status word for a failed
	// SET STATUS, as a 4-digit uppercase hex string (e.g. "6985"
	// for conditions-of-use, "6982" for security-status,
	// "6A88" for referenced-data-not-found). Empty when the
	// transition succeeded or when the failure didn't originate
	// from a card-side rejection (transport error, OCE-auth
	// refusal). Per the external review on feat/sd-keys-cli,
	// Finding 10: lifecycle JSON should preserve raw SW for
	// every failed transition so an operator can distinguish
	// 'card policy rejected this transition' from 'host encoded
	// wrong APDU' without parsing the free-form Detail string.
	LastSW string `json:"last_sw,omitempty"`
}

// cmdSDLock transitions the Issuer Security Domain to the
// CARD_LOCKED lifecycle state via GP §11.1.10 SET STATUS.
//
// What CARD_LOCKED means in practice.
//
// A locked card rejects most operational commands (PIV authentication,
// SCP11b session opens, application selects beyond what's needed for
// recovery). What's still allowed: SCP authentication using the SD's
// existing keys, which is exactly the channel needed to issue an
// unlock. Lock is intended as a "freeze the card pending
// investigation" state, not a permanent disable — for that, see
// 'sd terminate'.
//
// Lock is recoverable. Run 'sd unlock' to transition back to SECURED
// from CARD_LOCKED. Both commands require an authenticated SCP
// session (SCP03 by default; the same --scp03-* keys flags as the
// rest of the SD-management commands).
//
// Pre-flight check.
//
// Before opening the SCP03 session, lock reads the current ISD
// lifecycle via an unauthenticated GET STATUS. If the card is
// already CARD_LOCKED, the destructive path is skipped (the
// transition would be a no-op, but real cards return 6985 on a
// SECURED→SECURED-style request and that surfaces as a confusing
// error). If the card is TERMINATED, lock refuses outright — there
// is no recovery from TERMINATED and pretending otherwise would
// mislead operators.
//
// Confirmation gating.
//
// Lock is destructive in the sense that it changes observable card
// behavior, but it is reversible (unlock restores SECURED). The
// gate flag is the standard --confirm-write — same as the other
// SD-management writes. Distinct from --confirm-terminate-card,
// which is reserved for the irreversible terminate path.
//
// SCP protocol.
//
// SCP03 is the default and the only protocol exposed by this
// command. Cards with rotated SCP03 keys must supply --scp03-kvn /
// --scp03-enc / --scp03-mac / --scp03-dek. Lock does not require
// the DEK (no key wrapping happens), but the SCP03 handshake
// itself does, so the standard scp03 key flags apply unchanged.
func cmdSDLock(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd lock", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd lock runs in "+
			"dry-run mode (validates inputs and reports the planned "+
			"transition without transmitting SET STATUS).")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	report := &Report{Subcommand: "sd lock", Reader: *reader}
	data := &sdLockData{}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	// Pre-flight lifecycle read. Best-effort — if the card requires
	// auth for ISD reads we proceed without a pre-check rather than
	// fail closed; the destructive path will surface any real
	// problem at SET STATUS time.
	stateBefore, preErr := readISDLifecycle(ctx, t)
	if preErr == nil {
		data.LifecycleBefore = stateBefore.String()
		report.Pass("read pre-lock state", stateBefore.String())

		// Short-circuit on idempotent and irrecoverable states.
		switch stateBefore {
		case securitydomain.LifecycleCardLocked:
			report.Skip("lock",
				"card is already CARD_LOCKED; no transition needed")
			_ = report.Emit(env.out, *jsonMode)
			return nil
		case securitydomain.LifecycleTerminated:
			report.Fail("lock",
				"card is TERMINATED — irrecoverable, lock has no effect")
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("sd lock: card is TERMINATED")
		}
	} else {
		report.Skip("read pre-lock state",
			fmt.Sprintf("%v (proceeding without pre-check)", preErr))
	}

	if !*confirm {
		report.Skip("lock",
			"dry-run; pass --confirm-write to actually transition the ISD "+
				"to CARD_LOCKED. Lock is reversible via 'sd unlock' from a "+
				"key-holder. PIV applet state is NOT affected.")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	// Destructive path. Open SCP03 against the SD, send SET STATUS,
	// close before the post-check.
	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd lock: open SCP03: %w", err)
	}
	if err := sd.SetISDLifecycle(ctx, securitydomain.LifecycleCardLocked); err != nil {
		sd.Close()
		data.LastSW = extractLifecycleSW(err)
		report.Fail("lock", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd lock: SET STATUS: %w", err)
	}
	sd.Close()
	data.Locked = true
	report.Pass("lock",
		"ISD transitioned to CARD_LOCKED via SET STATUS (P1=0x80 P2=0x7F)")

	// Post-flight lifecycle read for confirmation. Same best-effort
	// posture as the pre-check — if it fails, the lock itself
	// already succeeded; we just won't have a confirmation line.
	stateAfter, postErr := readISDLifecycle(ctx, t)
	if postErr == nil {
		data.LifecycleAfter = stateAfter.String()
		report.Pass("read post-lock state", stateAfter.String())
	} else {
		report.Skip("read post-lock state",
			fmt.Sprintf("%v (lock SUCCESS, post-check unavailable)", postErr))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd lock reported failures")
	}
	return nil
}
