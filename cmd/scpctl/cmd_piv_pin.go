package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
)

// cmdPIVPin dispatches `scpctl piv pin <verb>` where <verb> is one
// of verify, change, unblock. The change-PUK flow is reachable here
// as `pin unblock` (PUK plus new PIN); a separate `puk change` lives
// at the same depth for symmetry with the spec.
//
// All three are PIN-gated by the card's own counter rather than by
// the session, because they are the operations that manipulate the
// counter. piv.IsWrongPIN / piv.RetriesRemaining surface the count
// from any 63xx response so callers do not need to inspect raw SWs.
func cmdPIVPin(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv pin <verify|change|unblock> [flags]"}
	}
	switch args[0] {
	case "verify":
		return cmdPIVPinVerify(ctx, env, args[1:])
	case "change":
		return cmdPIVPinChange(ctx, env, args[1:])
	case "unblock":
		return cmdPIVPinUnblock(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv pin <verify|change|unblock>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown pin subcommand %q", args[0])}
}

// cmdPIVPuk dispatches `scpctl piv puk <verb>`. Today only 'change'
// is meaningful at this level; PUK unblock-of-PIN goes through
// `pin unblock` because the operation is conceptually about the PIN.
func cmdPIVPuk(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv puk <change> [flags]"}
	}
	switch args[0] {
	case "change":
		return cmdPIVPukChange(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv puk <change>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown puk subcommand %q", args[0])}
}

func cmdPIVPinVerify(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv pin verify", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	pinFlag := registerSecretFlags(fs, "pin", "", "Application PIN to verify.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	pin, err := pinFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	if pin == "" {
		return &usageError{msg: "--pin (or --pin-stdin / --pin-file) is required"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv pin verify", Reader: *reader}
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

	if err := sess.VerifyPIN(ctx, []byte(pin)); err != nil {
		// Decode the retry count when it's available and surface it
		// without leaking the wrong-PIN state ambiguously.
		if retries, ok := piv.RetriesRemaining(err); ok {
			report.Fail("verify pin", fmt.Sprintf("wrong PIN (%d retries left)", retries))
		} else if piv.IsPINBlocked(err) {
			report.Fail("verify pin", "PIN is blocked; use 'pin unblock' with the PUK")
		} else {
			report.Fail("verify pin", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("verify pin", "verified")
	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	return nil
}

func cmdPIVPinChange(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv pin change", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	oldFlag := registerSecretFlags(fs, "old-pin", "", "Current application PIN.")
	newFlag := registerSecretFlags(fs, "new-pin", "", "New application PIN.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	oldPIN, err := oldFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	newPIN, err := newFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	if oldPIN == "" || newPIN == "" {
		return &usageError{msg: "old PIN and new PIN are both required (--old-pin/--old-pin-stdin/--old-pin-file and --new-pin/--new-pin-stdin/--new-pin-file)"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv pin change", Reader: *reader}
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

	if err := sess.ChangePIN(ctx, []byte(oldPIN), []byte(newPIN)); err != nil {
		if retries, ok := piv.RetriesRemaining(err); ok {
			report.Fail("change pin", fmt.Sprintf("wrong old PIN (%d retries left)", retries))
		} else if piv.IsPINBlocked(err) {
			report.Fail("change pin", "PIN is blocked; use 'pin unblock' with the PUK")
		} else {
			report.Fail("change pin", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("change pin", "changed")
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVPinUnblock(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv pin unblock", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	pukFlag := registerSecretFlags(fs, "puk", "", "PUK (PIN unblocking key).")
	newPINFlag := registerSecretFlags(fs, "new-pin", "", "New application PIN to set after unblock.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	puk, err := pukFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	newPIN, err := newPINFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	if puk == "" || newPIN == "" {
		return &usageError{msg: "PUK and new PIN are both required (--puk/--puk-stdin/--puk-file and --new-pin/--new-pin-stdin/--new-pin-file)"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv pin unblock", Reader: *reader}
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

	if err := sess.UnblockPIN(ctx, []byte(puk), []byte(newPIN)); err != nil {
		if retries, ok := piv.RetriesRemaining(err); ok {
			report.Fail("unblock pin", fmt.Sprintf("wrong PUK (%d retries left)", retries))
		} else if errors.Is(err, piv.ErrNotAuthenticated) {
			report.Fail("unblock pin", err.Error())
		} else {
			report.Fail("unblock pin", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("unblock pin", "unblocked and new PIN set")
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVPukChange(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv puk change", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	oldFlag := registerSecretFlags(fs, "old-puk", "", "Current PUK.")
	newFlag := registerSecretFlags(fs, "new-puk", "", "New PUK.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	oldPUK, err := oldFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	newPUK, err := newFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	if oldPUK == "" || newPUK == "" {
		return &usageError{msg: "old PUK and new PUK are both required (--old-puk/--old-puk-stdin/--old-puk-file and --new-puk/--new-puk-stdin/--new-puk-file)"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv puk change", Reader: *reader}
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

	if err := sess.ChangePUK(ctx, []byte(oldPUK), []byte(newPUK)); err != nil {
		if retries, ok := piv.RetriesRemaining(err); ok {
			report.Fail("change puk", fmt.Sprintf("wrong old PUK (%d retries left)", retries))
		} else {
			report.Fail("change puk", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("change puk", "changed")
	return report.Emit(env.out, *jsonMode)
}
