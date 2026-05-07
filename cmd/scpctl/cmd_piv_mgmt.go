package main

// `scpctl piv mgmt` verbs — auth, change-key.
//
//   auth         Authenticate against the card's PIV
//                management key. Required before any
//                management-key-gated operation (cert put /
//                delete, object put, key generation in
//                protected slots).
//   change-key   Rotate the card's PIV management key. Takes
//                the current key for auth, the new key as a
//                hex argument, and writes the new key over
//                an authenticated channel.
//
// Split from cmd_piv_ops.go because the mgmt verbs operate
// on the card's auth state itself (not on data objects) and
// share a flag surface (--key, --algo, --new-key on
// change-key) that's distinct from data-object verbs.
//
// The dispatcher in cmd_piv_ops.go routes here on
// args[0] == "auth" / "change-key" under "piv mgmt".

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/piv/session"
)

func cmdPIVMgmtAuth(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv mgmt auth", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	mgmtKeyFlag := registerSecretFlags(fs, "mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "", "Management-key algorithm. Empty = profile default.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	mgmtKey, err := mgmtKeyFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv mgmt auth", Reader: *reader}
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

	mk, err := resolveMgmtKey(sess, mgmtKey, *mgmtAlgo)
	if err != nil {
		return err
	}

	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		report.Fail("mgmt auth", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("mgmt auth", fmt.Sprintf("authenticated with %s", mk.Algorithm))
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVMgmtChangeKey(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv mgmt change-key", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	oldKeyFlag := registerSecretFlags(fs, "old-mgmt-key", "default", "Current management key (hex or 'default').")
	oldAlgo := fs.String("old-mgmt-alg", "", "Current management-key algorithm. Empty = profile default.")
	newKeyFlag := registerSecretFlags(fs, "new-mgmt-key", "", "New management key (hex). Required.")
	newAlgo := fs.String("new-mgmt-alg", "", "New management-key algorithm. Empty = profile default.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive operation.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("piv mgmt change-key is destructive; pass --confirm-write to proceed")
	}
	oldKey, err := oldKeyFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	newKey, err := newKeyFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	if newKey == "" {
		return &usageError{msg: "new management key is required (--new-mgmt-key/--new-mgmt-key-stdin/--new-mgmt-key-file)"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv mgmt change-key", Reader: *reader}
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

	// Resolve both keys against the active profile so empty
	// --old-mgmt-alg / --new-mgmt-alg pick the right default for
	// the card class we actually probed.
	oldMK, err := resolveMgmtKey(sess, oldKey, *oldAlgo)
	if err != nil {
		return fmt.Errorf("old key: %w", err)
	}
	newMK, err := resolveMgmtKey(sess, newKey, *newAlgo)
	if err != nil {
		return fmt.Errorf("new key: %w", err)
	}

	if err := sess.AuthenticateManagementKey(ctx, oldMK); err != nil {
		report.Fail("mgmt auth", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("mgmt auth", "authenticated to old key")

	if err := sess.ChangeManagementKey(ctx, newMK, session.ChangeManagementKeyOptions{}); err != nil {
		report.Fail("change mgmt key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("change mgmt key", fmt.Sprintf("now %s", newMK.Algorithm))
	return report.Emit(env.out, *jsonMode)
}
