package main

// `scpctl piv cert` verbs — get, put, delete.
//
//   get      Read the X.509 certificate stored in a PIV slot's
//            cert object and write it to disk (PEM by default,
//            --der for raw).
//   put      Write a PEM-loaded certificate to a slot's cert
//            object. No on-card signing involved — pure data
//            object write.
//   delete   Remove the certificate from a slot's cert object
//            (clears the data object). The associated key, if
//            any, is unaffected.
//
// All three verbs target the cert data objects (5FC1xx tag
// family) under PIV INS GET DATA / PUT DATA. Auth requirements
// vary by verb: get is read-only, put and delete require
// management-key authentication.
//
// Split from cmd_piv_ops.go because the cert verbs share a
// common slot+--cert flag surface, common error shapes, and
// common readCertPEM / writeFileAtomic helpers. Keeping the
// three together makes the cert-flow contract auditable in
// isolation.
//
// The dispatcher in cmd_piv_ops.go routes here on
// args[0] == "get" / "put" / "delete" under "piv cert".

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/session"
)

func cmdPIVCertGet(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv cert get", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot.")
	out := fs.String("out", "", "Path to write the certificate (PEM). Default stdout.")
	jsonMode := fs.Bool("json", false, "Emit JSON output (suppresses stdout cert dump).")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	slot, err := piv.ParseSlot(*slotStr)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv cert get", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	cert, err := sess.GetCertificate(ctx, slot)
	if err != nil {
		report.Fail("get cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	if cert == nil {
		report.Pass("get cert", "no certificate installed in slot")
		return report.Emit(env.out, *jsonMode)
	}
	report.Pass("get cert", fmt.Sprintf("subject=%s", cert.Subject))

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if *out != "" {
		if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
			report.Fail("write cert", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("write cert", *out)
		return report.Emit(env.out, *jsonMode)
	}
	if *jsonMode {
		// JSON mode: report carries the cert subject and other
		// metadata; stdout stays JSON-clean. The PEM is not in the
		// JSON payload because callers asking for JSON typically want
		// machine-parseable structure, not bytes-as-text. Use --out
		// to capture the PEM in any mode.
		return report.Emit(env.out, *jsonMode)
	}
	// Default text mode with no --out: PEM goes to stdout, report
	// goes to stderr. This makes 'scpctl piv cert get > cert.pem'
	// produce a clean PEM file rather than mixing report text into
	// the certificate output.
	if _, err := env.out.Write(pemBytes); err != nil {
		return fmt.Errorf("write PEM to stdout: %w", err)
	}
	return report.Emit(env.errOut, false)
}

func cmdPIVCertPut(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv cert put", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot.")
	certPath := fs.String("cert", "", "Path to PEM-encoded certificate to install.")
	mgmtKeyFlag := registerSecretFlags(fs, "mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "", "Management-key algorithm. Empty = profile default.")
	expectedPubKey := fs.String("expected-pubkey", "",
		"Path to the expected public key (PEM) for the slot. Required when --no-pubkey-binding is not set, because this CLI does not generate-then-install in one invocation.")
	noPubKeyBinding := fs.Bool("no-pubkey-binding", false,
		"Skip the cert-to-public-key binding check. Off by default; the binding check is part of the safe-by-default provisioning posture and skipping it lets a malformed cert install over a slot whose private key it does not match. Use only when you have an out-of-band guarantee.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive write to the slot.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("piv cert put is destructive; pass --confirm-write to proceed")
	}
	if *certPath == "" {
		return &usageError{msg: "--cert is required"}
	}
	if !*noPubKeyBinding && *expectedPubKey == "" {
		return &usageError{msg: "binding check is on by default. Supply --expected-pubkey <path> with the public key for this slot, or pass --no-pubkey-binding to skip the check (not recommended for production)."}
	}
	slot, err := piv.ParseSlot(*slotStr)
	if err != nil {
		return err
	}
	cert, err := readCertPEM(*certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	var expected interface{}
	if *expectedPubKey != "" {
		expected, err = readPublicKeyPEM(*expectedPubKey)
		if err != nil {
			return fmt.Errorf("read expected public key: %w", err)
		}
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

	report := &Report{Subcommand: "piv cert put", Reader: *reader}
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
	report.Pass("mgmt auth", "authenticated")

	if err := sess.PutCertificate(ctx, slot, cert, session.PutCertificateOptions{
		RequirePubKeyBinding: !*noPubKeyBinding,
		ExpectedPublicKey:    expected,
	}); err != nil {
		report.Fail("put cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	if *noPubKeyBinding {
		report.Pass("put cert", fmt.Sprintf("slot=%s subject=%s (binding check skipped)", slot, cert.Subject))
	} else {
		report.Pass("put cert", fmt.Sprintf("slot=%s subject=%s (binding verified)", slot, cert.Subject))
	}
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVCertDelete(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv cert delete", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "", "PIV slot to clear.")
	mgmtKeyFlag := registerSecretFlags(fs, "mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "", "Management-key algorithm. Empty = profile default.")
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
		return fmt.Errorf("piv cert delete is destructive; pass --confirm-write to proceed")
	}
	if *slotStr == "" {
		return &usageError{msg: "--slot is required"}
	}
	slot, err := piv.ParseSlot(*slotStr)
	if err != nil {
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

	report := &Report{Subcommand: "piv cert delete", Reader: *reader}
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
	report.Pass("mgmt auth", "authenticated")

	if err := sess.DeleteCertificate(ctx, slot); err != nil {
		report.Fail("delete cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("delete cert", fmt.Sprintf("slot=%s cleared", slot))
	return report.Emit(env.out, *jsonMode)
}
