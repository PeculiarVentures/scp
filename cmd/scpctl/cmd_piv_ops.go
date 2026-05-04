package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/session"
)

// cmdPIVKey dispatches `scpctl piv key <verb>`.
func cmdPIVKey(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv key <generate|attest> [flags]"}
	}
	switch args[0] {
	case "generate":
		return cmdPIVKeyGenerate(ctx, env, args[1:])
	case "attest":
		return cmdPIVKeyAttest(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv key <generate|attest>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown key subcommand %q", args[0])}
}

// cmdPIVCert dispatches `scpctl piv cert <verb>`.
func cmdPIVCert(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv cert <get|put|delete> [flags]"}
	}
	switch args[0] {
	case "get":
		return cmdPIVCertGet(ctx, env, args[1:])
	case "put":
		return cmdPIVCertPut(ctx, env, args[1:])
	case "delete":
		return cmdPIVCertDelete(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv cert <get|put|delete>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown cert subcommand %q", args[0])}
}

// cmdPIVObject dispatches `scpctl piv object <verb>`.
func cmdPIVObject(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv object <get|put> [flags]"}
	}
	switch args[0] {
	case "get":
		return cmdPIVObjectGet(ctx, env, args[1:])
	case "put":
		return cmdPIVObjectPut(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv object <get|put>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown object subcommand %q", args[0])}
}

// cmdPIVMgmt dispatches `scpctl piv mgmt <verb>`.
func cmdPIVMgmt(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv mgmt <auth|change-key> [flags]"}
	}
	switch args[0] {
	case "auth":
		return cmdPIVMgmtAuth(ctx, env, args[1:])
	case "change-key":
		return cmdPIVMgmtChangeKey(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv mgmt <auth|change-key>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown mgmt subcommand %q", args[0])}
}

// authMgmtFromFlag is the shared management-key parser used by every
// subcommand that needs management auth. It accepts the literal
// "default" (the well-known 24-byte factory value) or a hex string.
// The algorithm string is parsed by piv.ParseManagementKeyAlgorithm.
func authMgmtFromFlag(keyHex, algoStr string) (piv.ManagementKey, error) {
	if keyHex == "" {
		keyHex = "default"
	}
	if algoStr == "" {
		algoStr = "aes192"
	}
	if _, err := piv.ParseManagementKeyAlgorithm(algoStr); err != nil {
		return piv.ManagementKey{}, err
	}
	return piv.ParseManagementKey(keyHex, algoStr)
}

// cmdPIVKeyGenerate runs GENERATE KEY against a slot. Requires
// --confirm-write because generating a key destroys whatever was in
// the slot. The session caches the public key so a subsequent
// 'cert put' on the same session can use it for binding; this CLI
// flow is one-shot, so the key is also written to the path in --out.
func cmdPIVKeyGenerate(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv key generate", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot (9a, 9c, 9d, 9e, 82..95, f9).")
	algoStr := fs.String("alg", "eccp256", "Algorithm: rsa2048, eccp256, eccp384, ed25519, x25519.")
	pinPolicyStr := fs.String("pin-policy", "default", "PIN policy (YubiKey extension): default, never, once, always, match.")
	touchPolicyStr := fs.String("touch-policy", "default", "Touch policy (YubiKey extension): default, never, always, cached.")
	mgmtKey := fs.String("mgmt-key", "default", `Management key (hex or "default").`)
	mgmtAlgo := fs.String("mgmt-alg", "aes192", "Management-key algorithm: 3des, aes128, aes192, aes256.")
	pin := fs.String("pin", "", "Application PIN (required because GENERATE KEY is PIN-gated by some policies).")
	out := fs.String("out", "", "Path to write the generated public key in PEM (SubjectPublicKeyInfo).")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive write to the slot.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if !*confirm {
		return fmt.Errorf("piv key generate is destructive (overwrites slot %s); pass --confirm-write to proceed", *slotStr)
	}
	slot, err := piv.ParseSlot(*slotStr)
	if err != nil {
		return err
	}
	algo, err := piv.ParseAlgorithm(*algoStr)
	if err != nil {
		return err
	}
	pinPolicy, err := piv.ParsePINPolicy(*pinPolicyStr)
	if err != nil {
		return err
	}
	touchPolicy, err := piv.ParseTouchPolicy(*touchPolicyStr)
	if err != nil {
		return err
	}
	mk, err := authMgmtFromFlag(*mgmtKey, *mgmtAlgo)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv key generate", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		report.Fail("mgmt auth", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("mgmt auth", "authenticated")

	if *pin != "" {
		if err := sess.VerifyPIN(ctx, []byte(*pin)); err != nil {
			report.Fail("verify pin", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("verify pin", "verified")
	}

	pub, err := sess.GenerateKey(ctx, slot, session.GenerateKeyOptions{
		Algorithm:   algo,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		report.Fail("generate key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("generate key", fmt.Sprintf("slot=%s alg=%s", slot, algo))

	if *out != "" {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			report.Fail("marshal public key", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
			report.Fail("write public key", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("write public key", *out)
	}

	return report.Emit(env.out, *jsonMode)
}

func cmdPIVKeyAttest(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv key attest", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot to attest.")
	out := fs.String("out", "", "Path to write the attestation certificate (PEM).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
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

	report := &Report{Subcommand: "piv key attest", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	cert, err := sess.Attest(ctx, slot)
	if err != nil {
		report.Fail("attest", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("attest", fmt.Sprintf("slot=%s subject=%s", slot, cert.Subject))

	if *out != "" {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
			report.Fail("write attestation", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("write attestation", *out)
	}
	return report.Emit(env.out, *jsonMode)
}

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
	} else if !*jsonMode {
		// Dump to stdout after the report so a piped consumer sees
		// the report on stderr and the PEM on stdout. Report is going
		// to env.out today; stash the PEM in the report data instead.
		_, _ = env.out.Write(pemBytes)
	}
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVCertPut(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv cert put", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot.")
	certPath := fs.String("cert", "", "Path to PEM-encoded certificate to install.")
	mgmtKey := fs.String("mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "aes192", "Management-key algorithm.")
	requireBinding := fs.Bool("require-pubkey-binding", false,
		"Refuse if the cert's public key does not match the slot's most recently generated key (host-side check).")
	expectedPubKey := fs.String("expected-pubkey", "",
		"Optional path to the expected public key (PEM) for binding check; if absent and require-pubkey-binding is set, the slot must have a recent in-session generate.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive write to the slot.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if !*confirm {
		return fmt.Errorf("piv cert put is destructive; pass --confirm-write to proceed")
	}
	if *certPath == "" {
		return &usageError{msg: "--cert is required"}
	}
	slot, err := piv.ParseSlot(*slotStr)
	if err != nil {
		return err
	}
	mk, err := authMgmtFromFlag(*mgmtKey, *mgmtAlgo)
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

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv cert put", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		report.Fail("mgmt auth", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("mgmt auth", "authenticated")

	if err := sess.PutCertificate(ctx, slot, cert, session.PutCertificateOptions{
		RequirePubKeyBinding: *requireBinding,
		ExpectedPublicKey:    expected,
	}); err != nil {
		report.Fail("put cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("put cert", fmt.Sprintf("slot=%s subject=%s", slot, cert.Subject))
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVCertDelete(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv cert delete", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "", "PIV slot to clear.")
	mgmtKey := fs.String("mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "aes192", "Management-key algorithm.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive operation.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
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
	mk, err := authMgmtFromFlag(*mgmtKey, *mgmtAlgo)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv cert delete", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

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

func cmdPIVObjectGet(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv object get", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	idHex := fs.String("id", "", "Object ID in hex (e.g. 5fc105 for slot 9a cert).")
	out := fs.String("out", "", "Path to write the raw object bytes.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *idHex == "" {
		return &usageError{msg: "--id is required"}
	}
	id, err := piv.ParseObjectID(*idHex)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv object get", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	data, err := sess.ReadObject(ctx, id)
	if err != nil {
		report.Fail("read object", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("read object", fmt.Sprintf("id=%s len=%d", id, len(data)))

	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			report.Fail("write object", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("write object", *out)
	} else if !*jsonMode {
		fmt.Fprintln(env.out, hex.EncodeToString(data))
	}
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVObjectPut(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv object put", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	idHex := fs.String("id", "", "Object ID in hex.")
	in := fs.String("in", "", "Path to file containing the object bytes (raw, not 0x53-wrapped; the session wraps).")
	mgmtKey := fs.String("mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "aes192", "Management-key algorithm.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive write.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if !*confirm {
		return fmt.Errorf("piv object put is destructive; pass --confirm-write to proceed")
	}
	if *idHex == "" || *in == "" {
		return &usageError{msg: "--id and --in are required"}
	}
	id, err := piv.ParseObjectID(*idHex)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	mk, err := authMgmtFromFlag(*mgmtKey, *mgmtAlgo)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv object put", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		report.Fail("mgmt auth", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("mgmt auth", "authenticated")

	if err := sess.WriteObject(ctx, id, data); err != nil {
		report.Fail("write object", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("write object", fmt.Sprintf("id=%s len=%d", id, len(data)))
	return report.Emit(env.out, *jsonMode)
}

func cmdPIVMgmtAuth(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv mgmt auth", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	mgmtKey := fs.String("mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "aes192", "Management-key algorithm.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	mk, err := authMgmtFromFlag(*mgmtKey, *mgmtAlgo)
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv mgmt auth", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

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
	oldKey := fs.String("old-mgmt-key", "default", "Current management key (hex or 'default').")
	oldAlgo := fs.String("old-mgmt-alg", "aes192", "Current management-key algorithm.")
	newKey := fs.String("new-mgmt-key", "", "New management key (hex). Required.")
	newAlgo := fs.String("new-mgmt-alg", "aes192", "New management-key algorithm.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive operation.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if !*confirm {
		return fmt.Errorf("piv mgmt change-key is destructive; pass --confirm-write to proceed")
	}
	if *newKey == "" {
		return &usageError{msg: "--new-mgmt-key is required"}
	}
	oldMK, err := authMgmtFromFlag(*oldKey, *oldAlgo)
	if err != nil {
		return fmt.Errorf("old key: %w", err)
	}
	newMK, err := authMgmtFromFlag(*newKey, *newAlgo)
	if err != nil {
		return fmt.Errorf("new key: %w", err)
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv mgmt change-key", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

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

// cmdPIVGroupReset resets the PIV applet to factory state. YubiKey-only;
// refused under StandardPIV. The card-side precondition (PIN and PUK
// both blocked) is the operator's responsibility because forcing
// blocks here would be an opinionated choice that doesn't belong in
// a session method. The smoke piv-reset subcommand has the
// block-then-reset flow for hardware harnesses.
func cmdPIVGroupReset(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv reset", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive operation.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if !*confirm {
		return fmt.Errorf("piv reset erases all slots, certificates, and credentials; pass --confirm-write to proceed")
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv reset", Reader: *reader}
	sess, err := session.New(ctx, t, session.Options{})
	if err != nil {
		report.Fail("open session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	if err := sess.Reset(ctx, session.ResetOptions{}); err != nil {
		report.Fail("reset", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("reset", "PIV applet reset to factory state")
	return report.Emit(env.out, *jsonMode)
}

// readCertPEM reads a PEM-encoded certificate from disk and parses
// the first CERTIFICATE block. Helper shared by cert put and similar
// flows that take a cert on the command line.
func readCertPEM(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// readPublicKeyPEM reads a PEM-encoded SubjectPublicKeyInfo from
// disk and returns the parsed public key (any algorithm).
func readPublicKeyPEM(path string) (interface{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
