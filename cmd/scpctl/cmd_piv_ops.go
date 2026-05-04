package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/piv/session"
	"github.com/PeculiarVentures/scp/transport"
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

// resolveMgmtKey turns the (possibly empty) operator-supplied
// management-key flags into a piv.ManagementKey, deferring the
// algorithm choice to the session's active profile when the flag
// was left at its zero value.
//
// The fix here is to never default to AES-192 before knowing what
// card we're talking to. AES-192 is the YubiKey 5.4.2+ factory
// default; YubiKey pre-5.4.2 ships 3DES, and Standard PIV cards
// follow SP 800-78-4 which historically meant 3DES (with AES added
// in SP 800-78-5 but no spec-mandated default). Defaulting to
// AES-192 unconditionally would silently fail mutual auth on the
// other classes of card.
//
// Callers must call this with a constructed session so the profile
// is available. keyHex empty means "use the well-known factory
// default for the active profile's default algorithm". algoStr
// empty means "use the active profile's default algorithm". Both
// empty means "factory key, factory algorithm, whatever the profile
// says that is".
func resolveMgmtKey(sess sessionForMgmt, keyHex, algoStr string) (piv.ManagementKey, error) {
	caps := sess.Profile().Capabilities()

	// Algorithm: empty means "profile default".
	var algo piv.ManagementKeyAlgorithm
	if algoStr == "" {
		algo = caps.DefaultMgmtKeyAlg
	} else {
		var err error
		algo, err = piv.ParseManagementKeyAlgorithm(algoStr)
		if err != nil {
			return piv.ManagementKey{}, err
		}
	}

	// Key: empty means "factory default for the algorithm".
	if keyHex == "" {
		keyHex = "default"
	}

	mk, err := piv.ParseManagementKey(keyHex, algo.String())
	if err != nil {
		// piv.ParseManagementKey accepts the literal "default" only
		// when the algorithm is one whose key length matches the
		// 24-byte well-known value (3DES or AES-192). Surface a
		// clearer error for AES-128/AES-256 + "default" so the
		// operator knows to supply the actual key bytes.
		return piv.ManagementKey{}, fmt.Errorf("management key: %w", err)
	}
	return mk, nil
}

// sessionForMgmt is the minimal session interface resolveMgmtKey
// needs, so tests can pass a stub without standing up a real
// session.
type sessionForMgmt interface {
	Profile() profile.Profile
}

// scp11bChannelFlags is the cluster of flags every destructive or
// credential-bearing scpctl piv command exposes. The mode for the
// session is chosen by --scp11b (secure channel) versus
// --raw-local-ok (explicit raw-mode acknowledgement). Exactly one
// must be set; the absence of both is a usage error.
//
// Raw mode is the right choice for local-USB administration where
// the host running scpctl is in the operator's trust boundary.
// SCP11b is the right choice for APDU relays, browser-mediated
// sessions, remote provisioning, or any host path the operator
// does not control end to end. See docs/piv.md for the threat-
// model split.
type scp11bChannelFlags struct {
	scp11b     *bool
	rawLocalOK *bool
	trust      *trustFlags
}

// registerSCP11bChannelFlags adds --scp11b plus the shared trust
// flags (--trust-roots, --lab-skip-scp11-trust) plus --raw-local-ok
// to fs. Returns a handle that openPIVSession reads.
//
// The --raw-local-ok flag is the explicit acknowledgement that
// running raw (no secure channel) is acceptable for the operator's
// trust boundary. Default behavior is fail-closed: a destructive or
// credential-bearing scpctl piv command without either --scp11b or
// --raw-local-ok rejects with a clear error explaining the choice.
//
// The asymmetry (require positive assertion of raw mode rather than
// requiring --scp11b) is deliberate: SCP11b is the right answer for
// any environment that is not the operator's own machine in front of
// their own card, and an operator who hasn't thought about which
// they're in should not get raw mode by accident. The smoke harness
// in scp-smoke piv-provision (the predecessor of this surface) used
// SCP11b unconditionally; this fail-closed-with-explicit-opt-out
// keeps the migration honest without forcing trust-roots setup on
// the local-USB case that was the entire reason raw mode exists in
// the new surface.
func registerSCP11bChannelFlags(fs *flag.FlagSet) *scp11bChannelFlags {
	return &scp11bChannelFlags{
		scp11b: fs.Bool("scp11b", false,
			"Run this destructive operation over an SCP11b-on-PIV secure channel "+
				"instead of raw APDUs. Required for any host path that is not in the "+
				"operator's trust boundary (APDU relay, remote provisioning, "+
				"browser-mediated sessions). See docs/piv.md."),
		rawLocalOK: fs.Bool("raw-local-ok", false,
			"Explicitly assert that raw APDUs are acceptable for this invocation "+
				"because the host is in the operator's trust boundary (typical "+
				"local-USB administration). Required when --scp11b is not set. "+
				"Mutually exclusive with --scp11b."),
		trust: registerTrustFlags(fs),
	}
}

// validate is the early-return channel-mode check. Every handler
// that uses registerSCP11bChannelFlags should call this immediately
// after fs.Parse, before any handler-specific I/O. The reason for
// the early call is ordering: an operator who passes incompatible
// channel-mode flags should see that error before any downstream
// flag-reading-from-disk (like --cert <path> or --in <path>) gets
// a chance to fail with a different error. openPIVSession does the
// same check defensively, but every handler should call validate
// up front so the error surface is predictable.
func (f *scp11bChannelFlags) validate() error {
	switch {
	case *f.scp11b && *f.rawLocalOK:
		return &usageError{msg: "--scp11b and --raw-local-ok are mutually exclusive; pick one"}
	case !*f.scp11b && !*f.rawLocalOK:
		return &usageError{msg: "this command requires either --scp11b (secure channel) or --raw-local-ok (explicit raw-mode acknowledgement for local-USB administration); see docs/piv.md for the threat-model split"}
	}
	return nil
}

// openPIVSession is the session-construction path every destructive
// or credential-bearing scpctl piv handler uses. The channel mode is
// chosen by the flag pair (--scp11b, --raw-local-ok); exactly one
// must be set. The fail-closed default (neither set is a usage
// error) is what closes the gap to the smoke harness this surface
// supersedes: scp-smoke piv-provision and scp-smoke piv-reset both
// ran SCP11b unconditionally, and an operator migrating to the
// scpctl piv surface should never silently get a downgrade to raw
// just because they did not type --scp11b.
//
// When --scp11b is set without a trust posture (no --trust-roots
// and no --lab-skip-scp11-trust), the report gets a SKIP entry
// (consistent with applyTrust for the smoke commands) and the
// function returns (nil, false, nil); the caller emits the report
// and returns without a transmit attempt.
//
// Returns (sess, true, nil) on success; the caller is responsible
// for sess.Close(). The bool is "proceed"; false plus nil err
// means a clean SKIP path.
func openPIVSession(
	ctx context.Context,
	t transportLike,
	flags *scp11bChannelFlags,
	report *Report,
) (*session.Session, bool, error) {
	switch {
	case *flags.scp11b && *flags.rawLocalOK:
		return nil, false, &usageError{msg: "--scp11b and --raw-local-ok are mutually exclusive; pick one"}
	case !*flags.scp11b && !*flags.rawLocalOK:
		return nil, false, &usageError{msg: "this command requires either --scp11b (secure channel) or --raw-local-ok (explicit raw-mode acknowledgement for local-USB administration); see docs/piv.md for the threat-model split"}
	}

	if *flags.rawLocalOK {
		report.Pass("channel mode", "raw (operator asserted local-USB trust)")
		sess, err := session.New(ctx, t, session.Options{})
		if err != nil {
			return nil, false, err
		}
		return sess, true, nil
	}

	policy, insecureSkip, proceed, err := flags.trust.applyToPIVTrust(report)
	if err != nil {
		return nil, false, err
	}
	if !proceed {
		return nil, false, nil
	}
	sess, err := session.OpenSCP11bPIV(ctx, t, session.SCP11bPIVOptions{
		CardTrustPolicy:                policy,
		InsecureSkipCardAuthentication: insecureSkip,
	})
	if err != nil {
		return nil, false, fmt.Errorf("scp11b open: %w", err)
	}
	report.Pass("channel mode", "scp11b-on-piv")
	return sess, true, nil
}

// transportLike is the minimal Transport interface session.New and
// session.OpenSCP11bPIV both accept. Defined locally so the helper
// signature does not pull a transport import into every caller.
type transportLike = transport.Transport

// cmdPIVKeyGenerate runs GENERATE KEY against a slot. Requires
// --confirm-write because generating a key destroys whatever was in
// the slot.
//
// CLI binding note: the session-level helper caches the most-recent
// generated public key for an in-process cert-put binding check,
// but scpctl's key generate and cert put are separate process
// invocations and therefore separate sessions, so the cache is not
// reachable across them. Pass --out to capture the public key, then
// pass --expected-pubkey to 'scpctl piv cert put' for the same slot
// to enforce binding when installing the matching certificate. The
// in-session cache exists for downstream library callers (a single
// process driving both steps) and does not affect this CLI.
func cmdPIVKeyGenerate(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv key generate", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	slotStr := fs.String("slot", "9a", "PIV slot (9a, 9c, 9d, 9e, 82..95, f9).")
	algoStr := fs.String("alg", "eccp256", "Algorithm: rsa2048, eccp256, eccp384, ed25519, x25519.")
	pinPolicyStr := fs.String("pin-policy", "default", "PIN policy (YubiKey extension): default, never, once, always, match.")
	touchPolicyStr := fs.String("touch-policy", "default", "Touch policy (YubiKey extension): default, never, always, cached.")
	mgmtKeyFlag := registerSecretFlags(fs, "mgmt-key", "default", `Management key (hex or "default").`)
	mgmtAlgo := fs.String("mgmt-alg", "", "Management-key algorithm (3des/aes128/aes192/aes256). Empty = profile default.")
	pinFlag := registerSecretFlags(fs, "pin", "", "Application PIN (required because GENERATE KEY is PIN-gated by some policies).")
	out := fs.String("out", "", "Path to write the generated public key in PEM (SubjectPublicKeyInfo).")
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
	mgmtKey, err := mgmtKeyFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	pin, err := pinFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv key generate", Reader: *reader}
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

	if pin != "" {
		if err := sess.VerifyPIN(ctx, []byte(pin)); err != nil {
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

func cmdPIVObjectGet(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv object get", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	idHex := fs.String("id", "", "Object ID in hex (e.g. 5fc105 for slot 9a cert).")
	out := fs.String("out", "", "Path to write the raw object bytes.")
	strict := fs.Bool("strict", false,
		"Require the card response to be well-formed BER-TLV with a 0x53 envelope. Off by default for vendor-quirk tolerance; on for compliance, audit, and provisioning paths where a malformed response should fail loudly.")
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

	var data []byte
	if *strict {
		data, err = sess.ReadObjectStrict(ctx, id)
	} else {
		data, err = sess.ReadObject(ctx, id)
	}
	if err != nil {
		report.Fail("read object", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	mode := "lenient"
	if *strict {
		mode = "strict"
	}
	report.Pass("read object", fmt.Sprintf("id=%s len=%d (%s)", id, len(data), mode))

	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			report.Fail("write object", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("write object", *out)
		return report.Emit(env.out, *jsonMode)
	}
	if *jsonMode {
		return report.Emit(env.out, *jsonMode)
	}
	// Default text mode with no --out: hex goes to stdout, report
	// goes to stderr. This makes 'scpctl piv object get > obj.hex'
	// produce a clean hex line rather than mixing report text into
	// the data output.
	fmt.Fprintln(env.out, hex.EncodeToString(data))
	return report.Emit(env.errOut, false)
}

// cmdPIVObjectPut writes a raw PIV data object by ID. This is the
// generic escape hatch; common objects have dedicated commands that
// build the right envelope for their semantics:
//
//   - Slot certificates: use 'scpctl piv cert put' (builds the
//     0x70/0x71/0xFE certificate envelope correctly and supports
//     binding checks).
//
//   - YubiKey-vendor objects (CHUID, CCC, etc.) currently have no
//     dedicated command; this is the way to write them, and the
//     caller is responsible for the inner payload shape. The
//     session wraps the supplied bytes in the 0x53 envelope, so
//     the file passed via --in is the raw payload, not a
//     pre-wrapped object.
//
// Mistakes here can produce a card whose CHUID, CCC, or security
// object is structurally invalid, which then cascades into PIV
// authentication failures elsewhere. Use with care, and prefer the
// dedicated commands for slot certificates.
func cmdPIVObjectPut(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv object put", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	idHex := fs.String("id", "", "Object ID in hex (e.g. 5fc102 for CHUID).")
	in := fs.String("in", "", "Path to file containing the raw object bytes (the session wraps in 0x53 for the SP 800-73-4 envelope).")
	mgmtKeyFlag := registerSecretFlags(fs, "mgmt-key", "default", "Management key (hex or 'default').")
	mgmtAlgo := fs.String("mgmt-alg", "", "Management-key algorithm. Empty = profile default.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive write. Note: this command writes raw PIV data objects. For slot certificates use 'scpctl piv cert put' instead, which builds the correct certificate envelope and supports binding checks.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
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
	mgmtKey, err := mgmtKeyFlag.resolve(env.stdin)
	if err != nil {
		return err
	}
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv object put", Reader: *reader}
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

// cmdPIVGroupReset resets the PIV applet to factory state. YubiKey-only;
// refused under StandardPIV. The card-side precondition (PIN and PUK
// both blocked) is the operator's responsibility because forcing
// blocks here would be an opinionated choice that doesn't belong in
// a session method. The smoke piv-reset subcommand has the
// block-then-reset flow for hardware harnesses.
//
// Reset is the most-destructive PIV operation: every slot keypair
// is erased, every certificate is dropped, PIN/PUK/management-key
// all return to factory defaults. A wrong-card reset is a card
// that has to be re-enrolled, with all of the trust-bootstrap cost
// that implies. So this command takes a second gate beyond
// --confirm-write: --confirm-reset-piv. The two-flag pattern
// distinguishes 'I am about to overwrite a slot' from 'I am about
// to wipe the whole applet' so an operator who pastes a stale
// command line cannot accidentally turn a slot rotation into a
// full reset.
func cmdPIVGroupReset(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv reset", env)
	reader := fs.String("reader", "", "PC/SC reader name.")
	confirm := fs.Bool("confirm-write", false, "Required: confirm a destructive operation.")
	confirmReset := fs.Bool("confirm-reset-piv", false,
		"Required (in addition to --confirm-write): confirm the operator understands this is a full PIV applet reset, not a single-slot operation. Erases all 24 slot keys, all certificates, and resets PIN/PUK/management-key to factory defaults.")
	chFlags := registerSCP11bChannelFlags(fs)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if err := chFlags.validate(); err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("piv reset erases all slots, certificates, and credentials; pass --confirm-write to proceed")
	}
	if !*confirmReset {
		return fmt.Errorf("piv reset additionally requires --confirm-reset-piv to distinguish a full applet wipe from a single-slot operation; pass both flags to proceed")
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv reset", Reader: *reader}
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
