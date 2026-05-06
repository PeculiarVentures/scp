package main

// `scpctl piv key` verbs — generate and attest.
//
//   generate   On-card asymmetric key generation in a PIV slot
//              (9A/9C/9D/9E/82-95). RSA 1024/2048 or EC P-256/P-384.
//              The card never reveals the private key; the public
//              key is returned and written to disk.
//   attest     YubiKey-only. Generates an attestation cert chain
//              proving the key in a slot was generated on this
//              device. Attestation root + intermediate stay on the
//              card; we read the chain and write it out.
//
// Split from cmd_piv_ops.go because the key verbs are
// algorithmically distinct from cert/object/mgmt: they don't
// move data into or out of the card's PIV data objects, they
// drive the card's key-generation engine. The flag surface
// (--algo, --slot, --pin, --touch-policy / --pin-policy on
// generate; --slot, --out-chain on attest) is also shared
// between just these two verbs.
//
// The dispatcher in cmd_piv_ops.go routes here on
// args[0] == "generate" / "attest" under "piv key".

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/session"
)

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

