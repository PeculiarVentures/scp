package main

// `scpctl piv object` verbs — get, put.
//
//   get   Read a raw PIV data object by 3-byte object ID and
//         write the bytes to disk. Used for non-cert objects:
//         CHUID, CCC, key history, BITGT, etc.
//   put   Write raw bytes to a PIV data object by 3-byte
//         object ID. Used for the same non-cert objects, or
//         for vendor extensions that don't fit the cert-shaped
//         5FC1xx range.
//
// Object verbs are the lower-level cousin of cert verbs: cert
// verbs target a specific tag family (5FC1xx) and validate
// X.509 shape; object verbs take any tag and don't validate
// content. The two are kept distinct so an operator
// accidentally putting non-cert bytes into a cert slot gets a
// usage error rather than installing garbage.
//
// Split from cmd_piv_ops.go because the object verbs share a
// flag surface (--object-id as hex bytes, --in/--out as raw
// file paths) distinct from cert and key flows, and use
// hex-encoding helpers (encoding/hex, bytes.TrimSpace) that
// don't appear in other piv verb groups.
//
// The dispatcher in cmd_piv_ops.go routes here on
// args[0] == "get" / "put" under "piv object".

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/session"
)

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

