package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// sdKeysDeleteData is the JSON payload of `sd keys delete`.
//
// Mode is "single" or "all-at-kvn" so JSON consumers don't have to
// reverse-engineer intent from flag combinations. Channel records the
// wire mode used; for Phase 3 this is always "scp03" (SCP11a auth is
// Phase 2b/3b parallel).
type sdKeysDeleteData struct {
	Channel string `json:"channel"`
	Mode    string `json:"mode"` // "single" or "all-at-kvn"
	KIDHex  string `json:"kid_hex,omitempty"`
	KVNHex  string `json:"kvn_hex"`
}

// cmdSDKeysDelete removes one (single mode) or all (all-at-kvn mode)
// key references from the Security Domain. Composes
// Session.DeleteKey, which takes a KeyReference and a deleteLast
// flag indicating whether to allow removing the final key in a
// reference set.
//
// Flag-validation rules (host-side, before any APDU is sent):
//
//	--kid + --kvn (no --all)         single-ref deletion. Maps to
//	                                 DeleteKey({kid, kvn}, false).
//	--kvn + --all (no --kid)         all keys at this KVN. Maps to
//	                                 DeleteKey({0, kvn}, true).
//	--kid only / --kvn only / --kid + --all  USAGE ERROR.
//
// The asymmetry with the underlying library API is deliberate. The
// library accepts kid-only or kvn-only deletes (matching yubikit's
// permissive surface), but the CLI's job is to refuse ambiguous
// invocations: bare --kid leaves the KVN unspecified, bare --kvn
// without --all hides whether the operator means one ref or all
// refs at that version. The wire effect of a misfire here is
// destructive and not always recoverable; explicit signals only.
//
// Confirmation gate: --confirm-delete-key (NOT --confirm-write).
// Deletion is a recovery-meaningful action distinct from rotation;
// each blast-radius gets its own flag so a script that confirms one
// kind of write cannot accidentally trigger another.
//
// Dry-run by default: without --confirm-delete-key, the command
// validates inputs, reports the planned action and target ref(s),
// and exits 0 without opening SCP03 or transmitting DELETE KEY.
// Same dry-run pattern as sd lock / unlock / terminate.
//
// SCP03 KID rewriting: the library's DeleteKey rewrites SCP03 KIDs
// (0x01/0x02/0x03) to 0x00 internally because cards reject KID-
// bearing DELETE for SCP03. The CLI surfaces the operator's typed
// reference verbatim in the check name (kid=0x01 kvn=...); the
// rewrite is library-internal and doesn't bubble up.
func cmdSDKeysDelete(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys delete", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "",
		"Key ID to delete, hex byte (e.g. 11). Required with --kvn for "+
			"single-ref deletion; mutually exclusive with --all.")
	kvnStr := fs.String("kvn", "",
		"Key Version Number, hex byte (e.g. 01). Required.")
	all := fs.Bool("all", false,
		"Delete every key reference installed at the given --kvn. Requires "+
			"--kvn; mutually exclusive with --kid. The explicit signal that "+
			"broad deletion is intended.")
	confirm := fs.Bool("confirm-delete-key", false,
		"Confirm key-reference deletion. Distinct from --confirm-write so a "+
			"careless script that authorizes ordinary writes cannot trigger "+
			"deletion. Without this flag, sd keys delete runs in dry-run "+
			"mode (validates inputs, reports planned action, exits 0).")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	// Flag validation. Each branch maps to one library call shape;
	// every other combination is rejected here so the operator
	// cannot accidentally invoke a destructive op with ambiguous
	// arguments.
	if *kvnStr == "" {
		return &usageError{msg: "sd keys delete requires --kvn"}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}

	var (
		mode       string
		kid        byte
		ref        securitydomain.KeyReference
		deleteLast bool
		kidHex     string
	)
	switch {
	case *kidStr != "" && *all:
		return &usageError{msg: "sd keys delete: --all is mutually exclusive with --kid"}
	case *kidStr != "":
		kid, err = parseHexByte(*kidStr)
		if err != nil {
			return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
		}
		mode = "single"
		ref = securitydomain.NewKeyReference(kid, kvn)
		deleteLast = false
		kidHex = fmt.Sprintf("0x%02X", kid)
	case *all:
		mode = "all-at-kvn"
		ref = securitydomain.NewKeyReference(0, kvn)
		deleteLast = true
	default:
		return &usageError{msg: "sd keys delete: pass --kid for single-ref deletion or --all for KVN-wide deletion (bare --kvn is ambiguous)"}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	report := &Report{Subcommand: "sd keys delete", Reader: *reader}
	data := &sdKeysDeleteData{
		Mode:   mode,
		KVNHex: fmt.Sprintf("0x%02X", kvn),
		KIDHex: kidHex,
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		var planned string
		switch mode {
		case "single":
			planned = fmt.Sprintf("dry-run; pass --confirm-delete-key to delete kid=0x%02X kvn=0x%02X.", kid, kvn)
		case "all-at-kvn":
			planned = fmt.Sprintf("dry-run; pass --confirm-delete-key to delete every key at kvn=0x%02X. This is broad deletion.", kvn)
		}
		report.Skip("DELETE KEY", planned)
		data.Channel = "dry-run"
		return report.Emit(env.out, *jsonMode)
	}

	// Destructive path.
	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys delete: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"

	var checkName string
	switch mode {
	case "single":
		checkName = fmt.Sprintf("DELETE KEY kid=0x%02X kvn=0x%02X", kid, kvn)
	case "all-at-kvn":
		checkName = fmt.Sprintf("DELETE KEY all-at-kvn=0x%02X", kvn)
	}

	if err := sd.DeleteKey(ctx, ref, deleteLast); err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys delete: %w", err)
	}
	report.Pass(checkName, "")

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys delete reported failures")
	}
	return nil
}
