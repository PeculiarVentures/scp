package main

import (
	"context"
	"fmt"
	"strings"

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
	Profile string `json:"profile,omitempty"`
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
	allowOrphan := fs.Bool("allow-orphan-auth", false,
		"Permit a delete that would leave the card with zero SCP03 keysets "+
			"installed. Without this flag, sd keys delete pre-fetches the "+
			"inventory and refuses if the deletion would remove the last "+
			"SCP03 keyset (KID=0x01) — that's the foot-gun case where the "+
			"operator loses the only authentication path and can no longer "+
			"manage the card. Pass this flag deliberately when rotating to "+
			"a non-SCP03 auth model or when intentionally retiring the SD.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	scp11Keys := registerSCP11KeyFlags(fs, scp11Optional)
	sdAIDFlag := registerSDAIDFlag(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	sdAID, err := sdAIDFlag.Resolve()
	if err != nil {
		return err
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

	if err := validateAuthFlags(scp03Keys, scp11Keys); err != nil {
		return err
	}

	report := &Report{Subcommand: "sd keys delete", Reader: *reader}
	data := &sdKeysDeleteData{
		Mode:   mode,
		KVNHex: fmt.Sprintf("0x%02X", kvn),
		KIDHex: kidHex,
	}
	report.Data = data

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

	// Active path: connect to the reader. Dry-run above does not
	// need card inventory and intentionally completes without a
	// connect call so previews work in environments without a
	// reader attached.
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	// Destructive path.
	sd, profName, err := openManagementSession(ctx, t, scp03Keys, scp11Keys, sdAID, report)
	if err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys delete: open SCP03: %w", err)
	}
	defer sd.Close()
	data.Channel = strings.ToLower(sd.Protocol())
	data.Profile = profName

	// Pre-flight orphan check. The foot-gun case: operator deletes
	// the only SCP03 keyset on the card and locks themselves out
	// of any subsequent management because no auth path remains.
	// Pre-fetch the inventory, count SCP03 keysets that would
	// remain after the planned delete, and refuse the operation
	// when the count drops to zero — unless the operator has
	// explicitly acknowledged the consequence with
	// --allow-orphan-auth.
	//
	// We don't extend the check to SCP11 SD slots because an SCP11
	// SD key on the card alone isn't an auth path the operator can
	// reach: SCP11 needs both the SD key AND OCE credentials AND
	// trust-anchor agreement. SCP03 is the simplest and most
	// reliable indicator of "can I still authenticate to this
	// card?" — protecting it captures the realistic foot-gun.
	//
	// Pre-fetch failure isn't fatal. If GetKeyInformation can't
	// read the KIT (some cards gate it; some applets don't
	// implement it), we log a SKIP and proceed — destructive ops
	// shouldn't block on failed inquiry. The operator already
	// passed --confirm-delete-key.
	if !*allowOrphan {
		preDelete, err := sd.GetKeyInformation(ctx)
		switch {
		case err != nil:
			report.Skip("orphan-auth pre-flight check",
				fmt.Sprintf("GetKeyInformation failed (%v); proceeding without pre-flight", err))
		default:
			scp03After := countSCP03After(preDelete, mode, kid, kvn)
			scp03Before := countSCP03(preDelete)
			if scp03Before > 0 && scp03After == 0 {
				report.Fail("orphan-auth pre-flight check",
					fmt.Sprintf("delete would leave card with zero SCP03 keysets (had %d, would have 0); "+
						"this removes the only authentication path. Pass --allow-orphan-auth to proceed.",
						scp03Before))
				_ = report.Emit(env.out, *jsonMode)
				return fmt.Errorf("sd keys delete: would orphan card auth; pass --allow-orphan-auth if intended")
			}
			report.Pass("orphan-auth pre-flight check",
				fmt.Sprintf("%d SCP03 keyset(s) would remain after delete", scp03After))
		}
	}

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

// countSCP03 returns the number of SCP03 keyset entries (KID=0x01)
// in the given KIT slice. SCP03 keysets are identified by the
// canonical KID=0x01 — every YubiKey-tested card uses this; a
// hypothetical non-standard card that puts SCP03 elsewhere would
// fall outside this check, but no such card has been encountered
// in practice.
func countSCP03(keys []securitydomain.KeyInfo) int {
	n := 0
	for _, k := range keys {
		if k.Reference.ID == securitydomain.KeyIDSCP03 {
			n++
		}
	}
	return n
}

// countSCP03After computes how many SCP03 keysets would remain in
// the inventory after the planned delete is applied. The mode,
// kid, kvn arguments mirror the cmdSDKeysDelete dispatch:
//
//   - mode "single", kid==0x01, kvn==X → -1 if (0x01, X) is currently
//     present (else no change, the entry doesn't exist)
//   - mode "single", kid!=0x01 → no change (deleting a non-SCP03 ref
//     can't affect the SCP03 count)
//   - mode "all-at-kvn", kvn==X → -count of (0x01, X) entries
//
// The function is total over the inputs the dispatch would emit;
// other (mode, kid, kvn) combinations get rejected at flag-parse
// time before they reach this code path.
func countSCP03After(keys []securitydomain.KeyInfo, mode string, kid, kvn byte) int {
	current := countSCP03(keys)
	switch mode {
	case "single":
		if kid != securitydomain.KeyIDSCP03 {
			return current
		}
		// Single-ref delete of an SCP03 keyset at KVN. -1 if it's
		// installed; no change if the operator is asking to delete
		// something that isn't there.
		for _, k := range keys {
			if k.Reference.ID == securitydomain.KeyIDSCP03 && k.Reference.Version == kvn {
				return current - 1
			}
		}
		return current
	case "all-at-kvn":
		// Every key at the named KVN is removed, including any
		// SCP03 keyset at that KVN.
		removed := 0
		for _, k := range keys {
			if k.Reference.ID == securitydomain.KeyIDSCP03 && k.Reference.Version == kvn {
				removed++
			}
		}
		return current - removed
	default:
		// Unreachable given the dispatch's flag validation.
		return current
	}
}
