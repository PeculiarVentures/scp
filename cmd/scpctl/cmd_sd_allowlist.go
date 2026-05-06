package main

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// cmdSDAllowlist dispatches `scpctl sd allowlist <verb>`.
//
// Phase 2 verbs (authenticated, --confirm-write gated):
//
//	set     Install a certificate-serial-number allowlist for one
//	        SCP11 key reference. Replaces any existing allowlist
//	        wholesale (the wire is full-replace, not merge).
//	clear   Remove the allowlist for one key reference.
//
// There is intentionally no `get` verb. The Yubico Python SDK
// (yubikit/securitydomain.py) implements store_allowlist but not
// get_allowlist; the on-card allowlist is effectively write-only on
// retail YubiKey. The production model is for operators to keep the
// canonical allowlist in their own systems (config / secret store /
// deployment manifest) and use 'sd allowlist set' to push it to the
// card. The card holds a deployed copy, not the source of record.
// See docs/design/sd-keys-cli.md.
func cmdSDAllowlist(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl sd allowlist <set|clear> [flags]"}
	}
	switch args[0] {
	case "set":
		return cmdSDAllowlistSet(ctx, env, args[1:])
	case "clear":
		return cmdSDAllowlistClear(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(env.out, `scpctl sd allowlist - Manage SCP11 certificate-serial allowlists

Usage:
  scpctl sd allowlist <verb> [flags]

Verbs:
  set       Install allowlist of certificate serials for one SCP11
            key reference. Replaces any existing allowlist wholesale.
  clear     Remove the allowlist for one key reference. After clear,
            the card accepts any certificate signed by the CA.

There is no 'get' verb by design — the on-card allowlist is
write-only on YubiKey. Operators maintain authoritative state in
their own systems; 'sd allowlist set' pushes that state to the card.

Use "scpctl sd allowlist <verb> -h" for per-verb flags.
`)
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown allowlist subcommand %q", args[0])}
}

// sdAllowlistData is the JSON-friendly payload of `sd allowlist set`
// and `sd allowlist clear`.
//
// Channel records the wire mode used; for Phase 2 this is always
// "scp03" because both verbs require authentication. Action is one
// of "set" or "clear" so JSON consumers don't have to parse the
// subcommand string. Serials echoes the canonical decimal serial
// list the operator passed (for set) so audit logs record what was
// pushed; clear leaves it empty.
type sdAllowlistData struct {
	Channel string   `json:"channel"`
	Profile string   `json:"profile,omitempty"`
	Action  string   `json:"action"` // "set" or "clear"
	KIDHex  string   `json:"kid_hex"`
	KVNHex  string   `json:"kvn_hex"`
	Serials []string `json:"serials,omitempty"` // decimal strings
}

// serialsFlag is a repeatable string flag. Each instance stays as
// the raw operator-supplied token so usage errors can echo the
// offending input verbatim. Parsing into *big.Int happens once after
// flag.Parse, where invalid tokens get a single consolidated error.
type serialsFlag []string

func (s *serialsFlag) String() string { return strings.Join(*s, ",") }
func (s *serialsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseSerial accepts a non-negative integer serial in decimal or
// 0x-prefixed hex. Returns a usage-friendly error citing the
// offending token verbatim. Negative values are rejected because
// X.509 serials are unsigned (RFC 5280 §4.1.2.2).
func parseSerial(token string) (*big.Int, error) {
	if token == "" {
		return nil, fmt.Errorf("--serial: empty value")
	}
	n := new(big.Int)
	var ok bool
	switch {
	case strings.HasPrefix(token, "0x"), strings.HasPrefix(token, "0X"):
		_, ok = n.SetString(token[2:], 16)
	default:
		_, ok = n.SetString(token, 10)
	}
	if !ok {
		return nil, fmt.Errorf("--serial %q: not a valid integer (decimal or 0x-prefixed hex)", token)
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("--serial %q: must be non-negative", token)
	}
	return n, nil
}

// cmdSDAllowlistSet pushes a certificate-serial-number allowlist to
// the card for one SCP11 key reference. Wire shape per Yubico SDK:
//
//	A6 { 83 { KID, KVN } } + 70 { 93 { serial1 } 93 { serial2 } ... }
//
// Sent via STORE DATA. Replaces any existing allowlist for the ref
// — the wire semantics are full-replace, not merge, so the operator's
// supplied --serial list IS the new allowlist.
//
// Empty allowlist (zero --serial flags) is rejected here as a usage
// error: the wire effect is identical to clear, but the intent is
// ambiguous. Operators who mean "remove the allowlist" use
// 'sd allowlist clear' so the audit log records the right verb.
//
// Dry-run by default (no --confirm-write): validates inputs, reports
// the planned action and serial count, exits 0 without opening SCP03
// or transmitting STORE DATA. Same dry-run pattern as 'sd lock' /
// 'sd unlock' / 'sd terminate'.
func cmdSDAllowlistSet(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd allowlist set", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "", "Key ID, hex byte (e.g. 11). Required.")
	kvnStr := fs.String("kvn", "", "Key Version Number, hex byte (e.g. 01). Required.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd allowlist set "+
			"runs in dry-run mode (validates inputs and reports the planned "+
			"action without transmitting STORE DATA).")
	var serials serialsFlag
	fs.Var(&serials, "serial",
		"Certificate serial number to permit. Decimal or 0x-prefixed hex. "+
			"Repeat for multiple serials. At least one is required.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd allowlist set requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}
	if len(serials) == 0 {
		return &usageError{msg: "sd allowlist set requires at least one --serial; use 'sd allowlist clear' to remove the allowlist"}
	}
	parsed := make([]*big.Int, 0, len(serials))
	canonical := make([]string, 0, len(serials))
	for _, tok := range serials {
		n, err := parseSerial(tok)
		if err != nil {
			return &usageError{msg: err.Error()}
		}
		parsed = append(parsed, n)
		canonical = append(canonical, n.String())
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd allowlist set", Reader: *reader}
	data := &sdAllowlistData{
		Action:  "set",
		KIDHex:  fmt.Sprintf("0x%02X", kid),
		KVNHex:  fmt.Sprintf("0x%02X", kvn),
		Serials: canonical,
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		report.Skip("STORE DATA allowlist set",
			fmt.Sprintf("dry-run; pass --confirm-write to push %d serial(s) "+
				"to kid=0x%02X kvn=0x%02X. The on-card allowlist is replaced "+
				"wholesale (full-replace, not merge).", len(parsed), kid, kvn))
		data.Channel = "dry-run"
		return report.Emit(env.out, *jsonMode)
	}

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, profName, err := openSCP03WithProfile(ctx, t, scp03Cfg, scp03Keys, report)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd allowlist set: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"
	data.Profile = profName

	checkName := fmt.Sprintf("STORE DATA allowlist kid=0x%02X kvn=0x%02X", kid, kvn)
	if err := sd.StoreAllowlist(ctx, ref, parsed); err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd allowlist set: %w", err)
	}
	report.Pass(checkName, fmt.Sprintf("%d serial(s) installed", len(parsed)))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd allowlist set reported failures")
	}
	return nil
}

// cmdSDAllowlistClear removes the allowlist for one key reference.
// Wire shape: same STORE DATA as set, with an empty 0x70 TLV.
//
// Library convenience: Session.ClearAllowlist forwards to
// StoreAllowlist with a nil serials slice, which the wire encoder
// produces as the empty allowlist.
//
// After clear, the card accepts any certificate signed by the
// associated CA — not the same as "no certificates accepted." A
// confused operator who runs 'clear' expecting a deny-all is in for
// a surprise; the dry-run output makes that explicit.
func cmdSDAllowlistClear(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd allowlist clear", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "", "Key ID, hex byte (e.g. 11). Required.")
	kvnStr := fs.String("kvn", "", "Key Version Number, hex byte (e.g. 01). Required.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd allowlist clear "+
			"runs in dry-run mode.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd allowlist clear requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd allowlist clear", Reader: *reader}
	data := &sdAllowlistData{
		Action: "clear",
		KIDHex: fmt.Sprintf("0x%02X", kid),
		KVNHex: fmt.Sprintf("0x%02X", kvn),
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		report.Skip("STORE DATA allowlist clear",
			fmt.Sprintf("dry-run; pass --confirm-write to remove the allowlist "+
				"for kid=0x%02X kvn=0x%02X. After clear, any certificate signed "+
				"by the associated CA is accepted (NOT 'all certificates "+
				"rejected').", kid, kvn))
		data.Channel = "dry-run"
		return report.Emit(env.out, *jsonMode)
	}

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, profName, err := openSCP03WithProfile(ctx, t, scp03Cfg, scp03Keys, report)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd allowlist clear: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"
	data.Profile = profName

	checkName := fmt.Sprintf("STORE DATA allowlist clear kid=0x%02X kvn=0x%02X", kid, kvn)
	if err := sd.ClearAllowlist(ctx, ref); err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd allowlist clear: %w", err)
	}
	report.Pass(checkName, "")

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd allowlist clear reported failures")
	}
	return nil
}
