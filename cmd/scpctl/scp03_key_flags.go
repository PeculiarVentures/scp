package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain/profile"
)

// scp03KeyFlags is the flag set SCP03-aware commands share for
// configuring the static key set used in the handshake. The flags
// are the same in both modes; what changes is the meaning of "no
// flags set":
//
//	scp03Required  used by destructive bootstrap-style commands that
//	               always open an SCP03 channel. With no flags, the
//	               channel uses the YubiKey factory keys (KVN=0xFF,
//	               well-known publicly documented values).
//
//	scp03Optional  used by read-only commands (sd keys list/export)
//	               that default to unauthenticated reads. With no
//	               flags, the command opens unauthenticated and the
//	               SCP03 path is skipped entirely. Setting any flag
//	               opts the operator into an authenticated read.
//
// Flag forms (same in both modes):
//
//	--scp03-keys-default    Explicit opt-in to factory keys.
//	                        In scp03Required this matches the
//	                        implicit default; in scp03Optional this
//	                        is how the operator opts into an
//	                        authenticated read with factory keys.
//
//	--scp03-kvn <byte>
//	--scp03-enc <hex>       Custom key set for cards whose SCP03
//	--scp03-mac <hex>       keys have been rotated. All four flags
//	--scp03-dek <hex>       must be supplied together; partial
//	                        specification is a usage error so a
//	                        half-completed key rotation is impossible
//	                        to misfire.
type scp03KeyFlags struct {
	mode       scp03FlagMode
	useDefault *bool
	kvn        *string
	enc        *string
	mac        *string
	dek        *string

	// profile selection: "auto" (default, probe at session open),
	// "yubikey-sd" (force YubiKey profile), or "standard-sd"
	// (force standard GP profile). Affects:
	//
	//   - Whether --scp03-keys-default is acceptable (the
	//     YubiKey factory keys are vendor-specific; on standard
	//     GP cards the operator must pass the custom triple).
	//   - Whether implicit factory-default fallback is acceptable
	//     in required-auth mode (same reason).
	//
	// Verbs that have additional profile-dependent behavior
	// (e.g. sd keys generate emits Yubico INS=0xF1) read the
	// resolved profile via the library-level SetProfile +
	// Capabilities mechanism; the CLI also short-circuits in
	// the explicit standard-sd case for clearer diagnostics.
	vendor *string
}

// scp03FlagMode selects the help-text wording for registerSCP03KeyFlags
// so the same flag set can serve both required-auth (bootstrap) and
// optional-auth (read-only) commands without confusing operators
// about what "no flags" means.
type scp03FlagMode int

const (
	// scp03Required: the command always opens an SCP03 channel.
	// No flags = factory keys (current bootstrap behavior).
	scp03Required scp03FlagMode = iota

	// scp03Optional: the command opens unauthenticated by default
	// and only opens SCP03 when at least one flag is set.
	scp03Optional
)

// registerSCP03KeyFlags adds the SCP03 key flags to the given
// FlagSet, with help text appropriate to mode. Returns a handle
// to read parsed values and apply them to a *scp03.Config.
func registerSCP03KeyFlags(fs *flag.FlagSet, mode scp03FlagMode) *scp03KeyFlags {
	// Help text for --scp03-keys-default and the custom-key trio
	// varies by mode. The flag names and validation logic are
	// identical; only the operator-facing wording changes so the
	// help reflects what "no flags" actually does in this command.
	var defaultHelp, customSuffix string
	switch mode {
	case scp03Required:
		defaultHelp = "Explicit opt-in to YubiKey factory SCP03 keys (KVN=0xFF, " +
			"well-known publicly documented values). Same as the implicit " +
			"default for this command; useful for scripts that want to be " +
			"explicit. Mutually exclusive with the --scp03-{kvn,enc,mac,dek} " +
			"custom-key flags."
		customSuffix = "Required together with --scp03-enc, --scp03-mac, " +
			"--scp03-dek for cards whose keys have been rotated."
	case scp03Optional:
		defaultHelp = "Authenticate using YubiKey factory SCP03 keys (KVN=0xFF, " +
			"well-known publicly documented values). Without any --scp03-* " +
			"flag this command opens unauthenticated; pass this flag to " +
			"force an authenticated read using factory keys. Mutually " +
			"exclusive with the --scp03-{kvn,enc,mac,dek} custom-key flags."
		customSuffix = "Implies SCP03-authenticated read. Required together " +
			"with --scp03-enc, --scp03-mac, --scp03-dek for cards whose " +
			"keys have been rotated."
	}

	return &scp03KeyFlags{
		mode:       mode,
		useDefault: fs.Bool("scp03-keys-default", false, defaultHelp),
		kvn: fs.String("scp03-kvn", "",
			"SCP03 key version number, hex byte (e.g. 01, FF). "+customSuffix),
		enc: fs.String("scp03-enc", "",
			"SCP03 channel encryption key, hex (16, 24, or 32 bytes for AES-128/192/256)."),
		mac: fs.String("scp03-mac", "",
			"SCP03 channel MAC key, hex; same length as --scp03-enc."),
		dek: fs.String("scp03-dek", "",
			"SCP03 data encryption key, hex; same length as --scp03-enc."),
		vendor: fs.String("profile", "auto",
			"Card profile selection. 'auto' (default) probes the card "+
				"non-destructively at session open and selects YubiKey or "+
				"Standard based on the result. 'yubikey-sd' forces the "+
				"YubiKey profile (Yubico extensions enabled — GENERATE "+
				"EC KEY etc.). 'standard-sd' forces the standard GP "+
				"profile (Yubico extensions refused host-side; --scp03-keys-default "+
				"rejected; KIDs labeled by raw value rather than YubiKey "+
				"convention). The active profile is reported in JSON output."),
	}
}

// VendorProfile returns the parsed --profile value, normalized.
// Returns one of "auto", "yubikey-sd", "standard-sd". Verbs that
// need the resolved profile (after auto-detect) call ResolveProfile
// instead.
func (kf *scp03KeyFlags) VendorProfile() string {
	if kf == nil || kf.vendor == nil {
		return "auto"
	}
	return *kf.vendor
}

// validateVendor returns a usageError if the --profile flag value
// isn't recognized. Called from both applyToConfig variants so
// the validation runs at the point of first SCP03 use.
func (kf *scp03KeyFlags) validateVendor() error {
	switch kf.VendorProfile() {
	case "auto", "yubikey-sd", "standard-sd":
		return nil
	default:
		return &usageError{msg: fmt.Sprintf(
			"--profile: %q not recognized; valid values are 'auto', 'yubikey-sd', 'standard-sd'",
			*kf.vendor)}
	}
}

// effectiveProfileBeforeProbe returns the static profile when the
// --profile value is non-auto. Returns nil when --profile is auto
// (in which case the verb should call profile.Probe to resolve).
//
// This is the synchronous part of profile resolution: validation
// and the explicit-pin path. The auto path requires a live
// transport, which only the verb has.
func (kf *scp03KeyFlags) effectiveProfileBeforeProbe() profile.Profile {
	switch kf.VendorProfile() {
	case "yubikey-sd":
		return profile.YubiKey()
	case "standard-sd":
		return profile.Standard()
	default:
		return nil
	}
}

// IsStandardSD reports whether the resolved (or pinned) profile is
// the standard-sd profile. Used by validation paths that need to
// reject vendor-specific shortcuts (e.g. --scp03-keys-default).
//
// Without auto-detection happening yet, this method conservatively
// returns true only when --profile=standard-sd was explicitly
// specified. The auto path defers the standard/yubikey decision
// until the verb opens a transport and runs Probe; the
// applyToConfig validation runs BEFORE that, so it can't block on
// "auto might resolve to standard." The CLI-level fail-fast checks
// (factory-key rejection, generate refusal) are accepted-as-best-
// effort for auto: they fire on explicit standard-sd, not on auto.
// Auto-resolved standard-sd is caught at the library level by the
// SetProfile + Capabilities gate, which is the authoritative
// safety net.
func (kf *scp03KeyFlags) IsStandardSD() bool {
	return kf.VendorProfile() == "standard-sd"
}

// applyToConfigOptional is the read-only-command counterpart to
// applyToConfig. It returns (nil, nil) when no SCP03 key flag was
// set — signalling "operator did not opt into authenticated reads,
// caller should choose an unauthenticated open." When any flag is
// set it dispatches to applyToConfig so factory / custom selection,
// validation, and error messages are all single-sourced there.
//
// Bootstrap-style commands that always authenticate continue to call
// applyToConfig directly; the implicit "no flags = factory" semantic
// is preserved for them. Read-only commands call this method instead.
func (kf *scp03KeyFlags) applyToConfigOptional() (*scp03.Config, error) {
	if kf == nil {
		return nil, nil
	}
	// Validate vendor profile even when no SCP03 flags are set —
	// operators can typo the vendor value and the unauth fallback
	// shouldn't silently swallow that. validateVendor is cheap.
	if err := kf.validateVendor(); err != nil {
		return nil, err
	}
	if !kf.anyFlagSet() {
		return nil, nil
	}
	return kf.applyToConfig()
}

// anyFlagSet reports whether any of the four custom-key fields is
// non-empty or --scp03-keys-default was passed. Private helper for
// applyToConfigOptional.
func (kf *scp03KeyFlags) anyFlagSet() bool {
	if kf.useDefault != nil && *kf.useDefault {
		return true
	}
	for _, p := range []*string{kf.kvn, kf.enc, kf.mac, kf.dek} {
		if p != nil && *p != "" {
			return true
		}
	}
	return false
}

// applyToConfig builds a *scp03.Config matching the flag selection.
// Returns a *usageError on conflict, partial-custom, or hex parse
// failures.
func (kf *scp03KeyFlags) applyToConfig() (*scp03.Config, error) {
	if err := kf.validateVendor(); err != nil {
		return nil, err
	}
	custom := kf.kvn != nil && (*kf.kvn != "" || *kf.enc != "" || *kf.mac != "" || *kf.dek != "")
	if *kf.useDefault && custom {
		return nil, &usageError{msg: "--scp03-keys-default and --scp03-{kvn,enc,mac,dek} are mutually exclusive"}
	}

	// Profile gates: the YubiKey factory keys are vendor-specific
	// (KVN=0xFF, well-known publicly documented AES-128 values
	// from Yubico). On a standard GP card these keys are wrong by
	// definition, so we refuse the factory-default path
	// explicitly when --profile=standard-sd was specified rather
	// than emit an authenticated APDU that will fail in
	// card-error noise.
	//
	// For --profile=auto: this CLI-level check doesn't fire because
	// auto hasn't been resolved yet at flag-parse time. The
	// authoritative gate runs at the library level via SetProfile +
	// Capabilities; the CLI fast-fail here is best-effort for the
	// explicit-pin case.
	//
	// Two cases to reject when standard-sd is pinned:
	//   1. --scp03-keys-default was set explicitly
	//   2. No SCP03 flags were set, and we're in required-auth
	//      mode (so the implicit fallback would be factory keys)
	//
	// Optional-auth verbs (sd keys list, sd keys export) handle
	// case 2 via applyToConfigOptional, which short-circuits
	// before this function runs when no flags are set; this
	// function only sees the "auth was requested" path.
	if kf.IsStandardSD() {
		if *kf.useDefault {
			return nil, &usageError{msg: "--scp03-keys-default is not valid with --profile standard-sd " +
				"(YubiKey factory keys don't apply to standard GP cards). Pass the explicit " +
				"--scp03-{kvn,enc,mac,dek} triple instead."}
		}
		if !custom {
			return nil, &usageError{msg: "--profile standard-sd requires explicit --scp03-{kvn,enc,mac,dek} " +
				"(no implicit YubiKey factory-key fallback for standard GP cards)."}
		}
	}

	if !custom {
		// Implicit or explicit factory default — same result.
		return scp03.FactoryYubiKeyConfig(), nil
	}
	// Custom: all four sub-flags required.
	missing := []string{}
	if *kf.kvn == "" {
		missing = append(missing, "--scp03-kvn")
	}
	if *kf.enc == "" {
		missing = append(missing, "--scp03-enc")
	}
	if *kf.mac == "" {
		missing = append(missing, "--scp03-mac")
	}
	if *kf.dek == "" {
		missing = append(missing, "--scp03-dek")
	}
	if len(missing) > 0 {
		return nil, &usageError{msg: "custom SCP03 keys: missing " + strings.Join(missing, ", ") +
			" (all four of --scp03-kvn, --scp03-enc, --scp03-mac, --scp03-dek must be supplied together)"}
	}

	kvn, err := parseHexByte(*kf.kvn)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("--scp03-kvn: %v", err)}
	}
	encBytes, err := parseSCP03KeyHex("--scp03-enc", *kf.enc)
	if err != nil {
		return nil, err
	}
	macBytes, err := parseSCP03KeyHex("--scp03-mac", *kf.mac)
	if err != nil {
		return nil, err
	}
	dekBytes, err := parseSCP03KeyHex("--scp03-dek", *kf.dek)
	if err != nil {
		return nil, err
	}
	if len(macBytes) != len(encBytes) || len(dekBytes) != len(encBytes) {
		return nil, &usageError{msg: fmt.Sprintf(
			"SCP03 key length mismatch: enc=%d mac=%d dek=%d (all three must match — 16/24/32 bytes)",
			len(encBytes), len(macBytes), len(dekBytes))}
	}
	return &scp03.Config{
		Keys:       scp03.StaticKeys{ENC: encBytes, MAC: macBytes, DEK: dekBytes},
		KeyVersion: kvn,
	}, nil
}

// describeKeys returns a one-line label for the report describing
// which key mode is in effect. Names "factory" or "custom (KVN 0xNN,
// AES-N)" — never logs key bytes.
func (kf *scp03KeyFlags) describeKeys(cfg *scp03.Config) string {
	if cfg.KeyVersion == scp03.YubiKeyFactoryKeyVersion &&
		bytesEqualKey(cfg.Keys.ENC, scp03.DefaultKeys.ENC) {
		return "factory (KVN 0xFF, AES-128 well-known)"
	}
	bits := len(cfg.Keys.ENC) * 8
	return fmt.Sprintf("custom (KVN 0x%02X, AES-%d)", cfg.KeyVersion, bits)
}

func parseHexByte(s string) (byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	v, err := strconv.ParseUint(s, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid hex byte", s)
	}
	return byte(v), nil
}

// parseSCP03KeyHex decodes a hex-encoded SCP03 key, tolerating the
// usual paste-from-docs cosmetics (whitespace, colons, dashes), and
// validates the length is 16/24/32 (AES-128/192/256).
//
// Returns error (not *usageError) deliberately: callers may have a
// pre-declared err of type error from earlier in their function,
// and assigning a *usageError into that interface variable produces
// a "non-nil interface holding a nil pointer" when the function
// succeeds, which makes downstream `if err != nil` checks fire on
// a nil-valued error. Returning error directly avoids the typed-nil
// trap. The concrete type is still *usageError; callers can
// errors.As to recover it.
func parseSCP03KeyHex(label, s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("%s: not valid hex: %v", label, err)}
	}
	switch len(b) {
	case 16, 24, 32:
		return b, nil
	default:
		return nil, &usageError{msg: fmt.Sprintf(
			"%s: length %d not valid (want 16/24/32 bytes for AES-128/192/256)", label, len(b))}
	}
}

// bytesEqualKey is a non-constant-time byte comparison used only
// to detect "is this the well-known factory key" for the report
// label. Not security-sensitive — the factory key is publicly
// documented.
func bytesEqualKey(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
