package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/scp03"
)

// scp03KeyFlags is the flag set every SCP03 command shares for
// configuring the static key set used in the handshake. Three modes,
// mutually exclusive:
//
//	(no flags)              YubiKey factory: KVN=0xFF and the
//	                        well-known publicly documented default
//	                        keys (404142...4F). Same as the
//	                        historical default.
//
//	--scp03-keys-default    Explicit opt-in to the same factory
//	                        defaults — useful for scripts that want
//	                        to make the choice deliberate rather
//	                        than implicit.
//
//	--scp03-kvn <byte>
//	--scp03-enc <hex>       Custom key set for cards whose SCP03
//	--scp03-mac <hex>       keys have been rotated. All four flags
//	--scp03-dek <hex>       must be supplied together; partial
//	                        specification is a usage error so a
//	                        half-completed key rotation is impossible
//	                        to misfire.
type scp03KeyFlags struct {
	useDefault *bool
	kvn        *string
	enc        *string
	mac        *string
	dek        *string
}

// registerSCP03KeyFlags adds the SCP03 key flags to the given
// FlagSet. Returns a handle to read parsed values and apply them
// to a *scp03.Config.
func registerSCP03KeyFlags(fs *flag.FlagSet) *scp03KeyFlags {
	return &scp03KeyFlags{
		useDefault: fs.Bool("scp03-keys-default", false,
			"Explicit opt-in to YubiKey factory SCP03 keys (KVN=0xFF, well-known "+
				"publicly documented values). Same as the implicit default; useful "+
				"for scripts that want to be explicit. Mutually exclusive with the "+
				"--scp03-{kvn,enc,mac,dek} custom-key flags."),
		kvn: fs.String("scp03-kvn", "",
			"SCP03 key version number, hex byte (e.g. 01, FF). Required together "+
				"with --scp03-enc, --scp03-mac, --scp03-dek for cards whose keys "+
				"have been rotated."),
		enc: fs.String("scp03-enc", "",
			"SCP03 channel encryption key, hex (16, 24, or 32 bytes for AES-128/192/256)."),
		mac: fs.String("scp03-mac", "",
			"SCP03 channel MAC key, hex; same length as --scp03-enc."),
		dek: fs.String("scp03-dek", "",
			"SCP03 data encryption key, hex; same length as --scp03-enc."),
	}
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
	if kf == nil || !kf.anyFlagSet() {
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
	custom := kf.kvn != nil && (*kf.kvn != "" || *kf.enc != "" || *kf.mac != "" || *kf.dek != "")
	if *kf.useDefault && custom {
		return nil, &usageError{msg: "--scp03-keys-default and --scp03-{kvn,enc,mac,dek} are mutually exclusive"}
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
