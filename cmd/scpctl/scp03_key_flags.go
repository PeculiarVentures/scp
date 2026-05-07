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
// configuring the static key set used in the handshake. Four modes,
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
//
//	--scp03-kvn <byte>
//	--scp03-key <hex>       Single-key shorthand: same hex value used
//	                        for ENC, MAC, and DEK. Common on GP cards
//	                        provisioned with a single master key
//	                        rather than three independent ones.
//	                        Mutually exclusive with the split
//	                        --scp03-{enc,mac,dek} flags above.
type scp03KeyFlags struct {
	useDefault *bool
	kvn        *string
	enc        *string
	mac        *string
	dek        *string
	key        *string
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
				"--scp03-{kvn,enc,mac,dek} custom-key flags and the --scp03-key shorthand."),
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
		key: fs.String("scp03-key", "",
			"SCP03 single-key shorthand: same hex value used for ENC, MAC, and DEK. "+
				"Common on GP cards provisioned with a single master key. Requires "+
				"--scp03-kvn. Mutually exclusive with the split --scp03-{enc,mac,dek} flags."),
	}
}

// explicitlyConfigured reports whether the operator made a
// deliberate SCP03 key-set choice. True if --scp03-keys-default,
// --scp03-key, or any of the custom split-key flags were set;
// false if every flag is empty and the implicit YubiKey factory
// default would apply.
//
// Used by commands whose audience may not be running a YubiKey —
// notably 'gp registry', whose generic-GP posture would make
// silently trying the public 404142...4F factory keys against an
// unknown card surprising and potentially bad operator hygiene.
// Such commands gate themselves on this helper and refuse to run
// without an explicit choice; legacy YubiKey-flavored commands
// keep the implicit default.
func (kf *scp03KeyFlags) explicitlyConfigured() bool {
	if kf.useDefault != nil && *kf.useDefault {
		return true
	}
	if kf.kvn != nil && *kf.kvn != "" {
		return true
	}
	if kf.enc != nil && *kf.enc != "" {
		return true
	}
	if kf.mac != nil && *kf.mac != "" {
		return true
	}
	if kf.dek != nil && *kf.dek != "" {
		return true
	}
	if kf.key != nil && *kf.key != "" {
		return true
	}
	return false
}

// applyToConfig builds a *scp03.Config matching the flag selection.
// Returns a *usageError on conflict, partial-custom, or hex parse
// failures.
func (kf *scp03KeyFlags) applyToConfig() (*scp03.Config, error) {
	custom := kf.kvn != nil && (*kf.kvn != "" || *kf.enc != "" || *kf.mac != "" || *kf.dek != "")
	shorthand := kf.key != nil && *kf.key != ""

	if *kf.useDefault && (custom || shorthand) {
		return nil, &usageError{msg: "--scp03-keys-default and the custom-key flags are mutually exclusive"}
	}
	if shorthand && (*kf.enc != "" || *kf.mac != "" || *kf.dek != "") {
		return nil, &usageError{msg: "--scp03-key and --scp03-{enc,mac,dek} are mutually exclusive (use one form or the other)"}
	}
	if !custom && !shorthand {
		// Implicit or explicit factory default — same result.
		return scp03.FactoryYubiKeyConfig(), nil
	}

	if shorthand {
		if *kf.kvn == "" {
			return nil, &usageError{msg: "--scp03-key requires --scp03-kvn (the key version number is independent of the key bytes)"}
		}
		kvn, err := parseHexByte(*kf.kvn)
		if err != nil {
			return nil, &usageError{msg: fmt.Sprintf("--scp03-kvn: %v", err)}
		}
		keyBytes, err := parseSCP03KeyHex("--scp03-key", *kf.key)
		if err != nil {
			return nil, err
		}
		// Single-key shorthand: same bytes for ENC, MAC, DEK. Each
		// gets its own copy so a downstream caller mutating one does
		// not corrupt the others — the scp03 layer is not expected
		// to mutate, but the invariant should hold by construction.
		enc := append([]byte(nil), keyBytes...)
		mac := append([]byte(nil), keyBytes...)
		dek := append([]byte(nil), keyBytes...)
		return &scp03.Config{
			Keys:       scp03.StaticKeys{ENC: enc, MAC: mac, DEK: dek},
			KeyVersion: kvn,
		}, nil
	}

	// Custom split-key: all four sub-flags required.
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
			" (all four of --scp03-kvn, --scp03-enc, --scp03-mac, --scp03-dek must be supplied together; " +
			"or use --scp03-key for the single-key shorthand)"}
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
