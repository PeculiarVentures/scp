package main

// SCP11a/c management-auth flag surface.
//
// Per the external review on feat/sd-keys-cli, Finding 4: the
// management verbs (sd allowlist set/clear, sd keys delete /
// generate / import) need SCP11a/c authentication paths, not just
// SCP03. Operators with cards that have been moved off factory SCP03
// keys to SCP11a/c-only management need a way in.
//
// SCP11a vs SCP11c (this commit):
//
//   - SCP11a: mutual auth, OCE provides cert chain to the card via
//     PERFORM SECURITY OPERATION before the AUTHENTICATE round trip.
//     Standard GP slot is KID=0x11. This is the typical path for
//     YubiKey / vendor cards in production.
//
//   - SCP11c: mutual auth with a receipt that lets a follow-up
//     session script-replay against the same key schedule. Standard
//     GP slot is KID=0x15. SCP11c WITHOUT HostID/CardGroupID works
//     identically to SCP11a-with-receipt-validation; SCP11c WITH
//     those parameters needs the wire-side AUTHENTICATE encoding
//     (parameter bit + tag-0x84 control reference) which scp11.Open
//     gates behind ErrInvalidConfig until vectors land. This helper
//     accepts SCP11c without HostID/CardGroupID; setting either
//     surfaces as an Open-time error from the library.
//
// SCP11b is deliberately NOT offered by this helper. SCP11b is
// one-way auth (card authenticates to host, host does not
// authenticate to card) and the commands using these flags are all
// OCE-gated: PUT KEY, DELETE KEY, STORE DATA, INSTALL FOR PERSO,
// GENERATE EC KEY. The card will reject every one of those over an
// SCP11b session with SW=6982. We could let an operator try SCP11b
// and watch the card refuse; we choose to refuse host-side instead
// so the failure is fast and the diagnostic is clear (one flag
// rejection, not a card round-trip).
//
// Flag mode (parallels scp03_key_flags.go):
//
//   - scp11Required is reserved for future commands that always run
//     SCP11 (none today; bootstrap-scp11a* takes its OCE flags
//     directly without going through this helper because its flag
//     vocabulary is slightly different — it INSTALLS the OCE rather
//     than authenticating with one).
//
//   - scp11Optional is what every Finding-4-affected verb uses. The
//     command opens SCP03 by default; --scp11-* flags switch it to
//     SCP11a/c.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/scp11"
)

// scp11Variant is the operator-facing variant selector, parsed from
// --scp11-mode. Stays a typed string so the flag's help text and
// validation can reference the legal values directly.
type scp11Variant string

const (
	scp11VariantNone   scp11Variant = "" // --scp11-mode not set
	scp11VariantSCP11a scp11Variant = "a"
	scp11VariantSCP11c scp11Variant = "c"
)

// scp11FlagMode mirrors scp03FlagMode.
type scp11FlagMode int

const (
	// scp11Optional: command opens SCP03 by default; --scp11-*
	// flags switch to SCP11a/c. Used by every Finding-4 verb.
	scp11Optional scp11FlagMode = iota
)

// scp11KeyFlags is the parsed handle returned by registerSCP11KeyFlags.
//
// Field naming parallels scp11.Config: the trio of OCE inputs (key /
// cert / reference) on top, the card-side reference (sd-kid / sd-kvn)
// next, then trust validation (anchors / skip).
type scp11KeyFlags struct {
	mode scp11FlagMode

	// --scp11-mode: "a" or "c". Drives Variant and the default
	// SD KID per GP Amendment F §7.1.1.
	modeRaw *string

	// OCE inputs, all required when mode is set.
	oceKeyPath  *string
	oceCertPath *string
	oceKID      *string
	oceKVN      *string

	// Card-side SD key reference. Defaults differ per variant
	// (0x11 for SCP11a, 0x15 for SCP11c) and are filled in at
	// applyToConfig time, not here, so an unset flag stays
	// distinguishable from an explicit 0x00.
	sdKID *string
	sdKVN *string

	// Trust validation of the card's certificate chain. Mirrors
	// the smoke-test --trust-roots / --lab-skip-scp11-trust
	// flags but with the --scp11- prefix to keep the auth-flag
	// surface visually grouped.
	trustRoots   *string
	labSkipTrust *bool
}

// registerSCP11KeyFlags binds the SCP11a/c flag set to fs and
// returns the handle. Idempotent across the modes (only Optional
// today; Required reserved for future commands).
func registerSCP11KeyFlags(fs *flag.FlagSet, mode scp11FlagMode) *scp11KeyFlags {
	return &scp11KeyFlags{
		mode: mode,
		modeRaw: fs.String("scp11-mode", "",
			"SCP11 variant for management auth. One of: 'a' (SCP11a, "+
				"mutual with cert chain, KID=0x11 per GP), 'c' (SCP11c, "+
				"mutual with receipt, KID=0x15). Empty default keeps the "+
				"command on SCP03. SCP11b is intentionally not offered: "+
				"it's one-way auth and the card rejects every "+
				"OCE-gated management command (PUT KEY, DELETE KEY, "+
				"STORE DATA, GENERATE EC KEY) with SW=6982."),
		oceKeyPath: fs.String("scp11-oce-key", "",
			"Path to OCE private key PEM (PKCS#8 or SEC1). Required "+
				"when --scp11-mode is set. Must be P-256 — the GP "+
				"Amendment F §6.5 SCP11 ECDH curve."),
		oceCertPath: fs.String("scp11-oce-cert", "",
			"Path to OCE certificate chain PEM, leaf last. Required "+
				"when --scp11-mode is set. The card validates this "+
				"chain against its installed OCE root before accepting "+
				"the authentication."),
		oceKID: fs.String("scp11-oce-kid", "",
			"OCE Key ID on the card. Hex byte. Default 0x10 (KeyIDOCE "+
				"per GP §7.1.1, used by Yubico factory provisioning)."),
		oceKVN: fs.String("scp11-oce-kvn", "",
			"OCE Key Version Number on the card. Hex byte. Default "+
				"0x03 (matches Yubico factory provisioning)."),
		sdKID: fs.String("scp11-sd-kid", "",
			"Card-side SCP11 SD key reference, KID. Hex byte. Default "+
				"0x11 for SCP11a, 0x15 for SCP11c (GP Amendment F "+
				"§7.1.1). Override only if your card uses a non-"+
				"standard slot."),
		sdKVN: fs.String("scp11-sd-kvn", "",
			"Card-side SCP11 SD key reference, KVN. Hex byte. Default "+
				"0x00 (GP-spec literal 'any version'). Pass an explicit "+
				"value if your card has multiple SCP11 SD key versions "+
				"and you need to disambiguate."),
		trustRoots: fs.String("scp11-trust-roots", "",
			"Path to PEM bundle of card root certificates. Loaded into "+
				"cfg.CardTrustAnchors so the card's certificate is "+
				"validated during the SCP11 handshake. The production "+
				"path; either this or --scp11-lab-skip-trust is "+
				"required when --scp11-mode is set."),
		labSkipTrust: fs.Bool("scp11-lab-skip-trust", false,
			"LAB ONLY. Skip card cert validation. Reduces SCP11 to "+
				"opportunistic encryption against an unauthenticated "+
				"card key. Use ONLY against test cards in lab. Mutually "+
				"exclusive with --scp11-trust-roots."),
	}
}

// anyFlagSet reports whether any --scp11-* flag was supplied. The
// auth-mode dispatcher uses this to decide whether to open SCP11
// vs SCP03; commands then reject the SCP03+SCP11 cross-product as
// a usage error.
func (kf *scp11KeyFlags) anyFlagSet() bool {
	if kf == nil {
		return false
	}
	if kf.modeRaw != nil && *kf.modeRaw != "" {
		return true
	}
	for _, p := range []*string{kf.oceKeyPath, kf.oceCertPath, kf.oceKID, kf.oceKVN, kf.sdKID, kf.sdKVN, kf.trustRoots} {
		if p != nil && *p != "" {
			return true
		}
	}
	if kf.labSkipTrust != nil && *kf.labSkipTrust {
		return true
	}
	return false
}

// variant parses --scp11-mode. Returns scp11VariantNone when the
// flag is empty, with no error — anyFlagSet covers the "any flag
// set" branch independently. Other values surface as a usage error.
func (kf *scp11KeyFlags) variant() (scp11Variant, error) {
	if kf == nil || kf.modeRaw == nil || *kf.modeRaw == "" {
		return scp11VariantNone, nil
	}
	switch strings.ToLower(*kf.modeRaw) {
	case "a", "scp11a":
		return scp11VariantSCP11a, nil
	case "c", "scp11c":
		return scp11VariantSCP11c, nil
	case "b", "scp11b":
		return "", &usageError{
			msg: "--scp11-mode=b is not accepted: SCP11b is one-way auth " +
				"(host cannot authenticate to card), and the OCE-gated " +
				"commands that accept --scp11-mode all require host " +
				"authentication. Use --scp11-mode=a for SCP11a or " +
				"--scp11-mode=c for SCP11c.",
		}
	default:
		return "", &usageError{
			msg: fmt.Sprintf("--scp11-mode=%q: unknown variant. Valid: 'a' (SCP11a) or 'c' (SCP11c).", *kf.modeRaw),
		}
	}
}

// applyToConfigOptional builds *scp11.Config when at least one
// --scp11-* flag is set; returns (nil, nil) otherwise. Mirrors
// scp03KeyFlags.applyToConfigOptional so the dispatcher can call
// both helpers and decide based on which one returns non-nil.
func (kf *scp11KeyFlags) applyToConfigOptional() (*scp11.Config, error) {
	if kf == nil || !kf.anyFlagSet() {
		return nil, nil
	}
	return kf.applyToConfig()
}

// applyToConfig builds *scp11.Config matching the flag selection.
// Validates required fields, parses hex byte values, loads OCE key
// and cert chain. Returns *usageError on any operator-side mistake.
func (kf *scp11KeyFlags) applyToConfig() (*scp11.Config, error) {
	v, err := kf.variant()
	if err != nil {
		return nil, err
	}
	if v == scp11VariantNone {
		return nil, &usageError{
			msg: "--scp11-mode is required when any --scp11-* flag is set " +
				"(use 'a' for SCP11a or 'c' for SCP11c)",
		}
	}

	// OCE inputs are non-negotiable for both SCP11a and SCP11c.
	if *kf.oceKeyPath == "" {
		return nil, &usageError{msg: "--scp11-oce-key is required when --scp11-mode is set"}
	}
	if *kf.oceCertPath == "" {
		return nil, &usageError{msg: "--scp11-oce-cert is required when --scp11-mode is set"}
	}

	// Trust validation must be configured one way or the other.
	if *kf.trustRoots == "" && !*kf.labSkipTrust {
		return nil, &usageError{
			msg: "either --scp11-trust-roots <pem> (production) or " +
				"--scp11-lab-skip-trust (lab) is required when " +
				"--scp11-mode is set; opening an SCP11 session against " +
				"an unauthenticated card key is opportunistic " +
				"encryption, not authenticated key agreement",
		}
	}
	if *kf.trustRoots != "" && *kf.labSkipTrust {
		return nil, &usageError{
			msg: "--scp11-trust-roots and --scp11-lab-skip-trust are " +
				"mutually exclusive — one or the other, not both",
		}
	}

	oceKey, err := loadOCEPrivateKey(*kf.oceKeyPath)
	if err != nil {
		return nil, fmt.Errorf("--scp11-oce-key: %w", err)
	}
	oceChain, err := loadOCECertChain(*kf.oceCertPath)
	if err != nil {
		return nil, fmt.Errorf("--scp11-oce-cert: %w", err)
	}

	oceKID, err := parseHexByteOrDefault(*kf.oceKID, 0x10)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("--scp11-oce-kid: %v", err)}
	}
	oceKVN, err := parseHexByteOrDefault(*kf.oceKVN, 0x03)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("--scp11-oce-kvn: %v", err)}
	}

	var defaultSDKID byte
	var cfg *scp11.Config
	switch v {
	case scp11VariantSCP11a:
		cfg = scp11.YubiKeyDefaultSCP11aConfig()
		defaultSDKID = 0x11
	case scp11VariantSCP11c:
		cfg = scp11.StrictGPSCP11cConfig()
		defaultSDKID = 0x15
	default:
		// variant() rejected everything else above; this branch
		// is unreachable but makes the switch exhaustive.
		return nil, fmt.Errorf("internal: unhandled SCP11 variant %v", v)
	}

	sdKID, err := parseHexByteOrDefault(*kf.sdKID, defaultSDKID)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("--scp11-sd-kid: %v", err)}
	}
	sdKVN, err := parseHexByteOrDefault(*kf.sdKVN, 0x00)
	if err != nil {
		return nil, &usageError{msg: fmt.Sprintf("--scp11-sd-kvn: %v", err)}
	}

	cfg.OCEPrivateKey = oceKey
	cfg.OCECertificates = oceChain
	cfg.OCEKeyReference = scp11.KeyRef{KID: oceKID, KVN: oceKVN}
	cfg.KeyID = sdKID
	cfg.KeyVersion = sdKVN

	if *kf.labSkipTrust {
		cfg.InsecureSkipCardAuthentication = true
	} else {
		pool, err := loadCertPoolFromPEM(*kf.trustRoots)
		if err != nil {
			return nil, fmt.Errorf("--scp11-trust-roots: %w", err)
		}
		cfg.CardTrustAnchors = pool
	}
	return cfg, nil
}

// describeKeys produces the human-readable summary line for the
// session-open report (parallels scp03KeyFlags.describeKeys).
func (kf *scp11KeyFlags) describeKeys(cfg *scp11.Config) string {
	if cfg == nil {
		return ""
	}
	v, _ := kf.variant()
	variantStr := "SCP11" + string(v)
	chainLen := len(cfg.OCECertificates)
	trustStr := "trust roots"
	if cfg.InsecureSkipCardAuthentication {
		trustStr = "trust SKIP (lab)"
	}
	return fmt.Sprintf("%s OCE chain (%d cert%s), %s",
		variantStr,
		chainLen,
		plural(chainLen),
		trustStr,
	)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// parseHexByteOrDefault parses a hex byte string (e.g. "10", "FF")
// or returns the default if the input is empty. Used by the SD
// KID/KVN flags so an unset flag stays distinguishable from
// "explicit 0x00" — the latter is meaningful (GP "any version").
func parseHexByteOrDefault(s string, def byte) (byte, error) {
	if s == "" {
		return def, nil
	}
	cleaned := strings.TrimPrefix(strings.ToLower(s), "0x")
	n, err := strconv.ParseUint(cleaned, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid hex byte %q: %w", s, err)
	}
	return byte(n), nil
}

// loadCertPoolFromPEM loads a PEM bundle from disk and returns it
// as a *x509.CertPool. Mirrors registerTrustFlags's behavior so the
// helper here matches what the smoke commands do for SCP11.
func loadCertPoolFromPEM(path string) (*x509.CertPool, error) {
	chain, err := loadOCECertChain(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range chain {
		pool.AddCert(c)
	}
	return pool, nil
}

// Compile-time check that *ecdsa.PrivateKey is usable as the OCE
// key field. Catches a future API change in scp11.Config that
// silently drops the type.
var _ = (*ecdsa.PrivateKey)(nil)
