package main

// SCP03 key-set import branch of `scpctl sd keys import`.
//
// Imports a new AES-128 SCP03 key triple at (kid=0x01, kvn=<--kvn>)
// by issuing PUT KEY over an authenticated SCP03 session opened
// with the EXISTING (or factory) keys. This is the rotation
// pathway: the host authenticates with the OLD key set and
// installs the NEW key set under a different KVN.
//
// Split from cmd_sd_keys_import.go because it shares no flags or
// helpers with the SCP11-SD or trust-anchor branches: SCP03
// imports take three raw 16-byte hex blobs, while SCP11-SD takes a
// PEM private key + cert chain, and trust-anchor takes a public
// key or cert with optional --ski. Each branch's godoc, flag
// surface, and dry-run preview are independently scrutable; this
// file's content is the SCP03 branch in isolation.
//
// The dispatcher in cmd_sd_keys_import.go routes into this file
// based on importCategoryForKID(kid)=="scp03-key-set".

import (
	"context"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// cmdSDKeysImportSCP03 imports a new SCP03 AES-128 key triple at
// (kid=0x01, kvn=<--kvn>). Composes Session.PutSCP03Key.
//
// Flag surface specific to SCP03:
//
//	--new-scp03-enc <hex>   New K-ENC, exactly 16 bytes (AES-128).
//	--new-scp03-mac <hex>   New K-MAC, exactly 16 bytes.
//	--new-scp03-dek <hex>   New K-DEK, exactly 16 bytes.
//
// The "new-" prefix disambiguates from the existing --scp03-*
// flags, which carry the AUTHENTICATION key set (the keys used to
// open the SCP03 session that issues PUT KEY). The two sets are
// intentionally distinct: rotating SCP03 keys means authenticating
// with the OLD set and pushing the NEW set, so confusing them at
// the flag layer would be a recipe for footguns.
//
// All three new-key flags are required together; a partial set is
// a usage error before any APDU goes out.
//
// Length: 16 bytes per component, AES-128 only. Matches the library
// guard (putKeySCP03Cmd rejects 24/32-byte components with
// ErrInvalidKey). AES-192/256 SCP03 import is a separate expansion
// gated on library PUT KEY encoding work.
//
// KCV: the card returns a 3-byte KCV per imported component. The
// library verifies the card's KCV against the host-side computation
// and returns ErrChecksum on mismatch — that bubbles up here as a
// check-level FAIL with the comparison surfaced.
//
// Dry-run by default; --confirm-write to actually transmit PUT KEY.
// Same dry-run pattern as the rest of Phase 5.
func cmdSDKeysImportSCP03(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys import", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "", "Key ID, hex byte. Required (0x01 for SCP03).")
	kvnStr := fs.String("kvn", "", "Key Version Number for the imported key set, hex byte. Required.")
	replaceKvnStr := fs.String("replace-kvn", "00",
		"Replace an existing key set at this KVN, hex byte. 00 (default) "+
			"means install a new key set without replacing.")
	newEnc := fs.String("new-scp03-enc", "",
		"New K-ENC for the imported SCP03 key set, hex (exactly 16 bytes "+
			"= AES-128). Required.")
	newMac := fs.String("new-scp03-mac", "",
		"New K-MAC, hex (exactly 16 bytes). Required.")
	newDek := fs.String("new-scp03-dek", "",
		"New K-DEK, hex (exactly 16 bytes). Required.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd keys import "+
			"runs in dry-run mode (validates inputs, reports the planned "+
			"action, exits 0 without opening SCP03 or transmitting PUT KEY).")
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

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd keys import requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	if kid != securitydomain.KeyIDSCP03 {
		// Defensive: the dispatcher routes us here only for KID 0x01,
		// but if a future change widens the dispatch (or a test
		// invokes this handler directly) we want a clear error
		// rather than letting a wrong KID reach PutSCP03Key.
		return &usageError{msg: fmt.Sprintf(
			"--kid 0x%02X: SCP03 import handler accepts KID 0x01 only", kid)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}
	replaceKvn, err := parseHexByte(*replaceKvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--replace-kvn: %v", err)}
	}

	// Three-key validation: all-or-nothing. Partial specification
	// is a usage error. Same posture as registerSCP03KeyFlags's
	// custom-key trio (auth keys); identical wording so operators
	// who've seen one error recognize the other.
	if *newEnc == "" || *newMac == "" || *newDek == "" {
		return &usageError{msg: "sd keys import (SCP03): --new-scp03-enc, --new-scp03-mac, and --new-scp03-dek are all required for an SCP03 key-set import"}
	}
	enc, err := parseSCP03KeyHex("--new-scp03-enc", *newEnc)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	mac, err := parseSCP03KeyHex("--new-scp03-mac", *newMac)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	dek, err := parseSCP03KeyHex("--new-scp03-dek", *newDek)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	// Length guard mirrors the library's own AES-128-only check.
	// Catching it host-side gives the operator a flag-named error
	// instead of a generic ErrInvalidKey at PUT KEY time.
	for _, kp := range []struct {
		flag string
		val  []byte
	}{
		{"--new-scp03-enc", enc},
		{"--new-scp03-mac", mac},
		{"--new-scp03-dek", dek},
	} {
		if len(kp.val) != 16 {
			return &usageError{msg: fmt.Sprintf(
				"%s: %d bytes (Phase 5a supports AES-128 only — exactly 16 bytes per component)",
				kp.flag, len(kp.val))}
		}
	}

	if err := validateAuthFlags(scp03Keys, scp11Keys); err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd keys import", Reader: *reader}
	data := &sdKeysImportData{
		Category:   "scp03-key-set",
		KIDHex:     fmt.Sprintf("0x%02X", kid),
		KVNHex:     fmt.Sprintf("0x%02X", kvn),
		ReplaceKVN: replaceKvn,
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		var planned string
		if replaceKvn == 0 {
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install SCP03 AES-128 key set at kid=0x%02X kvn=0x%02X (additive install).",
				kid, kvn)
		} else {
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install SCP03 AES-128 key set at kid=0x%02X kvn=0x%02X, REPLACING the existing key set at KVN=0x%02X.",
				kid, kvn, replaceKvn)
		}
		report.Skip("PUT KEY (SCP03 AES-128)", planned)
		data.Channel = "dry-run"
		return report.Emit(env.out, *jsonMode)
	}

	sd, profName, err := openManagementSession(ctx, t, scp03Keys, scp11Keys, sdAID, report)
	if err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: open SCP03: %w", err)
	}
	defer sd.Close()
	data.Channel = strings.ToLower(sd.Protocol())
	data.Profile = profName

	checkName := fmt.Sprintf("PUT KEY SCP03 AES-128 kid=0x%02X kvn=0x%02X", kid, kvn)
	newKeys := scp03.StaticKeys{ENC: enc, MAC: mac, DEK: dek}
	if err := sd.PutSCP03Key(ctx, ref, newKeys, replaceKvn); err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: %w", err)
	}
	// PUT KEY's response carries per-component KCVs. The library
	// verifies them against the host-side computation and returns
	// ErrChecksum on mismatch, so reaching this line means the
	// card's commitment matches the host's expectation.
	//
	// We surface those KCVs in JSON so the operator's deployment
	// audit log captures the on-card commitment shape. The values
	// are computed host-side from the key bytes (the library has
	// already proven the card sees the same bytes), keeping the
	// JSON emit deterministic from the input flags.
	kcvENC := securitydomain.ComputeAESKCV(enc)
	kcvMAC := securitydomain.ComputeAESKCV(mac)
	kcvDEK := securitydomain.ComputeAESKCV(dek)
	data.KCVENC = fmt.Sprintf("%X", kcvENC)
	data.KCVMAC = fmt.Sprintf("%X", kcvMAC)
	data.KCVDEK = fmt.Sprintf("%X", kcvDEK)

	report.Pass(checkName, fmt.Sprintf(
		"card commitment verified (KCVs: ENC=%X MAC=%X DEK=%X)",
		kcvENC, kcvMAC, kcvDEK))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys import reported failures")
	}
	return nil
}

// peekKIDFlag scans args for --kid (or --kid=value) without
// consuming the flag set. Used by cmdSDKeysImport to dispatch by
// KID before re-parsing in the category handler. Returns a
// usage-friendly error if --kid is absent, malformed, or appears
// without a value.
//
// This is deliberately small and forgiving of flag ordering. A
// fully accurate parse would mean instantiating a flag set, but
// then the category handler couldn't re-parse with its own complete
// flag definitions (Go's flag.FlagSet is single-use).
