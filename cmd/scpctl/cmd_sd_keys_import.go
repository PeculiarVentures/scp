package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// sdKeysImportData is the JSON payload of `sd keys import`.
//
// Category records which KID-dispatched semantic branch ran:
// "scp03-key-set" (Phase 5a, this commit), "scp11-sd-key" (Phase
// 5b, forthcoming), or "ca-trust-anchor" (Phase 5c, forthcoming).
// Phase-5a-only output emits "scp03-key-set" or, for stubbed
// branches, the planned category alongside an explicit "not yet
// implemented" SKIP check so JSON consumers can reason about
// version readiness.
//
// KCV is the three-byte key check value the card returned for the
// imported SCP03 key set. Recorded so the operator's deployment
// audit log captures the on-card commitment.
type sdKeysImportData struct {
	Channel    string `json:"channel"`
	Category   string `json:"category"`
	KIDHex     string `json:"kid_hex"`
	KVNHex     string `json:"kvn_hex"`
	ReplaceKVN byte   `json:"replace_kvn"`

	// SCP11-SD-only fields (omitempty so the SCP03 path's JSON is
	// unchanged; consumers ignore unknown fields by convention).
	//
	// SPKIFingerprintSHA256 is computed from the imported PRIVATE
	// key's public counterpart, the same shape used by sd keys
	// list / export / generate. Recording the public fingerprint
	// gives the operator a stable cross-tool identifier for the
	// installed key without ever surfacing private material. Empty
	// in dry-run (no key has been committed to the card).
	//
	// CertCount is the number of certificates in --certs (0 when
	// --certs was not given). The presence vs absence of a chain
	// is part of the audit record because chain handling on the
	// card differs (STORE DATA vs no-op).
	SPKIFingerprintSHA256 string `json:"spki_fingerprint_sha256,omitempty"`
	CertCount             int    `json:"cert_count,omitempty"`

	// ca-trust-anchor-only fields (Phase 5c). SKIHex is the SKI
	// being registered against the public key reference; SKIOrigin
	// records how it was derived: "cert-extension" (cert had a
	// SubjectKeyId), "computed-sha1-spki" (cert lacked the
	// extension and we computed per RFC 5280 §4.2.1.2 method 1),
	// or "explicit-override" (operator passed --ski). Operators
	// auditing fleet provisioning need the origin to verify their
	// SKI canonicalization policy.
	SKIHex    string `json:"ski_hex,omitempty"`
	SKIOrigin string `json:"ski_origin,omitempty"`
}

// importCategoryForKID returns the import-semantic category for a
// KID, plus a phase tag (which Phase commit owns the implementation).
// The same KID-category mapping is used by sd keys list's classifier
// (classifyKID), but this version is import-specific because it also
// reports the implementation-status side: Phase 5a covers scp03 only,
// 5b adds scp11-sd, 5c adds ca-trust-anchor.
//
// Returning the phase tag lets the dispatcher emit a clear "not yet
// implemented in this phase" message for the categories whose handler
// hasn't landed yet, rather than a generic "unknown KID" — operators
// reading the message know what to wait for.
func importCategoryForKID(kid byte) (category string, phase string, ok bool) {
	switch {
	case kid == securitydomain.KeyIDSCP03:
		return "scp03-key-set", "5a", true
	case kid == securitydomain.KeyIDSCP11a,
		kid == securitydomain.KeyIDSCP11b,
		kid == securitydomain.KeyIDSCP11c:
		return "scp11-sd-key", "5b", true
	case kid == securitydomain.KeyIDOCE, kid >= 0x20 && kid <= 0x2F:
		return "ca-trust-anchor", "5c", true
	}
	return "", "", false
}

// cmdSDKeysImport dispatches by KID category to the appropriate
// import handler. The categories have materially different input
// surfaces and library compositions, so they're implemented as
// separate functions rather than fanned out in one big switch.
//
// Phase 5a (this commit): SCP03 key-set import only. The other
// categories return a clear "not yet implemented in Phase 5a"
// message that points at the future commit. This keeps the
// dispatcher in place — and any KID-category misuse rejected
// host-side — while the rest of Phase 5 is staged.
//
// Common flags parsed here for cross-category consistency:
//
//	--reader, --json
//	--kid, --kvn (required, both)
//	--replace-kvn (default 00)
//	--confirm-write
//	--scp03-* (auth, scp03Required mode)
//
// Per-category flags are parsed inside the per-category handler
// because their meaning varies by category. SCP03 takes new-key
// material; SCP11-SD takes a PEM private key + optional cert chain;
// OCE/CA takes a public key + SKI. Trying to register all of them
// at the top level would produce flag-help output that lies about
// which flags are meaningful for which KID.
func cmdSDKeysImport(ctx context.Context, env *runEnv, args []string) error {
	// First-pass parse: just enough to identify the KID, so we can
	// dispatch to the right category-specific handler. The category
	// handler will re-parse with its own complete flag set.
	//
	// flag.FlagSet is single-use, so we use a peek-only helper that
	// scans args for --kid without consuming them.
	kid, err := peekKIDFlag(args)
	if err != nil {
		return &usageError{msg: err.Error()}
	}

	category, _, ok := importCategoryForKID(kid)
	if !ok {
		return &usageError{msg: fmt.Sprintf(
			"--kid 0x%02X: not a recognized SD import category. Valid: "+
				"0x01 (SCP03), 0x10/0x20-0x2F (CA/OCE trust anchor), "+
				"0x11/0x13/0x15 (SCP11 SD key)", kid)}
	}

	switch category {
	case "scp03-key-set":
		return cmdSDKeysImportSCP03(ctx, env, args)
	case "scp11-sd-key":
		return cmdSDKeysImportSCP11SD(ctx, env, args)
	case "ca-trust-anchor":
		return cmdSDKeysImportTrustAnchor(ctx, env, args)
	}
	// Unreachable.
	return &usageError{msg: fmt.Sprintf("internal: unhandled category %q", category)}
}

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
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
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

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
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

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"

	checkName := fmt.Sprintf("PUT KEY SCP03 AES-128 kid=0x%02X kvn=0x%02X", kid, kvn)
	newKeys := scp03.StaticKeys{ENC: enc, MAC: mac, DEK: dek}
	if err := sd.PutSCP03Key(ctx, ref, newKeys, replaceKvn); err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: %w", err)
	}
	// PUT KEY's response carries per-component KCVs. Library
	// verifies them against the host-side computation and returns
	// ErrChecksum on mismatch — so reaching this line means the
	// card's commitment matches what we asked for. The KCVs aren't
	// surfaced in JSON yet (the helper is package-internal); a
	// follow-up commit can export it and add data.kcv_enc/mac/dek
	// without breaking the existing schema.
	report.Pass(checkName, "card commitment verified (KCVs match)")

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
func peekKIDFlag(args []string) (byte, error) {
	for i, a := range args {
		switch {
		case a == "--kid":
			if i+1 >= len(args) {
				return 0, fmt.Errorf("--kid requires a value")
			}
			return parseHexByte(args[i+1])
		case len(a) > 6 && a[:6] == "--kid=":
			return parseHexByte(a[6:])
		}
	}
	return 0, fmt.Errorf("sd keys import requires --kid")
}

// cmdSDKeysImportSCP11SD imports an SCP11 endpoint private key (and
// optionally a certificate chain) at one of the SCP11 SD slots.
// Composes Session.PutECPrivateKey (always) + Session.StoreCertificates
// (only when --certs is supplied).
//
// Flag surface specific to SCP11 SD import:
//
//	--key-pem <path>     PEM file with the EC P-256 private key.
//	                     Accepts PKCS#8 ('PRIVATE KEY') or SEC1
//	                     ('EC PRIVATE KEY') wrapping. Required.
//	--certs <path>       Optional PEM bundle with the certificate
//	                     chain to associate with the key reference.
//	                     Leaf certificate LAST per
//	                     Session.StoreCertificates / yubikit
//	                     store_certificate_bundle. When present,
//	                     stored against the same KID/KVN via
//	                     STORE DATA tag 0xBF21.
//
// Curve enforcement: the library accepts P-256 only for SCP11 (GP
// Amendment F §7.1.1.4). We refuse non-P-256 keys host-side with a
// clear error rather than letting a confusing wire-level error
// bubble up from PutECPrivateKey.
//
// Anti-typo safety guard: when --certs is supplied, the leaf cert's
// SubjectPublicKeyInfo must match the public counterpart of the
// imported private key. Mismatch is a usage error before any APDU
// transmits — almost always means the operator picked the wrong
// pair of files. Matching is by SPKI DER bytes, the same shape used
// by sd keys list/export for cross-tool key identity.
//
// Partial-failure posture: if PutECPrivateKey succeeds but
// StoreCertificates fails, the report records both (the key is on
// the card, the chain is not) but does not attempt cleanup. The
// operator can re-run with --certs alone to retry chain storage,
// or run sd keys delete to roll back the key. This matches
// bootstrap-scp11a-sd's behavior for the same wire shape.
//
// No private material in output, ever — the imported key bytes
// must never appear in the report or JSON, including on error
// paths. The TestSDKeysImportSCP11SD_NoPrivateMaterialOnFailure
// test pins this contract.
//
// Auth: SCP03-authenticated session (DEK required because the
// private key is encrypted with the session DEK before
// transmission). SCP11a auth is a Phase 2b/4b parallel.
//
// Dry-run by default; --confirm-write to actually transmit
// PUT KEY (and STORE DATA when --certs is given).
func cmdSDKeysImportSCP11SD(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys import", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "",
		"SCP11 SD slot, hex byte. Must be one of 11 (SCP11a), 13 "+
			"(SCP11b), 15 (SCP11c). Required.")
	kvnStr := fs.String("kvn", "",
		"Key Version Number for the imported key, hex byte. Required.")
	replaceKvnStr := fs.String("replace-kvn", "00",
		"Replace an existing key at this KVN, hex byte. 00 (default) "+
			"means install a new key without replacing.")
	keyPemPath := fs.String("key-pem", "",
		"PEM file containing the EC P-256 private key to import. "+
			"Accepts PKCS#8 (PRIVATE KEY) or SEC1 (EC PRIVATE KEY) wrapping. "+
			"Required. The private key bytes never appear in any output.")
	certsPath := fs.String("certs", "",
		"Optional PEM bundle with the certificate chain to store "+
			"against this key reference (leaf certificate LAST). When "+
			"supplied, the leaf cert's public key must match the imported "+
			"private key — a mismatch is rejected before any APDU goes out.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd keys import "+
			"runs in dry-run mode (validates inputs, parses files, reports "+
			"the planned action, exits 0 without opening SCP03 or "+
			"transmitting any APDU).")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd keys import requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	if !isSCP11SDSlot(kid) {
		// Defensive guard. Dispatcher routes only 0x11/0x13/0x15
		// here, but if a future change widens the dispatch this
		// keeps the wrong KID from reaching PutECPrivateKey.
		return &usageError{msg: fmt.Sprintf(
			"--kid 0x%02X: SCP11 SD import handler accepts SCP11 SD slots only "+
				"(0x11 SCP11a, 0x13 SCP11b, 0x15 SCP11c)", kid)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}
	replaceKvn, err := parseHexByte(*replaceKvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--replace-kvn: %v", err)}
	}
	if *keyPemPath == "" {
		return &usageError{msg: "sd keys import (SCP11 SD): --key-pem is required"}
	}

	// Parse files BEFORE opening any session. File-level errors
	// (missing path, bad PEM, wrong curve, key/cert mismatch) are
	// usage errors — fixing them doesn't require an authenticated
	// retry, so making the operator burn an SCP03 handshake to
	// learn about a typo is hostile.
	privKey, err := loadSDPrivateKey(*keyPemPath)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	var chain []*x509.Certificate
	if *certsPath != "" {
		chain, err = loadSDCertChain(*certsPath)
		if err != nil {
			return &usageError{msg: err.Error()}
		}
		if err := verifyLeafMatchesPrivateKey(privKey, chain[len(chain)-1]); err != nil {
			return &usageError{msg: err.Error()}
		}
	}
	leafSPKIFingerprint, err := publicKeySPKIFingerprint(&privKey.PublicKey)
	if err != nil {
		// Should never happen for a successfully-parsed P-256 key,
		// but if it does the operator deserves to see it before
		// the destructive APDU goes out.
		return fmt.Errorf("sd keys import: compute public-key fingerprint: %w", err)
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd keys import", Reader: *reader}
	data := &sdKeysImportData{
		Category:   "scp11-sd-key",
		KIDHex:     fmt.Sprintf("0x%02X", kid),
		KVNHex:     fmt.Sprintf("0x%02X", kvn),
		ReplaceKVN: replaceKvn,
		CertCount:  len(chain),
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		var planned string
		switch {
		case replaceKvn != 0:
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install SCP11 P-256 private key at kid=0x%02X kvn=0x%02X, REPLACING the existing key at KVN=0x%02X.",
				kid, kvn, replaceKvn)
		default:
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install SCP11 P-256 private key at kid=0x%02X kvn=0x%02X (additive install).",
				kid, kvn)
		}
		if len(chain) > 0 {
			planned += fmt.Sprintf(" Chain (%d cert%s) will be stored against the same key reference.",
				len(chain), pluralS(len(chain)))
		}
		report.Skip("PUT KEY (SCP11 P-256 private)", planned)
		if len(chain) > 0 {
			report.Skip("STORE DATA cert chain", fmt.Sprintf("dry-run; %d cert%s ready, leaf SPKI fingerprint matches private key.", len(chain), pluralS(len(chain))))
		}
		data.Channel = "dry-run"
		// SPKIFingerprintSHA256 is set on the active path only.
		// In dry-run we have computed the fingerprint host-side
		// but no card-side commitment exists yet, so we leave it
		// out of the JSON to avoid implying that the install
		// happened.
		_ = leafSPKIFingerprint
		return report.Emit(env.out, *jsonMode)
	}

	// Active path.
	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"

	putKeyCheck := fmt.Sprintf("PUT KEY SCP11 P-256 private kid=0x%02X kvn=0x%02X", kid, kvn)
	if err := sd.PutECPrivateKey(ctx, ref, privKey, replaceKvn); err != nil {
		report.Fail(putKeyCheck, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: %w", err)
	}
	report.Pass(putKeyCheck, "card commitment verified")
	// Now the card holds the key. If StoreCertificates fails below,
	// we report partial success — the key is on the card, chain is
	// not. Operator can retry with --certs alone or roll back via
	// sd keys delete.
	data.SPKIFingerprintSHA256 = leafSPKIFingerprint

	if len(chain) > 0 {
		storeCertsCheck := fmt.Sprintf("STORE DATA cert chain kid=0x%02X kvn=0x%02X", kid, kvn)
		if err := sd.StoreCertificates(ctx, ref, chain); err != nil {
			report.Fail(storeCertsCheck, err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("sd keys import: store cert chain (key already installed): %w", err)
		}
		report.Pass(storeCertsCheck, fmt.Sprintf("%d cert(s) stored", len(chain)))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys import reported failures")
	}
	return nil
}

// loadSDPrivateKey reads a PEM file and extracts an EC P-256 private
// key for SCP11 SD import. Mirrors loadOCEPrivateKey in shape but
// with SD-key-appropriate error messages.
//
// Accepts both PKCS#8 ('PRIVATE KEY') and SEC1 ('EC PRIVATE KEY')
// wrappings. Modern openssl genpkey defaults to PKCS#8; older
// tooling and Yubico reference fixtures use SEC1. Accepting both
// makes the CLI usable with whatever the operator already has.
//
// Curve enforcement: SCP11 (GP Amendment F §7.1.1.4) mandates P-256.
// A key on any other curve would be rejected at PUT KEY time with
// a less clear error chain, so we fail fast here.
func loadSDPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SD key %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("SD key %q: no PEM block found", path)
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 SD key: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("SD key is not ECDSA (got %T)", k)
		}
		key = ec
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC1 SD key: %w", err)
		}
		key = k
	default:
		return nil, fmt.Errorf("SD key %q: unsupported PEM type %q (want PRIVATE KEY or EC PRIVATE KEY)", path, block.Type)
	}

	if key.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("SD key %q: curve is %s, SCP11 requires P-256", path, key.Curve.Params().Name)
	}
	return key, nil
}

// loadSDCertChain parses a PEM bundle into one or more certificates
// for SCP11 SD chain storage. Same shape as loadOCECertChain but
// with naming appropriate to SD keys.
//
// Order: caller-preserved. The library's StoreCertificates expects
// leaf-LAST; this loader returns the certs in file order. Callers
// validate that the leaf (final entry) matches the imported private
// key via verifyLeafMatchesPrivateKey.
//
// Skips non-CERTIFICATE PEM blocks rather than failing — operators
// sometimes prepend trust-store comments or paste keys alongside
// certs by accident, and a noisy bundle with valid certs in it
// shouldn't be hostile.
func loadSDCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SD certs %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SD cert in %q: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("SD cert file contains no CERTIFICATE blocks")
	}
	return certs, nil
}

// verifyLeafMatchesPrivateKey is the anti-typo guard for
// SCP11 SD imports with --certs. Compares the leaf cert's SPKI
// against the public counterpart of the imported private key, byte-
// for-byte. A mismatch almost always means the operator picked the
// wrong pair of files; we refuse before transmitting any APDU.
//
// Returns nil on match, a usage-friendly error on mismatch.
func verifyLeafMatchesPrivateKey(priv *ecdsa.PrivateKey, leaf *x509.Certificate) error {
	leafSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("--certs: marshal leaf cert public key: %w", err)
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("--key-pem: marshal private key's public counterpart: %w", err)
	}
	if !bytes.Equal(leafSPKI, keySPKI) {
		return fmt.Errorf("--certs leaf cert public key does not match --key-pem private key. Most likely the wrong files were paired; verify --key-pem and --certs name a matching pair.")
	}
	return nil
}

// publicKeySPKIFingerprint returns the hex SHA-256 over the SPKI DER
// of an EC public key. Same shape used by sd keys list / export /
// generate so installed-key identity is comparable across tools.
// Computes the digest inline rather than calling spkiFingerprint
// (which takes a *x509.Certificate); this path has only the public
// key, no cert wrapper.
func publicKeySPKIFingerprint(pub *ecdsa.PublicKey) (string, error) {
	derSPKI, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(derSPKI)
	return hexEncode(sum[:]), nil
}

// pluralS returns "" when n==1 and "s" otherwise; small helper to
// keep dry-run wording grammatically clean.
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// cmdSDKeysImportTrustAnchor installs an OCE / CA public key as a
// trust anchor at one of the CA-public KIDs (0x10 OCE, 0x20–0x2F
// KLCC range) and registers its Subject Key Identifier. Composes
// Session.PutECPublicKey + Session.StoreCaIssuer.
//
// Trust-anchor semantics differ from SD-key semantics in one
// important way: chains are NOT stored against trust anchor refs.
// Trust anchors are root certs — the card uses them to validate
// other certs during SCP11 PSO, it doesn't store a chain about them.
// --certs is therefore rejected here with a usage error rather than
// silently no-op'd, so an operator who carried --certs over from an
// SD-key import gets a clear correction instead of a confusing
// "succeeded but no chain visible" outcome.
//
// Flag surface specific to trust anchor:
//
//	--key-pem <path>   PEM file containing either:
//	                   - a CERTIFICATE block (extract pubkey + SKI from cert)
//	                   - a PUBLIC KEY block (bare pubkey, --ski required)
//	                   Required.
//	--ski <hex>        Optional override or required-with-bare-pubkey.
//	                   Hex bytes (colons accepted, stripped). When the
//	                   --key-pem is a cert, --ski overrides whatever
//	                   the cert carries — useful for operators whose
//	                   fleet-management system has a canonical SKI
//	                   independent of the cert's own extension.
//	--certs <path>     REJECTED. Trust anchors don't get chains
//	                   stored on the card; if you have a chain, it's
//	                   for the SD-key category (KIDs 0x11/0x13/0x15)
//	                   or for OCE leaf delivery (--oce-cert in
//	                   bootstrap-oce).
//
// SKI derivation precedence (when --key-pem is a CERTIFICATE):
//
//  1. --ski hex      (operator override, wins)
//  2. cert.SubjectKeyId extension (preferred — fleet-management
//     systems typically carry this through unchanged)
//  3. SHA-1 of SPKI per RFC 5280 §4.2.1.2 method 1 (fallback for
//     certs that omit the extension)
//
// When --key-pem is a bare PUBLIC KEY, only path (1) is available;
// a missing --ski is a usage error because auto-derivation needs
// the cert wrapper.
//
// Partial-failure posture: PutECPublicKey + StoreCaIssuer are
// independent on the wire. If the first succeeds and the second
// fails, the card holds a public key with no SKI registered — the
// trust anchor is non-functional in that state but recoverable by
// re-running with --ski against the same KID/KVN. Cleanup is NOT
// attempted for the same reason as Phase 5b: silent rollback of
// successful operations is a bigger surprise than a partial-state
// FAIL report.
func cmdSDKeysImportTrustAnchor(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys import", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "",
		"CA-public KID, hex byte. Must be 10 (OCE) or 20–2F (KLCC range). Required.")
	kvnStr := fs.String("kvn", "",
		"Key Version Number, hex byte. Required.")
	replaceKvnStr := fs.String("replace-kvn", "00",
		"Replace an existing trust anchor at this KVN, hex byte. 00 (default) "+
			"means install a new anchor without replacing.")
	keyPemPath := fs.String("key-pem", "",
		"PEM file containing either a CERTIFICATE (preferred — SKI is derived "+
			"automatically) or a PUBLIC KEY (--ski must be supplied). The public "+
			"key must be NIST P-256. Required.")
	skiHex := fs.String("ski", "",
		"Subject Key Identifier override, hex (colons accepted). When --key-pem "+
			"is a CERTIFICATE this overrides whatever the cert carries. Required "+
			"when --key-pem is a bare PUBLIC KEY.")
	certsPath := fs.String("certs", "",
		"REJECTED for trust anchors. Trust anchors don't get cert chains "+
			"stored against them; chains are for SCP11 SD key imports (--kid "+
			"11/13/15) or OCE leaf delivery (bootstrap-oce). Refuse here so a "+
			"chain accidentally carried over from an SD-key invocation gets a "+
			"clear correction.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd keys import runs in "+
			"dry-run mode (validates inputs, parses files, derives SKI, reports "+
			"the planned action, exits 0 without opening SCP03 or transmitting "+
			"any APDU).")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd keys import requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	if !isCATrustAnchorKID(kid) {
		// Defensive guard. Dispatcher routes only 0x10 / 0x20–0x2F
		// here; widening or misuse should produce a clear error
		// rather than reaching PutECPublicKey with a wrong KID.
		return &usageError{msg: fmt.Sprintf(
			"--kid 0x%02X: trust-anchor handler accepts CA-public KIDs only "+
				"(0x10 OCE, 0x20–0x2F KLCC range)", kid)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}
	replaceKvn, err := parseHexByte(*replaceKvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--replace-kvn: %v", err)}
	}
	if *keyPemPath == "" {
		return &usageError{msg: "sd keys import (trust anchor): --key-pem is required"}
	}
	if *certsPath != "" {
		return &usageError{msg: "sd keys import (trust anchor): --certs is rejected — trust anchors don't get cert chains stored on the card. If you meant an SCP11 SD key import (which DOES store a chain), use --kid 11/13/15. If you meant OCE leaf delivery, use bootstrap-oce."}
	}

	pubKey, ski, skiOrigin, err := loadTrustAnchorMaterial(*keyPemPath, *skiHex)
	if err != nil {
		return &usageError{msg: err.Error()}
	}

	// Public-key fingerprint mirrors the projection Phase 5b uses
	// for SD keys. Computed host-side; populated on the active
	// path only.
	pkFingerprint, err := publicKeySPKIFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("sd keys import (trust anchor): compute SPKI fingerprint: %w", err)
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd keys import", Reader: *reader}
	data := &sdKeysImportData{
		Category:   "ca-trust-anchor",
		KIDHex:     fmt.Sprintf("0x%02X", kid),
		KVNHex:     fmt.Sprintf("0x%02X", kvn),
		ReplaceKVN: replaceKvn,
		SKIHex:     hexEncode(ski),
		SKIOrigin:  skiOrigin,
	}
	report.Data = data

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	if !*confirm {
		var planned string
		switch {
		case replaceKvn != 0:
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install CA trust anchor (P-256 public key) at kid=0x%02X kvn=0x%02X with SKI=%s [%s], REPLACING the existing anchor at KVN=0x%02X.",
				kid, kvn, hexEncode(ski), skiOrigin, replaceKvn)
		default:
			planned = fmt.Sprintf("dry-run; pass --confirm-write to install CA trust anchor (P-256 public key) at kid=0x%02X kvn=0x%02X with SKI=%s [%s] (additive install).",
				kid, kvn, hexEncode(ski), skiOrigin)
		}
		report.Skip("PUT KEY (P-256 public, trust anchor)", planned)
		report.Skip("STORE CA-ISSUER SKI", fmt.Sprintf("dry-run; SKI=%s [%s] ready to register against kid=0x%02X kvn=0x%02X.",
			hexEncode(ski), skiOrigin, kid, kvn))
		data.Channel = "dry-run"
		_ = pkFingerprint // populated only on active path; avoid implying install in dry-run
		return report.Emit(env.out, *jsonMode)
	}

	// Active path.
	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"

	putKeyCheck := fmt.Sprintf("PUT KEY P-256 public (trust anchor) kid=0x%02X kvn=0x%02X", kid, kvn)
	if err := sd.PutECPublicKey(ctx, ref, pubKey, replaceKvn); err != nil {
		report.Fail(putKeyCheck, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: %w", err)
	}
	report.Pass(putKeyCheck, "card commitment verified")
	data.SPKIFingerprintSHA256 = pkFingerprint

	skiCheck := fmt.Sprintf("STORE CA-ISSUER SKI kid=0x%02X kvn=0x%02X", kid, kvn)
	if err := sd.StoreCaIssuer(ctx, ref, ski); err != nil {
		report.Fail(skiCheck, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: register CA SKI (key already installed): %w", err)
	}
	report.Pass(skiCheck, fmt.Sprintf("SKI=%s registered [%s]", hexEncode(ski), skiOrigin))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys import reported failures")
	}
	return nil
}

// isCATrustAnchorKID reports whether a KID is in the CA-public range
// (0x10 OCE, 0x20–0x2F KLCC). Same dispatch boundary as
// importCategoryForKID; defined here as a separate predicate so
// individual handlers can defensively re-check.
func isCATrustAnchorKID(kid byte) bool {
	if kid == securitydomain.KeyIDOCE {
		return true
	}
	return kid >= 0x20 && kid <= 0x2F
}

// loadTrustAnchorMaterial parses --key-pem (cert or bare public key)
// and resolves the SKI per the precedence rules documented on
// cmdSDKeysImportTrustAnchor.
//
// Returns the EC public key, the SKI bytes, and the origin tag
// ("cert-extension" / "computed-sha1-spki" / "explicit-override")
// for audit-log shaping. All three are needed by both dry-run and
// active paths.
//
// Errors are usage-friendly: each cites the offending input by flag
// or path. Operators reading the message know which file or flag
// to fix without having to guess.
func loadTrustAnchorMaterial(keyPemPath, skiHexOverride string) (*ecdsa.PublicKey, []byte, string, error) {
	raw, err := os.ReadFile(keyPemPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read --key-pem %q: %w", keyPemPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, nil, "", fmt.Errorf("--key-pem %q: no PEM block found", keyPemPath)
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("--key-pem %q: parse CERTIFICATE: %w", keyPemPath, err)
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, "", fmt.Errorf("--key-pem %q: certificate public key is not ECDSA (got %T)",
				keyPemPath, cert.PublicKey)
		}
		if pub.Curve.Params().Name != "P-256" {
			return nil, nil, "", fmt.Errorf("--key-pem %q: certificate public key curve is %s, SCP11 trust anchors require P-256",
				keyPemPath, pub.Curve.Params().Name)
		}
		// SKI precedence: explicit override wins, else cert SKI ext,
		// else SHA-1 of SPKI per RFC 5280 §4.2.1.2 method 1.
		// oceCASKI implements paths 2 and 3.
		if skiHexOverride != "" {
			ski, err := parseSKIHex(skiHexOverride)
			if err != nil {
				return nil, nil, "", err
			}
			return pub, ski, "explicit-override", nil
		}
		ski := oceCASKI(cert)
		if len(ski) == 0 {
			return nil, nil, "", fmt.Errorf("--key-pem %q: certificate has no SubjectKeyId extension and no extractable SPKI; pass --ski explicitly",
				keyPemPath)
		}
		// oceCASKI doesn't tell us which path it took, so we
		// determine it here from the cert directly.
		origin := "computed-sha1-spki"
		if len(cert.SubjectKeyId) > 0 {
			origin = "cert-extension"
		}
		return pub, ski, origin, nil

	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("--key-pem %q: parse PUBLIC KEY: %w", keyPemPath, err)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, "", fmt.Errorf("--key-pem %q: public key is not ECDSA (got %T)",
				keyPemPath, k)
		}
		if pub.Curve.Params().Name != "P-256" {
			return nil, nil, "", fmt.Errorf("--key-pem %q: public key curve is %s, SCP11 trust anchors require P-256",
				keyPemPath, pub.Curve.Params().Name)
		}
		if skiHexOverride == "" {
			return nil, nil, "", fmt.Errorf("--key-pem %q: bare PUBLIC KEY (no certificate wrapper); --ski is required because automatic derivation needs the cert's SubjectKeyId extension or SPKI",
				keyPemPath)
		}
		ski, err := parseSKIHex(skiHexOverride)
		if err != nil {
			return nil, nil, "", err
		}
		return pub, ski, "explicit-override", nil

	case "PRIVATE KEY", "EC PRIVATE KEY":
		return nil, nil, "", fmt.Errorf("--key-pem %q: PEM type %q — trust anchor imports take a public key (CERTIFICATE or PUBLIC KEY block), not a private key. Did you mean an SCP11 SD key import (--kid 11/13/15)?",
			keyPemPath, block.Type)

	default:
		return nil, nil, "", fmt.Errorf("--key-pem %q: unsupported PEM type %q (want CERTIFICATE or PUBLIC KEY)",
			keyPemPath, block.Type)
	}
}

// parseSKIHex decodes the --ski flag value, accepting colon-separated
// or contiguous hex. Empty result is a usage error.
func parseSKIHex(s string) ([]byte, error) {
	cleaned := strings.ReplaceAll(s, ":", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("--ski: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--ski: empty value")
	}
	return out, nil
}
