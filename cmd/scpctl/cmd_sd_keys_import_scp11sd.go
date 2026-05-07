package main

// SCP11 SD key-import branch of `scpctl sd keys import`.
//
// Imports an SCP11 endpoint private key (and optionally a
// certificate chain) at one of the three SCP11 authentication
// slots:
//
//   KID 0x11   SCP11a — mutual auth, OCE certificate verified by card
//   KID 0x13   SCP11b — card-only auth, no OCE cert required
//   KID 0x15   SCP11c — same shape as 11a, distinct slot
//
// These are the ONLY KIDs this branch handles. The dispatcher in
// cmd_sd_keys_import.go enforces the invariant via
// importCategoryForKID:
//
//   0x01                  -> scp03-key-set     (cmd_sd_keys_import_scp03.go)
//   0x11 / 0x13 / 0x15    -> scp11-sd-key      (this file)
//   0x10, 0x20-0x2F       -> ca-trust-anchor   (cmd_sd_keys_import_anchor.go)
//
// 0x10 (PK.CA-KLOC.ECDSA) and 0x20-0x2F (KLCC range) are CA/OCE
// public-key trust anchors, NOT private-key import targets — they
// route to a different branch with a different flag surface and
// security model. An earlier revision of this file's header
// listed them here as "SCP11 management slots"; that was wrong
// and has been corrected. The runtime guard
// (cmdSDKeysImportSCP11SD itself) only accepts 0x11/0x13/0x15
// and rejects anything else as a usage error before any APDU
// goes out.
//
// Composes Session.PutECPrivateKey (always) and
// Session.StoreCertificates (only when --certs supplied). Both
// run inside an SCP03-authenticated session — SCP11 imports
// require the session DEK because the private key is encrypted
// before transmission, and DEK is an SCP03 session output.
//
// Split from cmd_sd_keys_import.go because the SCP11-SD branch
// has its own dedicated flag surface (--key-pem, --certs) and
// helper functions (PEM loading, leaf-vs-key match check) that
// don't apply to SCP03 imports or trust-anchor imports. Keeping
// the branch and its private helpers in one file makes the
// "all SCP11-SD-specific code" surface auditable in isolation.
//
// Helpers in this file used only by this branch:
//
//   loadSDPrivateKey            PEM private-key loader (PKCS#8 / SEC1)
//   loadSDCertChain             PEM bundle loader for the cert chain
//   verifyLeafMatchesPrivateKey anti-typo SPKI match check

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/securitydomain"
)

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
	sd, profName, err := openSCP03WithProfile(ctx, t, scp03Cfg, scp03Keys, report)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys import: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"
	data.Profile = profName

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
