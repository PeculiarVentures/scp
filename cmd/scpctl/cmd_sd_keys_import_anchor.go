package main

// Trust-anchor import branch of `scpctl sd keys import`.
//
// Installs an OCE / CA public key as a trust anchor at one of the
// CA-public KIDs (0x10 OCE, 0x20-0x2F KLCC range) and registers
// its Subject Key Identifier. Composes Session.PutECPublicKey
// + Session.StoreCaIssuer.
//
// Trust-anchor semantics differ from SD-key semantics: chains
// are NOT stored against trust-anchor refs (the card uses
// anchors to VALIDATE other certs during SCP11 PSO; the chain
// belongs to the SD-key category). --certs is rejected here
// with a usage error rather than silently no-op'd.
//
// Split from cmd_sd_keys_import.go because the trust-anchor
// branch has its own dedicated flag surface (--key-pem accepts
// either CERTIFICATE or PUBLIC KEY blocks; --ski has its own
// derivation precedence rules) and helper functions (PEM
// loading with cert/pubkey discrimination, SKI hex parsing).
// Keeping the branch and its private helpers in one file
// makes the "all trust-anchor-specific code" surface
// auditable in isolation — particularly important for the
// SKI derivation logic, which is the locus of the PR #90
// bug class.
//
// The dispatcher in cmd_sd_keys_import.go routes into this
// file based on importCategoryForKID(kid)=="ca-trust-anchor".
//
// Helpers in this file used only by this branch:
//
//   isCATrustAnchorKID       category gate for the dispatcher
//   loadTrustAnchorMaterial  PEM loader (cert OR bare pubkey)
//                            with SKI derivation
//   parseSKIHex              --ski flag value parser

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

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
// ("cert-extension" / "computed-rfc5280-method1" / "explicit-override")
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
		origin := "computed-rfc5280-method1"
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
