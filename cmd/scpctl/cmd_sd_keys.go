package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// cmdSDKeys dispatches `scpctl sd keys <verb>`.
//
// Phase 1 verbs (read-only; default unauthenticated, opt-in
// SCP03-authenticated via --scp03-* flags):
//
//	list    Inventory of installed key references with optional
//	        certificate summaries. Composes GetKeyInformation,
//	        GetSupportedCaIdentifiers, and GetCertificates.
//	export  Write the certificate chain stored against one key
//	        reference to a file (PEM by default, --der for raw).
//	        Fails by default when the reference has no chain stored;
//	        --allow-empty makes the no-chain case a SKIP at exit 0.
//
// Future verbs follow per docs/design/sd-keys-cli.md:
//
//	delete    Authenticated. Distinct --confirm-delete-key gate.
//	generate  Authenticated. SCP11 SD key on-card generation.
//	import    Authenticated. KID-dispatched key install.
//
// The opinionated bootstrap-* flows stay at the same depth and are
// the recommended path for fresh cards. 'sd keys' commands compose
// the lower-level primitives explicitly for operators who already
// have an established trust path or are inspecting a card.
func cmdSDKeys(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl sd keys <list|export|delete|generate> [flags]"}
	}
	switch args[0] {
	case "list":
		return cmdSDKeysList(ctx, env, args[1:])
	case "export":
		return cmdSDKeysExport(ctx, env, args[1:])
	case "delete":
		return cmdSDKeysDelete(ctx, env, args[1:])
	case "generate":
		return cmdSDKeysGenerate(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(env.out, `scpctl sd keys - Security Domain key inventory and certificate export

Usage:
  scpctl sd keys <verb> [flags]

Verbs:
  list      List installed Security Domain key references with
            optional certificate summaries. Read-only.
  export    Export the certificate chain stored against one key
            reference. PEM by default; --der for raw DER. Read-only.
            Fails when no chain is stored unless --allow-empty.
  delete    Delete one key reference (--kid + --kvn) or all keys at
            a given KVN (--kvn + --all). Authenticated SCP03; gated
            on --confirm-delete-key (NOT --confirm-write). Dry-run
            by default.
  generate  Generate an on-card EC P-256 key at one SCP11 SD slot
            (--kid 11/13/15). The private key never crosses the
            wire; the SPKI is written to --out as a PEM PUBLIC KEY
            block. Authenticated SCP03; gated on --confirm-write.
            Dry-run by default. Uses Yubico extension INS=0xF1.

Use "scpctl sd keys <verb> -h" for per-verb flags.
`)
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown keys subcommand %q", args[0])}
}

// sdKeysListData is the JSON-friendly payload of `sd keys list`.
//
// One entry per Key Information Template (KIT) row returned by the
// card. Certificates and CA SKIs are folded in by KID/KVN match so
// JSON consumers can iterate one collection and see everything they
// need about each reference. No private material appears in any
// field — KCV/SPKI fingerprints only.
//
// Channel reports the wire mode used for the underlying reads:
// "unauthenticated" or "scp03". The opt-in auth fallback (--scp03-*)
// surfaces here so audit logs can distinguish the two paths.
type sdKeysListData struct {
	Channel string       `json:"channel"`
	Keys    []sdKeyEntry `json:"keys"`
}

// sdKeyEntry describes one installed key reference.
//
// KID/KVN are emitted as both numeric (for machine consumers that
// want to do arithmetic / comparison) and hex-formatted (for human
// log inspection). 'Kind' is a host-side classification from KID per
// GP §7.1.1 and Yubico's KeyReference convention; cards that install
// references at non-canonical KIDs render as "unknown" and the raw
// KID is still authoritative.
type sdKeyEntry struct {
	KID        byte             `json:"kid"`
	KVN        byte             `json:"kvn"`
	KIDHex     string           `json:"kid_hex"`
	KVNHex     string           `json:"kvn_hex"`
	Kind       string           `json:"kind"`
	Components []sdKeyComponent `json:"components,omitempty"`

	// CASKI is the Subject Key Identifier registered against this
	// reference via STORE DATA (KLOC/KLCC). Populated for OCE / CA
	// public-key references on cards that report the SKI through
	// GET DATA tags 0xFF33 / 0xFF34.
	CASKI string `json:"ca_ski,omitempty"`

	// Certificates is the chain stored against this reference via
	// STORE DATA (cert store). Empty (omitted) when no chain is
	// stored, as is normal for SCP03 references and for SCP11
	// references that use bare-key trust rather than chain trust.
	Certificates []sdKeyCertView `json:"certificates,omitempty"`
}

// sdKeyComponent is one row of the GP Key Information Template, the
// raw "this key reference has component-id X of type Y" advertisement
// the card returns. Component IDs and types are defined in GP §11.3.4
// Table 11-29; rendering them is consumer-side, this view only carries
// the bytes the card sent so we don't lie if the card returns a value
// the host doesn't understand yet.
type sdKeyComponent struct {
	ID   byte `json:"id"`
	Type byte `json:"type"`
}

// sdKeyCertView is the JSON projection of one stored certificate.
//
// Subject is the canonical RFC 4514 string. SPKIFingerprintSHA256 is
// the SHA-256 over the raw SubjectPublicKeyInfo DER, rendered as
// uppercase hex without separators — the same fingerprint shape Chrome
// / Mozilla certificate viewers use, and the format Yubico's tools
// emit for SD cert summaries. NotBefore / NotAfter use RFC 3339 so
// JSON consumers can parse them with stdlib time.Parse.
type sdKeyCertView struct {
	Subject               string `json:"subject"`
	Issuer                string `json:"issuer,omitempty"`
	NotBefore             string `json:"not_before,omitempty"`
	NotAfter              string `json:"not_after,omitempty"`
	SPKIFingerprintSHA256 string `json:"spki_fingerprint_sha256,omitempty"`
	SerialHex             string `json:"serial_hex,omitempty"`
}

// cmdSDKeysList reports a key-centric inventory of the card. Three
// GET DATA call patterns per the GP card-management profile:
//
//   - tag 0x00E0 (Key Information Template): KID/KVN + component map
//     for every installed key reference. Mandatory; failure is FAIL
//     because the inventory is the whole point of this command.
//   - tags 0xFF33 (KLOC) and 0xFF34 (KLCC): SKIs registered against
//     OCE / CA public-key references. Optional; cards with no CA
//     identifiers set return SW=6A88 and we surface that as a SKIP
//     line, not a FAIL.
//   - tag 0xBF21 (cert store) per key reference: any certificate
//     chain stored against that reference. Per-reference; a 6A88
//     means "no chain stored for this ref" and is reported as a SKIP
//     for that reference only, not a command-level failure.
//
// Channel selection: by default opens an unauthenticated session. If
// any --scp03-* flag is set, opens an SCP03-authenticated session.
// Auth failure is FAIL (not SKIP) because the operator explicitly
// asked for auth and the card rejected it.
//
// 'sd keys list' is the key-centric peer to 'sd info'. Where 'sd
// info' answers "what kind of card is this and what's it advertising
// at the GP layer," 'sd keys list' answers "which key references
// does it have installed and what's stored against them."
func cmdSDKeysList(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys list", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	scp03Flags := registerSCP03KeyFlags(fs, scp03Optional)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "sd keys list", Reader: *reader}

	sd, channel, err := openSDForRead(ctx, t, scp03Flags, report)
	if err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sd.Close()

	// Step 1: Key Information Template. Without this we have no
	// inventory to report against, so a fetch failure is FAIL.
	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		report.Fail("GET DATA tag 0x00E0 (KIT)", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("get key information: %w", err)
	}
	if len(keys) == 0 {
		report.Skip("GET DATA tag 0x00E0 (KIT)", "card returned no key entries")
		report.Data = &sdKeysListData{Channel: channel, Keys: []sdKeyEntry{}}
		return report.Emit(env.out, *jsonMode)
	}
	report.Pass("GET DATA tag 0x00E0 (KIT)", fmt.Sprintf("%d entries", len(keys)))

	// Step 2: KLOC + KLCC SKIs. Optional. parseSupportedCaIdentifiers
	// returns an empty slice on SW=6A88 or empty data, so a nil error
	// with an empty result means "card has no CA identifiers"; we
	// surface that as a SKIP so operators see the absence in logs.
	allCAs, err := sd.GetSupportedCaIdentifiers(ctx, true, true)
	switch {
	case err != nil:
		report.Skip("GET DATA tags 0xFF33/0xFF34 (KLOC/KLCC)", err.Error())
	case len(allCAs) == 0:
		report.Skip("GET DATA tags 0xFF33/0xFF34 (KLOC/KLCC)",
			"no CA identifiers registered")
	default:
		report.Pass("GET DATA tags 0xFF33/0xFF34 (KLOC/KLCC)",
			fmt.Sprintf("%d CA identifier(s)", len(allCAs)))
	}

	caByRef := make(map[securitydomain.KeyReference][]byte, len(allCAs))
	for _, ca := range allCAs {
		caByRef[ca.Reference] = ca.SKI
	}

	// Step 3: per-reference cert chain. One GET DATA per entry; this
	// is O(KIT entries) APDUs, which is bounded (real cards typically
	// have 3-5 entries and never more than a dozen). Per-ref errors
	// are folded into the Checks stream as SKIP so a card that has a
	// chain on some refs but not others still produces a complete
	// inventory.
	data := &sdKeysListData{Channel: channel, Keys: make([]sdKeyEntry, 0, len(keys))}

	// Stable order: sort by KID then KVN. The KIT response order is
	// card-defined and not guaranteed; deterministic output makes
	// JSON goldens reviewable and operator log diffs meaningful.
	sortedKeys := make([]securitydomain.KeyInfo, len(keys))
	copy(sortedKeys, keys)
	sort.Slice(sortedKeys, func(i, j int) bool {
		a, b := sortedKeys[i].Reference, sortedKeys[j].Reference
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Version < b.Version
	})

	for _, ki := range sortedKeys {
		entry := sdKeyEntry{
			KID:        ki.Reference.ID,
			KVN:        ki.Reference.Version,
			KIDHex:     fmt.Sprintf("0x%02X", ki.Reference.ID),
			KVNHex:     fmt.Sprintf("0x%02X", ki.Reference.Version),
			Kind:       classifyKID(ki.Reference.ID),
			Components: projectComponents(ki.Components),
		}
		if ski, ok := caByRef[ki.Reference]; ok && len(ski) > 0 {
			entry.CASKI = hexEncode(ski)
		}

		// Selective cert fetch. SCP03 references never have a
		// stored certificate chain (they're symmetric key sets),
		// so issuing a 0xBF21 GET DATA against KID=0x01 is wasted
		// APDU traffic that always returns SW=6A88. Match ykman's
		// convention: only fetch certs for cert-capable kinds
		// (SCP11 SD refs, OCE/CA public-key refs, and unknown
		// non-canonical KIDs where the operator is explicitly
		// inspecting an unfamiliar card).
		checkName := fmt.Sprintf("certificates kid=0x%02X kvn=0x%02X",
			ki.Reference.ID, ki.Reference.Version)
		if entry.Kind == "scp03" {
			report.Skip(checkName, "scp03 ref (no chain expected)")
			data.Keys = append(data.Keys, entry)
			continue
		}

		// Library returns (nil, nil) for SW=6A88 (no chain stored),
		// which is the common case for SCP11 references that use
		// bare-key trust rather than chain trust.
		certs, err := sd.GetCertificates(ctx, ki.Reference)
		switch {
		case err != nil:
			report.Skip(checkName, err.Error())
		case len(certs) == 0:
			report.Skip(checkName, "no chain stored")
		default:
			report.Pass(checkName, fmt.Sprintf("%d entries", len(certs)))
			entry.Certificates = projectCertChain(certs)
		}

		data.Keys = append(data.Keys, entry)
	}

	report.Data = data
	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys list reported failures")
	}
	return nil
}

// sdKeysExportData is the JSON-friendly payload of `sd keys export`.
//
// Both the certificate summary view and the on-disk path are reported
// so JSON consumers can record provenance without re-reading the file.
// When --out is empty, OutPath is empty and the PEM/DER bytes were
// written to stdout as part of the report's text-mode rendering.
type sdKeysExportData struct {
	Channel      string          `json:"channel"`
	KIDHex       string          `json:"kid_hex"`
	KVNHex       string          `json:"kvn_hex"`
	Format       string          `json:"format"` // "pem" or "der"
	OutPath      string          `json:"out_path,omitempty"`
	Certificates []sdKeyCertView `json:"certificates"`
}

// cmdSDKeysExport writes the certificate chain stored against one
// key reference. One GET DATA call (tag 0xBF21, cert store, P1P2
// keyed by reference TLV).
//
// No-chain semantics:
//
//   - Default: when the card returns SW=6A88 (no chain stored for
//     this reference) the command FAILs with exit 1 and writes no
//     output file. An automation that named a specific reference
//     and asked for its chain must not silently proceed as if it
//     had received material.
//   - --allow-empty: the same condition becomes a SKIP at exit 0
//     with JSON-visible "certificates": []. For inventory-walk
//     scripts that iterate references and skip ones with no chain.
//
// Channel selection mirrors `sd keys list`: default unauthenticated,
// opt-in SCP03 via --scp03-* flags. Auth failure is FAIL.
//
// Output formats:
//
//   - PEM (default): one PEM block per certificate, leaf last,
//     concatenated in the order the card returned them.
//   - DER (--der):   raw concatenated DER. Useful when piping into
//     'openssl x509 -inform DER -text' or feeding a downstream
//     parser that expects bare DER.
//
// When --out is unspecified, output goes to stdout. JSON-mode runs
// must specify --out; mixing the binary cert bytes with the JSON
// report on the same stream would produce unparseable output.
func cmdSDKeysExport(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys export", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output (requires --out).")
	kidStr := fs.String("kid", "",
		"Key ID to export, hex byte (e.g. 01, 11, FF). Required.")
	kvnStr := fs.String("kvn", "",
		"Key Version Number, hex byte (e.g. 01, FF). Required.")
	outPath := fs.String("out", "",
		"Output file path. When unspecified, write certificates to stdout.")
	derMode := fs.Bool("der", false,
		"Emit raw concatenated DER instead of PEM.")
	allowEmpty := fs.Bool("allow-empty", false,
		"When the reference has no chain stored, exit 0 with a SKIP "+
			"check (default behavior is FAIL exit 1). For inventory-walk "+
			"scripts that iterate references and tolerate empties.")
	scp03Flags := registerSCP03KeyFlags(fs, scp03Optional)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd keys export requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	kvn, err := parseHexByte(*kvnStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kvn: %v", err)}
	}
	if *jsonMode && *outPath == "" {
		return &usageError{msg: "--json requires --out (cannot mix JSON report and binary cert bytes on stdout)"}
	}

	ref := securitydomain.NewKeyReference(kid, kvn)

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "sd keys export", Reader: *reader}

	sd, channel, err := openSDForRead(ctx, t, scp03Flags, report)
	if err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sd.Close()

	checkName := fmt.Sprintf("GET DATA tag 0xBF21 kid=0x%02X kvn=0x%02X", kid, kvn)
	certs, err := sd.GetCertificates(ctx, ref)
	if err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("get certificates: %w", err)
	}

	data := &sdKeysExportData{
		Channel: channel,
		KIDHex:  fmt.Sprintf("0x%02X", kid),
		KVNHex:  fmt.Sprintf("0x%02X", kvn),
		Format:  formatLabel(*derMode),
	}

	if len(certs) == 0 {
		// Two distinct conditions get two distinct check lines: the
		// GET DATA call succeeded (zero entries returned), and the
		// "chain present" check is the operator-meaningful condition
		// that --allow-empty toggles between FAIL and SKIP.
		report.Pass(checkName, "0 entries")
		data.Certificates = []sdKeyCertView{}
		report.Data = data

		if *allowEmpty {
			report.Skip("chain present",
				"no chain stored for this reference (--allow-empty: exit 0)")
			return report.Emit(env.out, *jsonMode)
		}

		report.Fail("chain present",
			"no chain stored for this reference (use --allow-empty for exit 0)")
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("no certificate chain stored for kid=0x%02X kvn=0x%02X", kid, kvn)
	}
	report.Pass(checkName, fmt.Sprintf("%d entries", len(certs)))
	report.Pass("chain present", "")

	body, err := encodeChain(certs, *derMode)
	if err != nil {
		report.Fail("encode chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("encode chain: %w", err)
	}
	data.Certificates = projectCertChain(certs)

	if *outPath != "" {
		// Atomic write: create a sibling temp file, sync, close,
		// rename into place. A failure between create and rename
		// leaves only the temp file behind (cleaned up); the final
		// path is never partially populated. This matters for
		// automation that uses the existence of the output file as
		// the success signal — a partial PEM/DER file would be
		// silently consumed and then fail downstream parsing far
		// from the cause.
		if err := writeFileAtomic(*outPath, body, 0o644); err != nil {
			report.Fail("write file", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("write %s: %w", *outPath, err)
		}
		report.Pass("write file", fmt.Sprintf("%s (%d bytes)", *outPath, len(body)))
		data.OutPath = *outPath
		report.Data = data
		return report.Emit(env.out, *jsonMode)
	}

	// stdout path. Text-mode only (we rejected --json + no --out
	// above). Emit the report header first so the operator knows
	// which reference and format the bytes correspond to, then the
	// body. PEM is text and round-trips fine; DER is binary and
	// the operator should redirect to a file or pipe.
	report.Data = data
	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if _, err := env.out.Write(body); err != nil {
		return fmt.Errorf("write to stdout: %w", err)
	}
	return nil
}

// openSDForRead is the shared open helper for read-only `sd keys`
// commands. It implements the design's authentication model:
//
//   - When no SCP03 auth flag is set, opens an unauthenticated SD
//     session (the YubiKey-friendly default).
//   - When any --scp03-* flag is set, opens an SCP03-authenticated
//     session using the supplied (or factory) keys.
//
// The returned channel string is "unauthenticated" or "scp03" and is
// recorded on the Data block of the report so audit logs can
// distinguish the two paths. Auth failures are FAIL on the report
// (the operator explicitly opted into auth and the card rejected) and
// are returned wrapped so the caller can propagate after emitting.
//
// Adding SCP11a fallback later means adding a parallel branch keyed
// off SCP11a flag presence; the public signature stays.
func openSDForRead(
	ctx context.Context,
	t transport.Transport,
	scp03Flags *scp03KeyFlags,
	report *Report,
) (*securitydomain.Session, string, error) {
	cfg, err := scp03Flags.applyToConfigOptional()
	if err != nil {
		report.Fail("parse SCP03 flags", err.Error())
		return nil, "", err
	}

	if cfg != nil {
		report.Pass("SCP03 keys", scp03Flags.describeKeys(cfg))
		sd, err := securitydomain.OpenSCP03(ctx, t, cfg)
		if err != nil {
			report.Fail("open SCP03 session", err.Error())
			return nil, "", fmt.Errorf("open SCP03: %w", err)
		}
		report.Pass("open SCP03 session", "")
		return sd, "scp03", nil
	}

	sd, err := securitydomain.OpenUnauthenticated(ctx, t)
	if err != nil {
		report.Fail("select ISD", err.Error())
		return nil, "", fmt.Errorf("select ISD: %w", err)
	}
	report.Pass("select ISD", "")
	return sd, "unauthenticated", nil
}

// writeFileAtomic writes data to path via a sibling temp file and a
// rename, so a failure mid-write never leaves a partial file at the
// final path. The temp file is created in the same directory as the
// target so the rename is atomic on POSIX filesystems (same-volume
// constraint). On any error after the temp file is created, the
// temp file is removed before returning.
//
// Mode is applied to the temp file before the rename so the final
// file lands with the requested permissions in one step.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".scpctl-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename to final path: %w", err)
	}
	return nil
}

// classifyKID maps a Key ID byte to a human-readable kind label per
// GP §7.1.1 and Yubico's KeyReference convention. Unknown KIDs render
// as "unknown" rather than guessing — the raw KID is still in the
// JSON output as the authoritative value. The KLOC/KLCC range covers
// both the canonical 0x10 and the 0x20–0x2F extension Yubico uses for
// additional CA references.
func classifyKID(kid byte) string {
	switch {
	case kid == securitydomain.KeyIDSCP03:
		return "scp03"
	case kid == securitydomain.KeyIDOCE, kid >= 0x20 && kid <= 0x2F:
		return "ca-public"
	case kid == securitydomain.KeyIDSCP11a:
		return "scp11a-sd"
	case kid == securitydomain.KeyIDSCP11b:
		return "scp11b-sd"
	case kid == securitydomain.KeyIDSCP11c:
		return "scp11c-sd"
	default:
		return "unknown"
	}
}

// projectComponents converts the KeyInfo component map (raw card
// bytes) to the sorted, JSON-friendly slice form. Sorting by ID makes
// the output deterministic regardless of map iteration order.
func projectComponents(m map[byte]byte) []sdKeyComponent {
	if len(m) == 0 {
		return nil
	}
	out := make([]sdKeyComponent, 0, len(m))
	for id, t := range m {
		out = append(out, sdKeyComponent{ID: id, Type: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// projectCertChain converts a slice of parsed x509.Certificate values
// to the JSON-friendly view. The leaf is last in both the input and
// the output (the library contract from GetCertificates).
//
// SPKI fingerprint is SHA-256 over the SubjectPublicKeyInfo DER, the
// same digest viewers like Chrome and Firefox display. Computing it
// here rather than emitting raw SPKI bytes keeps the output a
// fixed-size identifier that's easy to grep and cross-reference.
func projectCertChain(certs []*x509.Certificate) []sdKeyCertView {
	if len(certs) == 0 {
		return nil
	}
	views := make([]sdKeyCertView, 0, len(certs))
	for _, c := range certs {
		v := sdKeyCertView{
			Subject:               c.Subject.String(),
			Issuer:                c.Issuer.String(),
			NotBefore:             c.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
			NotAfter:              c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			SPKIFingerprintSHA256: spkiFingerprint(c),
		}
		if c.SerialNumber != nil {
			v.SerialHex = strings.ToUpper(c.SerialNumber.Text(16))
		}
		views = append(views, v)
	}
	return views
}

// spkiFingerprint returns SHA-256 over the certificate's raw
// SubjectPublicKeyInfo DER, uppercase hex without separators. This
// is the format Chrome's certificate viewer labels "Public Key SHA-256"
// and the form Yubico's tools emit for SD cert summaries.
func spkiFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hexEncode(sum[:])
}

// encodeChain serializes a chain to PEM (the default) or raw
// concatenated DER (--der). The leaf is last in the input slice; the
// output preserves that order, so consumers reading the file get the
// chain in card-storage order.
func encodeChain(certs []*x509.Certificate, der bool) ([]byte, error) {
	if der {
		var out []byte
		for _, c := range certs {
			out = append(out, c.Raw...)
		}
		return out, nil
	}
	var buf strings.Builder
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return nil, err
		}
	}
	return []byte(buf.String()), nil
}

// formatLabel returns the JSON-friendly format string for the
// --der flag state.
func formatLabel(der bool) string {
	if der {
		return "der"
	}
	return "pem"
}
