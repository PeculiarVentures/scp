package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
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
		return &usageError{msg: "scpctl sd keys <list|export|delete|generate|import> [flags]"}
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
	case "import":
		return cmdSDKeysImport(ctx, env, args[1:])
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
  import    Install a key set, private key, or trust anchor at one
            key reference, dispatched by KID. Supports SCP03 AES-128
            (--kid 01), SCP11 SD private key with optional cert chain
            (--kid 11/13/15), and CA/OCE trust anchor with SKI registration
            (--kid 10/20-2F). Authenticated SCP03; gated on
            --confirm-write. Dry-run by default.

Use "scpctl sd keys <verb> -h" for per-verb flags.
`)
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown keys subcommand %q", args[0])}
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
//
// Returns: (session, channel-label, profile-name, error). The
// channel-label is "scp03" or "unauthenticated"; the profile-name
// is the resolved profile via resolveProfile (e.g. "yubikey-sd",
// "standard-sd"). Both fields are passed through to the JSON
// output so audit logs across deployments are unambiguous.
func openSDForRead(
	ctx context.Context,
	t transport.Transport,
	scp03Flags *scp03KeyFlags,
	sdAID []byte,
	report *Report,
) (*securitydomain.Session, string, string, error) {
	cfg, err := scp03Flags.applyToConfigOptional()
	if err != nil {
		report.Fail("parse SCP03 flags", err.Error())
		return nil, "", "", err
	}

	prof, profName := resolveProfile(ctx, t, scp03Flags, sdAID, report)

	if cfg != nil {
		report.Pass("SCP03 keys", scp03Flags.describeKeys(cfg))
		sd, err := securitydomain.OpenSCP03WithAID(ctx, t, cfg, sdAID)
		if err != nil {
			report.Fail("open SCP03 session", err.Error())
			return nil, "", profName, fmt.Errorf("open SCP03: %w", err)
		}
		sd.SetProfile(prof)
		report.Pass("open SCP03 session", "")
		return sd, "scp03", profName, nil
	}

	sd, err := securitydomain.OpenUnauthenticatedWithAID(ctx, t, sdAID)
	if err != nil {
		report.Fail("select ISD", err.Error())
		return nil, "", profName, fmt.Errorf("select ISD: %w", err)
	}
	sd.SetProfile(prof)
	report.Pass("select ISD", "")
	return sd, "unauthenticated", profName, nil
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
//
// profileName selects the labeling convention:
//
//   - "yubikey-sd" or "auto": KIDs 0x11/0x13/0x15 are labeled
//     scp11a-sd/scp11b-sd/scp11c-sd per Yubico's KeyReference
//     namespace. This is the common case and matches what
//     ykman/yubikit print. ("auto" labels as YubiKey because if
//     auto-resolution lands on Standard at runtime, the JSON's
//     active_profile field is the authoritative signal of which
//     KID conventions apply; the kind label is human convenience.)
//   - "standard-sd": those same KIDs are labeled "scp11-sd" without
//     the variant letter, because standard GP cards don't promise
//     that KID 0x11 maps to SCP11a specifically — that's a Yubico
//     convention. The raw KID is preserved in the JSON's kid_hex
//     field as the authoritative value.
//
// SCP03 (KID=0x01) and the OCE/CA-public range are GP-spec
// conventions, not Yubico-specific, so their labels don't depend
// on the profile.
func classifyKID(kid byte, profileName string) string {
	switch {
	case kid == securitydomain.KeyIDSCP03:
		return "scp03"
	case kid == securitydomain.KeyIDOCE, kid >= 0x20 && kid <= 0x2F:
		return "ca-public"
	case kid == securitydomain.KeyIDSCP11a, kid == securitydomain.KeyIDSCP11b, kid == securitydomain.KeyIDSCP11c:
		if profileName == "standard-sd" {
			return "scp11-sd"
		}
		switch kid {
		case securitydomain.KeyIDSCP11a:
			return "scp11a-sd"
		case securitydomain.KeyIDSCP11b:
			return "scp11b-sd"
		case securitydomain.KeyIDSCP11c:
			return "scp11c-sd"
		}
		return "scp11-sd"
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
