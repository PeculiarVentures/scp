package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

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
	Profile    string `json:"profile,omitempty"`
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
	// SubjectKeyId), "computed-rfc5280-method1" (cert lacked the
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
