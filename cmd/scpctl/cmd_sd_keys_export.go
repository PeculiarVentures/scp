package main

// `scpctl sd keys export` — write the certificate chain stored
// against one SCP11 key reference to a file (PEM by default,
// --der for raw concatenated DER).
//
// Composes GetCertificates against the (KID, KVN) selected by
// --kid / --kvn. Default channel is unauthenticated — the BF21
// GET DATA read against a stored cert chain doesn't require an
// SCP session against YubiKey-shaped firmware. --scp03-* flags
// opt into authenticated reads when the card requires them.
//
// Chain ordering: cards may return chains in either leaf-first
// or leaf-last order. The --chain-order flag selects which
// shape the operator wants the file to carry. "as-stored"
// (default) preserves whatever the card returned;
// "leaf-last" / "leaf-first" reorder using SubjectKeyIdentifier
// linkage when present, falling back to issuer/subject DN
// matching otherwise.
//
// Split from cmd_sd_keys.go because the export path's flag
// surface, JSON projection (sdKeysExportData), and chain
// manipulation helpers (encodeChain, formatLabel, reorderChain,
// findLeafIndex) are independent of the list branch and the
// shared helpers. Keeping the export path and its private
// chain-manipulation code in one file makes the "all
// export-specific code" surface auditable in isolation.
//
// The dispatcher in cmd_sd_keys.go routes here on
// args[0] == "export".
//
// Helpers in this file used only by this branch:
//
//   encodeChain     PEM/DER serialization
//   formatLabel     JSON-friendly format string
//   reorderChain    --chain-order application
//   findLeafIndex   leaf detection by SKI/issuer matching

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// sdKeysExportData is the JSON-friendly payload of `sd keys export`.
//
// Both the certificate summary view and the on-disk path are reported
// so JSON consumers can record provenance without re-reading the file.
// When --out is empty, OutPath is empty and the PEM/DER bytes were
// written to stdout as part of the report's text-mode rendering.
type sdKeysExportData struct {
	Channel      string          `json:"channel"`
	Profile      string          `json:"profile,omitempty"`
	KIDHex       string          `json:"kid_hex"`
	KVNHex       string          `json:"kvn_hex"`
	Format       string          `json:"format"` // "pem" or "der"
	OutPath      string          `json:"out_path,omitempty"`
	ChainOrder   string          `json:"chain_order"` // "as-stored", "leaf-last", "leaf-first"
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
	chainOrder := fs.String("chain-order", "as-stored",
		"Order in which certificates appear in the output: 'as-stored' "+
			"(default; preserves the on-card storage order, which is "+
			"leaf-last for cards that follow GP §11.1.3 and ykman/yubikit "+
			"convention), 'leaf-last' (force leaf at the end regardless of "+
			"storage order — same as as-stored on conforming cards but "+
			"defensive against malformed cards), or 'leaf-first' (reverse "+
			"to leaf-at-start; useful for tooling that expects PEM bundles "+
			"in that order). Determining 'leaf' relies on the standard "+
			"signature-verifies-with-issuer-key relationship; if no leaf "+
			"can be unambiguously identified the export errors instead of "+
			"silently choosing.")
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

	switch *chainOrder {
	case "as-stored", "leaf-last", "leaf-first":
		// valid
	default:
		return &usageError{msg: fmt.Sprintf("--chain-order: %q not recognized; valid values are as-stored, leaf-last, leaf-first", *chainOrder)}
	}

	ref := securitydomain.NewKeyReference(kid, kvn)

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "sd keys export", Reader: *reader}

	sd, channel, profName, err := openSDForRead(ctx, t, scp03Flags, report)
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
		Profile: profName,
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

	orderedCerts, err := reorderChain(certs, *chainOrder)
	if err != nil {
		report.Fail("apply --chain-order", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("apply --chain-order: %w", err)
	}
	if *chainOrder != "as-stored" {
		report.Pass("apply --chain-order", *chainOrder)
	}

	body, err := encodeChain(orderedCerts, *derMode)
	if err != nil {
		report.Fail("encode chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("encode chain: %w", err)
	}
	data.Certificates = projectCertChain(orderedCerts)
	data.ChainOrder = *chainOrder

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

// reorderChain applies the --chain-order flag's selected ordering
// to the chain just fetched from the card.
//
// Order semantics:
//
//   - "as-stored": no-op. Cards that follow GP §11.1.3 store
//     leaf-last; the library's GetCertificates documents the
//     same; ykman/yubikit expects leaf-last; this is the default
//     because it's also the most-likely-correct.
//
//   - "leaf-last": detect the leaf via signature relationships,
//     reorder to put it at the end. On a conforming card this
//     is identical to as-stored; on a malformed card (cert order
//     scrambled at write time, or read shuffled by some applet)
//     this is defensive.
//
//   - "leaf-first": detect the leaf, place it first, then issuers
//     in chain order. Useful for tooling that consumes PEM
//     bundles in that direction.
//
// Leaf detection: walk the chain, find the cert that is NOT
// the issuer of any other cert in the chain. That's the leaf.
// If multiple candidates exist (chain has unrelated certs) or
// none can be identified (single-cert chains, or cyclic refs),
// the function returns an error rather than silently picking —
// the operator asked for a specific order and we can't guess.
//
// Single-cert chains are trivial: any order is leaf-first AND
// leaf-last simultaneously. Returns the input unchanged.
func reorderChain(certs []*x509.Certificate, order string) ([]*x509.Certificate, error) {
	if len(certs) <= 1 || order == "as-stored" {
		return certs, nil
	}

	leafIdx, err := findLeafIndex(certs)
	if err != nil {
		return nil, err
	}

	switch order {
	case "leaf-last":
		out := make([]*x509.Certificate, 0, len(certs))
		for i, c := range certs {
			if i == leafIdx {
				continue
			}
			out = append(out, c)
		}
		out = append(out, certs[leafIdx])
		return out, nil
	case "leaf-first":
		// "Leaf-first" is semantically the reverse of "leaf-last":
		// the chain is presented in validation order (leaf, then
		// its direct issuer, then that issuer's issuer, ..., root).
		// Easiest correct implementation: produce the leaf-last
		// ordering and reverse it. Without this reversal, the leaf
		// goes to position 0 but the rest stays in input order,
		// producing e.g. [leaf, root, intermediate] from a leaf-last
		// input — which is neither the input order nor a valid
		// leaf-first chain.
		leafLast, err := reorderChain(certs, "leaf-last")
		if err != nil {
			return nil, err
		}
		out := make([]*x509.Certificate, len(leafLast))
		for i, c := range leafLast {
			out[len(leafLast)-1-i] = c
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown --chain-order %q (validated upstream — this is a bug)", order)
	}
}

// findLeafIndex returns the index of the leaf cert in chain. The
// leaf is the cert whose Subject is NOT the Issuer of any other
// cert in the chain. Returns an error if no leaf or multiple
// leaves can be unambiguously identified.
func findLeafIndex(certs []*x509.Certificate) (int, error) {
	// Build set of all Issuer DNs.
	issuerSet := make(map[string]struct{}, len(certs))
	for _, c := range certs {
		issuerSet[string(c.RawIssuer)] = struct{}{}
	}
	var candidates []int
	for i, c := range certs {
		// A cert is a leaf candidate if no other cert in the chain
		// names this cert's Subject as Issuer (i.e., this cert
		// signed nothing else in the chain).
		signedSomethingElse := false
		for j, other := range certs {
			if i == j {
				continue
			}
			if string(other.RawIssuer) == string(c.RawSubject) {
				signedSomethingElse = true
				break
			}
		}
		if !signedSomethingElse {
			candidates = append(candidates, i)
		}
		_ = issuerSet // reserved for future cycle detection
	}
	switch len(candidates) {
	case 0:
		return 0, fmt.Errorf("no leaf in chain (every cert is an issuer of another — possible cycle)")
	case 1:
		return candidates[0], nil
	default:
		return 0, fmt.Errorf("ambiguous leaf in chain (%d candidates — chain may be malformed or contain unrelated certs)", len(candidates))
	}
}
