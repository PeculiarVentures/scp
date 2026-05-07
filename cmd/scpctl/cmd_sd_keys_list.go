package main

// `scpctl sd keys list` — read-only inventory of installed key
// references on a security domain.
//
// Composes GetKeyInformation (E0 template), GetSupportedCaIdentifiers
// (KLOC + KLCC SKI maps), and GetCertificates (per-ref BF21 chains)
// into a single key-centric report. Each row in the output corresponds
// to a Key Information Template entry returned by the card; cert
// chains and CA SKIs are folded in by KID/KVN match so a JSON consumer
// iterates one collection and sees everything that belongs to that
// key reference.
//
// Default channel is unauthenticated — these GET DATA reads don't
// require an SCP session against YubiKey-shaped firmware. The
// --scp03-* flag set opts into SCP03 authentication, in which case
// the same reads happen over secure messaging; the report's
// Channel field records which path was taken so audit logs can
// distinguish the two.
//
// Split from cmd_sd_keys.go because the list path's flag surface,
// JSON projection types (sdKeysListData / sdKeyEntry / sdKeyComponent
// / sdKeyCertView), and dry-run shape are independent of the
// export branch and the shared helpers. Keeping the list path in
// its own file makes the "all list-specific code" surface
// auditable in isolation.
//
// The dispatcher in cmd_sd_keys.go routes here on
// args[0] == "list".

import (
	"context"
	"fmt"
	"sort"

	"github.com/PeculiarVentures/scp/securitydomain"
)

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
	Profile string       `json:"profile,omitempty"`
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
	sdAIDFlag := registerSDAIDFlag(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	sdAID, err := sdAIDFlag.Resolve()
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "sd keys list", Reader: *reader}

	sd, channel, profName, err := openSDForRead(ctx, t, scp03Flags, sdAID, report)
	if err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sd.Close()

	// Step 1: Key Information Template. Without this we have no
	// inventory to report against, so a fetch failure is FAIL.
	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		// If the card refuses GET DATA on the unauthenticated
		// channel (SW=6982 Security status not satisfied), the
		// raw SW alone won't tell an operator how to recover.
		// Emit an explicit message that names the limitation:
		// SCP03 is the only authenticated read fallback this
		// command supports; SCP11a-authenticated reads are not
		// implemented (deferred until a concrete deployment
		// surfaces a card that requires SCP11a for GET DATA).
		hint := authRequiredHint(err, channel, "sd keys list")
		if hint != "" {
			report.Fail("GET DATA tag 0x00E0 (KIT)", hint)
		} else {
			report.Fail("GET DATA tag 0x00E0 (KIT)", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("get key information: %w", err)
	}
	if len(keys) == 0 {
		report.Skip("GET DATA tag 0x00E0 (KIT)", "card returned no key entries")
		report.Data = &sdKeysListData{Channel: channel, Profile: profName, Keys: []sdKeyEntry{}}
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
	data := &sdKeysListData{Channel: channel, Profile: profName, Keys: make([]sdKeyEntry, 0, len(keys))}

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
			Kind:       classifyKID(ki.Reference.ID, profName),
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
