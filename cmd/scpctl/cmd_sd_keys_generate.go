package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// sdKeysGenerateData is the JSON payload of `sd keys generate`.
//
// Curve is hardcoded to "P-256" because Session.GenerateECKey only
// supports NIST P-256 today; we still emit the field so JSON
// consumers don't have to assume, and so a future expansion that
// adds curve selection can populate it without a schema break.
//
// SPKIFingerprintSHA256 mirrors the projection used by
// sd keys list / export so the same identifier shape works across
// commands. The fingerprint is over the raw SubjectPublicKeyInfo
// DER (what 'openssl x509 -pubkey' emits, what Chrome's cert viewer
// displays as "Public Key SHA-256").
//
// Channel records the wire mode used; for Phase 4 this is "scp03"
// when the operation actually ran, "dry-run" when --confirm-write
// was omitted.
type sdKeysGenerateData struct {
	Channel               string `json:"channel"`
	KIDHex                string `json:"kid_hex"`
	KVNHex                string `json:"kvn_hex"`
	ReplaceKVN            byte   `json:"replace_kvn"`
	Curve                 string `json:"curve"`
	SPKIFingerprintSHA256 string `json:"spki_fingerprint_sha256,omitempty"`
	OutPath               string `json:"out_path,omitempty"`
}

// isSCP11SDSlot reports whether a KID is a Security Domain SCP11
// endpoint key reference (the only KIDs that GENERATE EC KEY targets
// meaningfully): 0x11 (SCP11a), 0x13 (SCP11b), 0x15 (SCP11c). Other
// KIDs — SCP03 0x01, OCE/CA public 0x10/0x20–0x2F, anything else —
// are refused host-side rather than letting the card respond with
// a generic 6A88 / 6D00.
func isSCP11SDSlot(kid byte) bool {
	switch kid {
	case securitydomain.KeyIDSCP11a,
		securitydomain.KeyIDSCP11b,
		securitydomain.KeyIDSCP11c:
		return true
	}
	return false
}

// cmdSDKeysGenerate triggers on-card EC key-pair generation at one
// SCP11 SD slot. The private key never crosses the wire; only the
// SPKI is returned, which the command writes as a PEM PUBLIC KEY
// block through the atomic write helper (write to temp file, sync,
// close, chmod, rename).
//
// Composes Session.GenerateECKey, which uses INS=0xF1 — a Yubico
// extension, NOT the GP standard PUT KEY (0xD8) generation form.
// Cards that don't implement INS=0xF1 will respond with 6D00
// (instruction not supported) or similar; we surface the Yubico-
// extension nature in the check name and JSON output so the audit
// log records exactly what was attempted, and operator log diffs
// across card profiles are unambiguous.
//
// Profile-aware behavior (per design doc): KID is validated against
// the SCP11 SD slot set host-side. Broader profile detection (does
// THIS card actually support INS=0xF1?) is currently implicit —
// bootstrap-scp11a-sd already calls GenerateECKey unprompted, so
// adding profile probing only here would be inconsistent. When a
// non-Yubico GP profile is added to the codebase, the gate moves
// into a shared helper and applies uniformly.
//
// Flag-validation rules:
//
//	--kid + --kvn + --out + --confirm-write     happy path
//	--kid not in {0x11, 0x13, 0x15}             USAGE ERROR
//	missing --kid / --kvn / --out               USAGE ERROR
//
// Confirmation gate: --confirm-write. Generate isn't as recovery-
// meaningful as delete (a freshly generated key replaces an existing
// one only when --replace-kvn is set; otherwise it's an additive
// install), so it shares the ordinary write gate rather than getting
// its own. --replace-kvn IS the destructive form, but only against
// a key the operator named explicitly.
//
// Dry-run by default: without --confirm-write, validates inputs,
// reports the planned action including the target slot and replace
// behavior, exits 0 without opening SCP03 or transmitting the
// GENERATE APDU. Same dry-run pattern as sd lock / unlock / etc.
func cmdSDKeysGenerate(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd keys generate", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	kidStr := fs.String("kid", "",
		"SCP11 SD slot to generate into, hex byte. Must be one of 11 "+
			"(SCP11a), 13 (SCP11b), 15 (SCP11c). Required.")
	kvnStr := fs.String("kvn", "",
		"Key Version Number, hex byte (e.g. 01). Required.")
	replaceKvnStr := fs.String("replace-kvn", "00",
		"Replace an existing key at this KVN, hex byte. 00 (the default) "+
			"means install a new key without replacing.")
	outPath := fs.String("out", "",
		"Output file path for the generated SPKI (PEM PUBLIC KEY block). "+
			"Required — the public key is the only artifact the operator "+
			"gets back from the card and needs to be captured to a file.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, sd keys generate "+
			"runs in dry-run mode (validates inputs, reports the planned "+
			"action, exits 0 without opening SCP03 or issuing the APDU).")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *kidStr == "" || *kvnStr == "" {
		return &usageError{msg: "sd keys generate requires --kid and --kvn"}
	}
	kid, err := parseHexByte(*kidStr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--kid: %v", err)}
	}
	if !isSCP11SDSlot(kid) {
		return &usageError{msg: fmt.Sprintf(
			"--kid 0x%02X: GENERATE EC KEY targets SCP11 SD slots only "+
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
	if *outPath == "" {
		return &usageError{msg: "sd keys generate requires --out (the SPKI must be captured to a file; otherwise generation is not observable to the operator)"}
	}

	// Vendor profile gate: GENERATE EC KEY uses INS=0xF1, which is
	// a Yubico extension to the GP spec. Generic GP cards return
	// SW=6D00 (instruction not supported). Refuse here rather than
	// emit the APDU and let the card error surface as
	// hard-to-interpret noise — the operator named --vendor-profile
	// generic explicitly, so they wanted the safety check.
	if scp03Keys.VendorProfile() == "generic" {
		return &usageError{msg: "sd keys generate requires --vendor-profile yubikey: " +
			"GENERATE EC KEY (INS=0xF1) is a Yubico extension and is not part of the GP " +
			"standard surface. Generic GP cards reject it with SW=6D00. To install an EC " +
			"key on a non-YubiKey card, generate the keypair off-card and use sd keys " +
			"import instead."}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	ref := securitydomain.NewKeyReference(kid, kvn)
	report := &Report{Subcommand: "sd keys generate", Reader: *reader}
	data := &sdKeysGenerateData{
		KIDHex:     fmt.Sprintf("0x%02X", kid),
		KVNHex:     fmt.Sprintf("0x%02X", kvn),
		ReplaceKVN: replaceKvn,
		Curve:      "P-256",
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
			planned = fmt.Sprintf("dry-run; pass --confirm-write to generate a P-256 key at kid=0x%02X kvn=0x%02X (additive install, no existing key replaced).",
				kid, kvn)
		} else {
			planned = fmt.Sprintf("dry-run; pass --confirm-write to generate a P-256 key at kid=0x%02X kvn=0x%02X, REPLACING the existing key at KVN=0x%02X.",
				kid, kvn, replaceKvn)
		}
		report.Skip("GENERATE EC KEY (Yubico extension INS=0xF1)", planned)
		data.Channel = "dry-run"
		return report.Emit(env.out, *jsonMode)
	}

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys generate: open SCP03: %w", err)
	}
	defer sd.Close()
	report.Pass("open SCP03 session", "")
	data.Channel = "scp03"

	checkName := fmt.Sprintf("GENERATE EC KEY (Yubico extension INS=0xF1) kid=0x%02X kvn=0x%02X", kid, kvn)
	pub, err := sd.GenerateECKey(ctx, ref, replaceKvn)
	if err != nil {
		report.Fail(checkName, err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys generate: %w", err)
	}
	report.Pass(checkName, "P-256 SPKI returned")

	derSPKI, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		report.Fail("marshal SPKI", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys generate: marshal SPKI: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derSPKI})

	// 0o644: SPKI is public material (the entire point of generation
	// is that the operator can hand the public key to other systems).
	// Same posture as sd keys export.
	if err := writeFileAtomic(*outPath, pemBytes, 0o644); err != nil {
		report.Fail("write file", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("sd keys generate: write %s: %w", *outPath, err)
	}
	report.Pass("write file", fmt.Sprintf("%s (%d bytes)", *outPath, len(pemBytes)))

	sum := sha256.Sum256(derSPKI)
	data.OutPath = *outPath
	data.SPKIFingerprintSHA256 = hexEncode(sum[:])

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("sd keys generate reported failures")
	}
	return nil
}
