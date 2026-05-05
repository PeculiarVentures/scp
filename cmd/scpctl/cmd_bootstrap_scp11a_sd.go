package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type bootstrapSCP11aSDData struct {
	Protocol         string `json:"protocol,omitempty"`
	Mode             string `json:"mode,omitempty"`
	KeyInstalled     bool   `json:"key_installed"`
	PublicKeyPath    string `json:"public_key_path,omitempty"`
	PrivateKeyOrigin string `json:"private_key_origin,omitempty"`
}

// cmdBootstrapSCP11aSD installs a card-side SCP11a Security Domain
// ECDH key (SK.SD.ECKA). This is the SD half of the SCP11a
// provisioning flow whose OCE half is covered by bootstrap-oce.
// Together the two commands enable a fresh card to complete an
// SCP11a mutual-auth handshake.
//
// IMPORTANT — fresh-card sequencing: on YubiKey 5.7.4 (and per
// Yubico's documented behavior more broadly), the first PUT KEY
// against the SD over factory SCP03 keys (KVN=0xFF) causes the
// card to delete those factory keys. If you've already run
// bootstrap-oce on a fresh card, the factory SCP03 keys are gone
// and this command's INITIALIZE UPDATE will fail with SW=6A88. To
// install BOTH the OCE public key and the SCP11a SD key on a fresh
// card, use the combined `bootstrap-scp11a` command (one session,
// both writes). Use bootstrap-scp11a-sd alone when:
//   - you only need to install/rotate the SCP11a SD key, or
//   - you have a custom SCP03 key set installed and pass
//     --scp03-* flags so this command authenticates with the new
//     keys rather than the consumed factory ones.
//
// Two modes:
//
//   --mode oncard   (default)
//
//     Sends the Yubico GENERATE KEY (INS=0xF1) APDU. The card
//     generates the P-256 keypair internally, returns the public
//     key, and stores the private key in the SD. The host never
//     sees the private key. This is strictly the strongest posture
//     against host compromise but uses a Yubico-specific extension.
//
//   --mode import
//
//     Sends GP PUT KEY (INS=0xD8). The private key is supplied
//     either via --key-pem (a P-256 EC private key file) or
//     generated freshly here on the host. In both cases the bytes
//     are wrapped under the SCP03 session DEK before transmission.
//     This works on any GP-compliant SD, lets ops policies derive
//     keys from an HSM or other deterministic source, and produces
//     reproducible installations across multiple cards.
//
// In both modes the resulting public key is written to --out as
// PEM (uncompressed SEC1 inside SubjectPublicKeyInfo) so callers
// can attach it to fleet-management records or feed it to allowlist
// configurations on the OCE side.
//
// Default key reference is KID=0x11 KVN=0x01 — Yubico factory
// expectations for SCP11a SK.SD.ECKA. Override with --sd-kid /
// --sd-kvn for non-Yubico cards or rotation scenarios.
//
// Destructive: --confirm-write is required to actually transmit
// the write APDU. Without it the command runs in dry-run mode,
// validating inputs and reporting planned operations.
func cmdBootstrapSCP11aSD(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd bootstrap-scp11a-sd", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	mode := fs.String("mode", "oncard",
		"Provisioning mode. 'oncard' (default) generates the keypair on the card via the "+
			"Yubico GENERATE KEY extension (private key never leaves the SE). 'import' uses GP "+
			"PUT KEY and either generates the keypair on the host or loads it from --key-pem; "+
			"the private key bytes are wrapped under the SCP03 session DEK before transmission.")
	keyPath := fs.String("key-pem", "",
		"Path to a P-256 EC private key PEM (PKCS#8 or SEC1) to import. Only used when --mode=import. "+
			"If absent and --mode=import, a fresh keypair is generated here on the host.")
	outPath := fs.String("out", "",
		"Write the resulting SD public key here as a SubjectPublicKeyInfo PEM. REQUIRED.")
	sdKID := fs.Int("sd-kid", 0x11,
		"SD key reference, KID. Default 0x11 (SCP11a SK.SD.ECKA per GP Amendment F §7.1.1).")
	sdKVN := fs.Int("sd-kvn", 0x01,
		"SD key reference, KVN. Default 0x01 matches Yubico factory expectations.")
	replaceKVN := fs.Int("replace-kvn", 0x00,
		"KVN to replace (0x00 = add new). Use this when rotating an existing SCP11a SD key.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, bootstrap-scp11a-sd runs in dry-run "+
			"mode (validates inputs and reports planned operations without transmitting writes).")
	scp03Keys := registerSCP03KeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	if *outPath == "" {
		return &usageError{msg: "--out is required"}
	}
	if *mode != "oncard" && *mode != "import" {
		return &usageError{msg: fmt.Sprintf("--mode must be 'oncard' or 'import' (got %q)", *mode)}
	}
	if *mode == "oncard" && *keyPath != "" {
		return &usageError{msg: "--key-pem is only valid with --mode=import"}
	}
	if *sdKID < 0 || *sdKID > 0xFF || *sdKVN < 0 || *sdKVN > 0xFF || *replaceKVN < 0 || *replaceKVN > 0xFF {
		return &usageError{msg: "--sd-kid, --sd-kvn, --replace-kvn must be in 0x00..0xFF"}
	}

	report := &Report{Subcommand: "sd bootstrap-scp11a-sd", Reader: *reader}
	data := &bootstrapSCP11aSDData{Mode: *mode}
	report.Data = data

	// In import mode, prepare the private key now (before opening
	// SCP03) so input errors are surfaced before we touch the card.
	var importedPriv *ecdsa.PrivateKey
	if *mode == "import" {
		if *keyPath != "" {
			loaded, err := loadOCEPrivateKey(*keyPath)
			if err != nil {
				report.Fail("load --key-pem", err.Error())
				_ = report.Emit(env.out, *jsonMode)
				return fmt.Errorf("load --key-pem: %w", err)
			}
			importedPriv = loaded
			data.PrivateKeyOrigin = "loaded from --key-pem"
			report.Pass("load --key-pem", "P-256 ECDSA")
		} else {
			fresh, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				report.Fail("generate keypair", err.Error())
				_ = report.Emit(env.out, *jsonMode)
				return fmt.Errorf("generate keypair: %w", err)
			}
			importedPriv = fresh
			data.PrivateKeyOrigin = "freshly generated on host"
			report.Pass("generate keypair", "P-256, fresh")
		}
	}

	if !*confirm {
		switch *mode {
		case "oncard":
			report.Skip("install SCP11a SD key (on-card)",
				"dry-run; pass --confirm-write to actually call GENERATE KEY")
		case "import":
			report.Skip("install SCP11a SD key (import)",
				"dry-run; pass --confirm-write to actually call PUT KEY")
		}
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report.Pass("SCP03 keys", scp03Keys.describeKeys(scp03Cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, scp03Cfg)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP03 SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP03 SD", "")

	ref := securitydomain.KeyReference{ID: byte(*sdKID), Version: byte(*sdKVN)}

	// Drive whichever mode the caller selected. Both end with a
	// public key that we PEM-encode into --out.
	var sdPub *ecdsa.PublicKey
	switch *mode {
	case "oncard":
		pub, err := sd.GenerateECKey(ctx, ref, byte(*replaceKVN))
		if err != nil {
			report.Fail("install SCP11a SD key (on-card)", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("GenerateECKey: %w", err)
		}
		sdPub = pub
		data.PrivateKeyOrigin = "generated on card (Yubico GENERATE KEY extension)"
		report.Pass("install SCP11a SD key (on-card)",
			fmt.Sprintf("KID=0x%02X KVN=0x%02X", byte(*sdKID), byte(*sdKVN)))

	case "import":
		if err := sd.PutECPrivateKey(ctx, ref, importedPriv, byte(*replaceKVN)); err != nil {
			report.Fail("install SCP11a SD key (import)", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("PutECPrivateKey: %w", err)
		}
		sdPub = &importedPriv.PublicKey
		report.Pass("install SCP11a SD key (import)",
			fmt.Sprintf("KID=0x%02X KVN=0x%02X", byte(*sdKID), byte(*sdKVN)))
	}
	data.KeyInstalled = true

	// Serialize the public key as a SubjectPublicKeyInfo PEM so any
	// X.509 / PKI tool can pick it up directly.
	derSPKI, err := x509.MarshalPKIXPublicKey(sdPub)
	if err != nil {
		report.Fail("serialize SD public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("serialize SD public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derSPKI})
	if err := os.WriteFile(*outPath, pemBytes, 0o644); err != nil {
		report.Fail("write SD public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	data.PublicKeyPath = *outPath
	report.Pass("write SD public key", *outPath)

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	return nil
}
