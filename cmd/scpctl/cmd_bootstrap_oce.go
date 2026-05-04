package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

type bootstrapOCEData struct {
	Protocol            string `json:"protocol,omitempty"`
	OCEKeyInstalled     bool   `json:"oce_key_installed"`
	CertChainStored     bool   `json:"cert_chain_stored,omitempty"`
	CertChainSkipped    bool   `json:"cert_chain_skipped,omitempty"`
	CACertSKIRegistered bool   `json:"ca_cert_ski_registered,omitempty"`
	CACertSKISkipped    bool   `json:"ca_cert_ski_skipped,omitempty"`
}

// cmdBootstrapOCE installs an Off-Card Entity (OCE) public key,
// optionally a certificate chain for the card to validate against
// during SCP11a/c handshakes, and optionally a CA issuer SKI.
//
// This is the Day-1 provisioning step that enables `scp11a-sd-read`
// against a fresh card. Without it, SCP11a opens fail with an
// authentication error because the card has no OCE root to verify
// the host's chain against.
//
// IMPORTANT — fresh-card sequencing: on YubiKey 5.7.4 (and per
// Yubico's documented behavior more broadly), the first PUT KEY a
// caller issues against the SD over factory SCP03 (KVN=0xFF)
// causes the card to delete those factory keys. So an immediately
// following bootstrap-scp11a-sd run cannot reopen SCP03 and fails
// INITIALIZE UPDATE with SW=6A88. If you need to install BOTH the
// OCE public key AND the SCP11a SD key on a fresh card, use the
// combined `bootstrap-scp11a` command, which performs both writes
// inside a single SCP03 session. Use bootstrap-oce alone when:
//   - you only need to install/rotate the OCE side, or
//   - you have a custom SCP03 key set installed (so factory keys
//     being consumed isn't a problem because subsequent commands
//     can pass --scp03-* flags to authenticate with the new keys).
//
// The session used is SCP03 (the only protocol that gives mutual
// auth without already having an OCE provisioned). Default keys are
// the YubiKey factory keys (KVN 0xFF, key
// 404142434445464748494A4B4C4D4E4F for ENC/MAC/DEK); a card whose
// SCP03 keys have been rotated needs --kvn / --enc / --mac / --dek
// supplied explicitly, which this version doesn't expose yet — that's
// follow-up work, but the mechanism is straightforward (build an
// scp03.Config from those flags rather than calling
// FactoryYubiKeyConfig).
//
// Destructive: this command writes to the card. It is gated behind
// --confirm-write to mirror the safety pattern the README's
// destructive-ops section sets up. Without the flag, the command
// runs in dry-run mode and prints what it would do without actually
// transmitting any APDU that mutates card state.
func cmdBootstrapOCE(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("bootstrap-oce", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	oceCertPath := fs.String("oce-cert", "",
		"Path to OCE certificate chain PEM, leaf last. REQUIRED. "+
			"The leaf's public key is installed; if --store-chain is set, the entire chain is also written to the card.")
	storeChain := fs.Bool("store-chain", false,
		"Also call STORE CERTIFICATES with the full chain. Useful when the card validates against the chain rather than just the root.")
	caSKIHex := fs.String("ca-ski", "",
		"Hex-encoded CA Subject Key Identifier to register on the card via STORE CA-IDENTIFIER. Optional.")
	oceKID := fs.Int("oce-kid", 0x10,
		"OCE Key ID. Default 0x10 (KeyIDOCE per GP §7.1.1).")
	oceKVN := fs.Int("oce-kvn", 0x03,
		"OCE Key Version Number to install. Default 0x03 matches Yubico factory expectations.")
	replaceKVN := fs.Int("replace-kvn", 0x00,
		"KVN to replace (0 = add new). Use this when rotating an existing OCE registration.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, bootstrap-oce runs in dry-run mode (validates inputs and reports planned operations without transmitting writes).")
	scp03Keys := registerSCP03KeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	if *oceCertPath == "" {
		return &usageError{msg: "--oce-cert is required for bootstrap-oce"}
	}
	if *oceKID < 0 || *oceKID > 0xFF || *oceKVN < 0 || *oceKVN > 0xFF || *replaceKVN < 0 || *replaceKVN > 0xFF {
		return &usageError{msg: "--oce-kid, --oce-kvn, --replace-kvn must be in 0x00..0xFF"}
	}

	report := &Report{Subcommand: "bootstrap-oce", Reader: *reader}
	data := &bootstrapOCEData{}
	report.Data = data

	chain, err := loadOCECertChain(*oceCertPath)
	if err != nil {
		report.Fail("load OCE cert chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("load OCE cert chain: %w", err)
	}
	report.Pass("load OCE cert chain", fmt.Sprintf("%d cert(s), leaf last", len(chain)))

	leaf := chain[len(chain)-1]
	leafEC, err := extractECDSAPublicKey(leaf)
	if err != nil {
		report.Fail("OCE leaf public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("OCE leaf public key: %w", err)
	}
	report.Pass("OCE leaf public key", "P-256 ECDSA")

	var caSKI []byte
	if *caSKIHex != "" {
		caSKI, err = hex.DecodeString(strings.ReplaceAll(*caSKIHex, ":", ""))
		if err != nil {
			return &usageError{msg: fmt.Sprintf("--ca-ski: %v", err)}
		}
	}

	if !*confirm {
		report.Skip("install OCE public key", "dry-run; pass --confirm-write to actually write")
		if *storeChain {
			report.Skip("store OCE cert chain", "dry-run")
		}
		if caSKI != nil {
			report.Skip("register CA SKI", "dry-run")
		}
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	// SCP03 keys come from --scp03-* flags (or factory default).
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

	ref := securitydomain.KeyReference{ID: byte(*oceKID), Version: byte(*oceKVN)}

	if err := sd.PutECPublicKey(ctx, ref, leafEC, byte(*replaceKVN)); err != nil {
		report.Fail("install OCE public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("install OCE public key: %w", err)
	}
	data.OCEKeyInstalled = true
	report.Pass("install OCE public key",
		fmt.Sprintf("KID=0x%02X KVN=0x%02X", byte(*oceKID), byte(*oceKVN)))

	if *storeChain {
		if err := sd.StoreCertificates(ctx, ref, chain); err != nil {
			report.Fail("store OCE cert chain", err.Error())
		} else {
			data.CertChainStored = true
			report.Pass("store OCE cert chain", fmt.Sprintf("%d cert(s)", len(chain)))
		}
	} else {
		data.CertChainSkipped = true
		report.Skip("store OCE cert chain", "--store-chain not set")
	}

	if caSKI != nil {
		if err := sd.StoreCaIssuer(ctx, ref, caSKI); err != nil {
			report.Fail("register CA SKI", err.Error())
		} else {
			data.CACertSKIRegistered = true
			report.Pass("register CA SKI", fmt.Sprintf("%X", caSKI))
		}
	} else {
		data.CACertSKISkipped = true
		report.Skip("register CA SKI", "--ca-ski not set")
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("bootstrap-oce reported failures")
	}
	return nil
}
