package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport/trace"
)

type bootstrapSCP11aData struct {
	Protocol            string `json:"protocol,omitempty"`
	OCEKeyInstalled     bool   `json:"oce_key_installed"`
	CertChainStored     bool   `json:"cert_chain_stored,omitempty"`
	CertChainSkipped    bool   `json:"cert_chain_skipped,omitempty"`
	CACertSKIRegistered bool   `json:"ca_cert_ski_registered,omitempty"`
	CACertSKISkipped    bool   `json:"ca_cert_ski_skipped,omitempty"`
	SDKeyMode           string `json:"sd_key_mode,omitempty"`
	SDKeyOrigin         string `json:"sd_key_origin,omitempty"`
	SDKeyInstalled      bool   `json:"sd_key_installed"`
	SDPublicKeyPath     string `json:"sd_public_key_path,omitempty"`
}

// cmdBootstrapSCP11a does the full SCP11a-on-fresh-card provisioning
// flow inside a single SCP03 session: install the OCE public key at
// KID=0x10/KVN=0x03 (and optionally its cert chain + CA SKI), then
// generate or import the SCP11a SD ECKA key at KID=0x11/KVN=0x01,
// and only then close the session.
//
// Why this exists separately from bootstrap-oce + bootstrap-scp11a-sd
// (the two single-purpose commands): on YubiKey 5.7.4 (and per
// Yubico's documented behavior more broadly), the first PUT KEY a
// caller issues against the SD over the publicly-known factory
// SCP03 keys at KVN=0xFF causes the card to delete those factory
// keys. That's intentional — Yubico's stance is that any caller
// installing custom keys is moving from "shipping" to "provisioned"
// state and the shared default keys should not survive that
// transition. The practical consequence is that two consecutive
// SCP03-authenticated commands cannot both rely on factory keys.
// bootstrap-oce works; the immediately-following bootstrap-scp11a-sd
// fails INITIALIZE UPDATE with SW=6A88. Confirmed empirically on
// rmhrisk's retail YubiKey 5.7.4 on 2026-05-04 and consistent with
// docs.yubico.com/yesdk: "When adding the first custom key set, the
// default keys are automatically removed."
//
// This command sequences both writes in one session so the factory
// keys only need to authorize one INITIALIZE UPDATE. Output:
// /path/to/sd-public-key.pem holds the SCP11a SD public key (SPKI
// PEM) so the caller can attach it to fleet records or verifier
// configs on the OCE side.
//
// Flags echo bootstrap-oce and bootstrap-scp11a-sd in shape; see
// those commands for the per-flag rationale. The SCP11a SD key
// flags are namespaced "sd-*" (sd-key-mode, sd-key-pem, sd-key-out,
// sd-kid, sd-kvn) so the OCE-side flags can keep their existing
// names.
//
// Destructive: --confirm-write is required, mirroring the safety
// pattern used by both single-purpose bootstrap commands. Without
// it the command runs in dry-run mode, validating inputs and
// reporting planned operations without transmitting writes.
func cmdBootstrapSCP11a(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("bootstrap-scp11a", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")

	// OCE-side flags (mirror bootstrap-oce).
	oceCertPath := fs.String("oce-cert", "",
		"Path to OCE certificate chain PEM, leaf last. REQUIRED. "+
			"Leaf's public key is installed at the OCE KID/KVN; "+
			"if --store-chain is set, the entire chain is also written.")
	storeChain := fs.Bool("store-chain", false,
		"Also call STORE CERTIFICATES with the full chain.")
	caSKIHex := fs.String("ca-ski", "",
		"Hex-encoded CA SKI to register via STORE CA-IDENTIFIER. Optional.")
	oceKID := fs.Int("oce-kid", 0x10,
		"OCE Key ID. Default 0x10 (KeyIDOCE per GP §7.1.1).")
	oceKVN := fs.Int("oce-kvn", 0x03,
		"OCE Key Version Number. Default 0x03 matches Yubico factory expectations.")
	oceReplaceKVN := fs.Int("oce-replace-kvn", 0x00,
		"OCE KVN to replace (0 = add new).")

	// SCP11a SD-side flags (mirror bootstrap-scp11a-sd).
	sdKeyMode := fs.String("sd-key-mode", "oncard",
		"SCP11a SD key provisioning mode. 'oncard' (default) uses Yubico's GENERATE KEY "+
			"extension (private key never leaves the SE). 'import' uses GP PUT KEY and "+
			"either generates the keypair on the host or loads it from --sd-key-pem.")
	sdKeyPath := fs.String("sd-key-pem", "",
		"Path to a P-256 EC private key PEM to import. Only used with --sd-key-mode=import. "+
			"If absent and --sd-key-mode=import, a fresh keypair is generated on the host.")
	sdKeyOut := fs.String("sd-key-out", "",
		"Write the resulting SCP11a SD public key here as a SubjectPublicKeyInfo PEM. REQUIRED.")
	sdKID := fs.Int("sd-kid", 0x11,
		"SCP11a SD key reference KID. Default 0x11 (SK.SD.ECKA per GP Amendment F §7.1.1).")
	sdKVN := fs.Int("sd-kvn", 0x01,
		"SCP11a SD key reference KVN. Default 0x01 matches Yubico factory expectations.")
	sdReplaceKVN := fs.Int("sd-replace-kvn", 0x00,
		"SCP11a SD KVN to replace (0 = add new).")

	// Shared.
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, bootstrap-scp11a runs in dry-run mode.")
	apduTrace := fs.String("apdu-trace", "",
		"If set, write every wire-level APDU exchange to this path as a JSON "+
			"trace. Used for byte-level diff against an externally-captured "+
			"yubikit/ykman trace (pcsc-spy on macOS, pcsc-tools on Linux) to "+
			"localize wire-shape bugs. The recorder sits at the transport "+
			"layer, so it captures POST-SCP03-wrapping bytes — exactly what "+
			"the external capture sees from the OS side. No effect in "+
			"dry-run mode (no APDUs are sent).")
	scp03Keys := registerSCP03KeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	scp03Cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	// Required-flag validation, fail fast before any side effects.
	if *oceCertPath == "" {
		return &usageError{msg: "--oce-cert is required"}
	}
	if *sdKeyOut == "" {
		return &usageError{msg: "--sd-key-out is required"}
	}
	if *sdKeyMode != "oncard" && *sdKeyMode != "import" {
		return &usageError{msg: fmt.Sprintf("--sd-key-mode must be 'oncard' or 'import' (got %q)", *sdKeyMode)}
	}
	if *sdKeyMode == "oncard" && *sdKeyPath != "" {
		return &usageError{msg: "--sd-key-pem is only valid with --sd-key-mode=import"}
	}
	for _, v := range []int{*oceKID, *oceKVN, *oceReplaceKVN, *sdKID, *sdKVN, *sdReplaceKVN} {
		if v < 0 || v > 0xFF {
			return &usageError{msg: "all KID/KVN values must be in 0x00..0xFF"}
		}
	}

	report := &Report{Subcommand: "bootstrap-scp11a", Reader: *reader}
	data := &bootstrapSCP11aData{SDKeyMode: *sdKeyMode}
	report.Data = data

	// Phase 1: load + parse all inputs from disk before opening
	// SCP03. Errors here surface before we touch the card and
	// before factory SCP03 is consumed.
	chain, err := loadOCECertChain(*oceCertPath)
	if err != nil {
		report.Fail("load OCE cert chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("load OCE cert chain: %w", err)
	}
	report.Pass("load OCE cert chain", fmt.Sprintf("%d cert(s), leaf last", len(chain)))

	caCert, caPubKey, computedSKI, err := oceCAFromChain(chain)
	if err != nil {
		report.Fail("OCE CA public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("OCE CA public key: %w", err)
	}
	report.Pass("OCE CA public key",
		fmt.Sprintf("P-256 ECDSA, CN=%q (chain[0])", caCert.Subject.CommonName))

	caSKI := computedSKI
	skiOrigin := "computed from chain[0]"
	if *caSKIHex != "" {
		override, err := hex.DecodeString(strings.ReplaceAll(*caSKIHex, ":", ""))
		if err != nil {
			return &usageError{msg: fmt.Sprintf("--ca-ski: %v", err)}
		}
		caSKI = override
		skiOrigin = "from --ca-ski override"
	}

	var importedPriv *ecdsa.PrivateKey
	if *sdKeyMode == "import" {
		if *sdKeyPath != "" {
			loaded, err := loadOCEPrivateKey(*sdKeyPath)
			if err != nil {
				report.Fail("load --sd-key-pem", err.Error())
				_ = report.Emit(env.out, *jsonMode)
				return fmt.Errorf("load --sd-key-pem: %w", err)
			}
			importedPriv = loaded
			data.SDKeyOrigin = "loaded from --sd-key-pem"
			report.Pass("load --sd-key-pem", "P-256 ECDSA")
		} else {
			fresh, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				report.Fail("generate SD keypair", err.Error())
				_ = report.Emit(env.out, *jsonMode)
				return fmt.Errorf("generate SD keypair: %w", err)
			}
			importedPriv = fresh
			data.SDKeyOrigin = "freshly generated on host"
			report.Pass("generate SD keypair", "P-256, fresh")
		}
	}

	if !*confirm {
		report.Skip("install OCE CA public key", "dry-run; pass --confirm-write to actually call PUT KEY")
		report.Skip("register CA SKI", fmt.Sprintf("dry-run (%s)", skiOrigin))
		if *storeChain {
			report.Skip("store OCE cert chain", "dry-run")
		}
		switch *sdKeyMode {
		case "oncard":
			report.Skip("install SCP11a SD key (on-card)",
				"dry-run; pass --confirm-write to actually call GENERATE KEY")
		case "import":
			report.Skip("install SCP11a SD key (import)",
				"dry-run; pass --confirm-write to actually call PUT KEY")
		}
		report.Skip("write SD public key", "dry-run; --sd-key-out would be written here")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	// Phase 2: connect, open SCP03, do BOTH writes, close.
	// The factory SCP03 keys at KVN=0xFF will be invalidated by
	// the first PUT KEY in this session — which is fine because
	// we never need them again after this single bootstrap.
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	// Wire-level APDU trace: wrap the transport with the recorder so
	// every Transmit/TransmitRaw is captured. Sits at the transport
	// layer, BELOW the SCP03 secure channel — the bytes recorded are
	// what hits the wire, including SCP03 C-MAC and (when configured)
	// C-DECRYPTION. This is apples-to-apples with what `pcsc-spy`
	// captures from the macOS PC/SC side, so a byte-diff between an
	// scpctl trace and an externally-captured ykman trace is a
	// localizes-the-bug operation: identical wire bytes prove the
	// scpctl path matches yubikit; any diff is the bug surface.
	if *apduTrace != "" {
		rec := trace.NewRecorder(t, trace.RecorderConfig{
			Profile: "scpctl bootstrap-scp11a",
			Reader:  *reader,
			Notes: "Captured for byte-diff against ykman/yubikit during the " +
				"SCP11a PSO SW=6A80 investigation. Recorded bytes are wire-level: " +
				"SCP03 wrapping has already been applied at this layer. " +
				"See https://github.com/PeculiarVentures/scp issue tracker.",
		})
		// The defer captures the loop-time pointer; on return we
		// flush whatever exchanges accumulated, regardless of how
		// the function exits. Flush errors are reported but do not
		// override a failing primary error.
		defer func() {
			if ferr := rec.FlushFile(*apduTrace); ferr != nil {
				fmt.Fprintf(env.errOut, "scpctl: --apdu-trace flush: %v\n", ferr)
			} else {
				fmt.Fprintf(env.errOut, "scpctl: APDU trace written to %s\n", *apduTrace)
			}
		}()
		t = rec
	}

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

	// 2a) OCE-side writes: install the CA public key, register its
	// SKI as CA-IDENTIFIER, then optionally store the chain.
	oceRef := securitydomain.KeyReference{ID: byte(*oceKID), Version: byte(*oceKVN)}
	if err := sd.PutECPublicKey(ctx, oceRef, caPubKey, byte(*oceReplaceKVN)); err != nil {
		report.Fail("install OCE CA public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("install OCE CA public key: %w", err)
	}
	data.OCEKeyInstalled = true
	report.Pass("install OCE CA public key",
		fmt.Sprintf("KID=0x%02X KVN=0x%02X (CN=%q)",
			byte(*oceKID), byte(*oceKVN), caCert.Subject.CommonName))

	if err := sd.StoreCaIssuer(ctx, oceRef, caSKI); err != nil {
		report.Fail("register CA SKI", err.Error())
	} else {
		data.CACertSKIRegistered = true
		report.Pass("register CA SKI",
			fmt.Sprintf("%X (%s)", caSKI, skiOrigin))
	}

	if *storeChain {
		if err := sd.StoreCertificates(ctx, oceRef, chain); err != nil {
			report.Fail("store OCE cert chain", err.Error())
		} else {
			data.CertChainStored = true
			report.Pass("store OCE cert chain", fmt.Sprintf("%d cert(s)", len(chain)))
		}
	} else {
		data.CertChainSkipped = true
		report.Skip("store OCE cert chain", "--store-chain not set")
	}

	// 2b) SCP11a SD-side writes. Same SCP03 session — no
	// re-authentication needed.
	sdRef := securitydomain.KeyReference{ID: byte(*sdKID), Version: byte(*sdKVN)}
	var sdPub *ecdsa.PublicKey
	switch *sdKeyMode {
	case "oncard":
		pub, err := sd.GenerateECKey(ctx, sdRef, byte(*sdReplaceKVN))
		if err != nil {
			report.Fail("install SCP11a SD key (on-card)", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("GenerateECKey: %w", err)
		}
		sdPub = pub
		data.SDKeyOrigin = "generated on card (Yubico GENERATE KEY extension)"
		report.Pass("install SCP11a SD key (on-card)",
			fmt.Sprintf("KID=0x%02X KVN=0x%02X", byte(*sdKID), byte(*sdKVN)))

	case "import":
		if err := sd.PutECPrivateKey(ctx, sdRef, importedPriv, byte(*sdReplaceKVN)); err != nil {
			report.Fail("install SCP11a SD key (import)", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("PutECPrivateKey: %w", err)
		}
		sdPub = &importedPriv.PublicKey
		report.Pass("install SCP11a SD key (import)",
			fmt.Sprintf("KID=0x%02X KVN=0x%02X", byte(*sdKID), byte(*sdKVN)))
	}
	data.SDKeyInstalled = true

	// 2c) Write the SD public key to disk.
	derSPKI, err := x509.MarshalPKIXPublicKey(sdPub)
	if err != nil {
		report.Fail("serialize SD public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("serialize SD public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derSPKI})
	if err := os.WriteFile(*sdKeyOut, pemBytes, 0o644); err != nil {
		report.Fail("write SD public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("write %s: %w", *sdKeyOut, err)
	}
	data.SDPublicKeyPath = *sdKeyOut
	report.Pass("write SD public key", *sdKeyOut)

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	return nil
}
