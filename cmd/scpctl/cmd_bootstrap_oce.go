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
// yubikey.FactorySCP03Config).
//
// Destructive: this command writes to the card. It is gated behind
// --confirm-write to mirror the safety pattern the README's
// destructive-ops section sets up. Without the flag, the command
// runs in dry-run mode and prints what it would do without actually
// transmitting any APDU that mutates card state.
func cmdBootstrapOCE(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("sd bootstrap-oce", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	oceCertPath := fs.String("oce-cert", "",
		"Path to OCE certificate chain PEM, leaf last. REQUIRED. "+
			"The leaf's public key is installed at the OCE KID/KVN. "+
			"The chain itself is NOT stored on the card — it travels "+
			"on the wire at session-open via PSO and is validated by "+
			"the card against the registered CA pubkey + SKI.")
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
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
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

	report := &Report{Subcommand: "sd bootstrap-oce", Reader: *reader}
	data := &bootstrapOCEData{}
	report.Data = data

	chain, err := loadOCECertChain(*oceCertPath)
	if err != nil {
		report.Fail("load OCE cert chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("load OCE cert chain: %w", err)
	}
	report.Pass("load OCE cert chain", fmt.Sprintf("%d cert(s), leaf last", len(chain)))

	// chain[0] is the OCE CA — the trust anchor for OCE certs the
	// card validates during SCP11a/c PSO. NOT chain[len-1] (the
	// leaf), which is what previous versions of this command
	// installed. See oceCAFromChain for the full rationale and the
	// Yubico .NET / yubikit Python references that document this.
	caCert, caPubKey, computedSKI, err := oceCAFromChain(chain)
	if err != nil {
		report.Fail("OCE CA public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("OCE CA public key: %w", err)
	}
	report.Pass("OCE CA public key",
		fmt.Sprintf("P-256 ECDSA, CN=%q (chain[0])", caCert.Subject.CommonName))

	// SKI: if --ca-ski was supplied, that value wins (caller may want
	// to register a SKI different from chain[0]'s for explicit auditing).
	// Otherwise auto-compute from chain[0] — either the SKI extension
	// if present, or the RFC 5280 §4.2.1.2 SHA-1(SPKI) fallback.
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

	if !*confirm {
		report.Skip("install OCE CA public key", "dry-run; pass --confirm-write to actually write")
		report.Skip("register CA SKI", fmt.Sprintf("dry-run (%s)", skiOrigin))
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

	if err := sd.PutECPublicKey(ctx, ref, caPubKey, byte(*replaceKVN)); err != nil {
		report.Fail("install OCE CA public key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("install OCE CA public key: %w", err)
	}
	data.OCEKeyInstalled = true
	report.Pass("install OCE CA public key",
		fmt.Sprintf("KID=0x%02X KVN=0x%02X (CN=%q)", byte(*oceKID), byte(*oceKVN), caCert.Subject.CommonName))

	// STORE CA-IDENTIFIER unconditionally now (it was opt-in before
	// and that's what made retail YubiKey 5.7+ reject the OCE chain
	// during SCP11a PSO with SW=6A80 — the card had no SKI to look
	// up the CA against).
	if err := sd.StoreCaIssuer(ctx, ref, caSKI); err != nil {
		report.Fail("register CA SKI", err.Error())
	} else {
		data.CACertSKIRegistered = true
		report.Pass("register CA SKI",
			fmt.Sprintf("%X (%s)", caSKI, skiOrigin))
	}

	// Note on cert chain storage. SCP11a/c involves two distinct
	// chains and they live in distinct places:
	//
	//   1. OCE chain (the chain that certifies PK.OCE.ECKA).
	//      Sent on the wire at session-open via PSO (GP §7.5.3).
	//      Validated by the card against the registered CA pubkey
	//      at the OCE KID + the SKI registered above. NEVER stored
	//      on the card. PutECPublicKey + StoreCaIssuer above are
	//      the complete OCE-side setup.
	//
	//   2. SD attestation chain (a chain that certifies PK.SD.ECKA).
	//      Stored on-card at the SCP11a/c SD KID, retrieved by the
	//      OCE at session-open via GET DATA (TAG_CERTIFICATE_STORE).
	//      The leaf cert MUST certify the on-card SD pubkey — i.e.
	//      built by signing the SD's pubkey with an issuer key chosen
	//      by the operator. Orthogonal to the OCE side: the OCE root
	//      and the SD attestation issuer can be (and in production
	//      usually are) different entities.
	//
	// Earlier versions of this command had a --store-chain flag that
	// passed the OCE chain to StoreCertificates(oceRef, ...). That
	// was wrong on two axes: wrong ref (KID=0x10 holds a CA pubkey,
	// not a chain), and wrong content (the OCE leaf cert doesn't
	// certify any on-card SD pubkey). The YubiKey returned SW=6A80
	// because the operation has no GP-spec meaning. The flag is
	// gone; SD attestation provisioning, if needed, is a separate
	// command that takes an issuer key + cert and signs the on-card
	// SD pubkey to build a proper attestation chain.

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("bootstrap-oce reported failures")
	}
	return nil
}
