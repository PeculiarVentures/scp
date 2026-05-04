package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
)

type scp11aSDReadData struct {
	Protocol         string `json:"protocol,omitempty"`
	OCEAuthenticated bool   `json:"oce_authenticated"`
	KeyEntries       int    `json:"key_entries,omitempty"`
}

// cmdSCP11aSDRead opens an SCP11a (mutual-auth) Security Domain
// session against a card that already has the OCE provisioned, then
// verifies the read APDUs work over the resulting secure channel.
//
// SCP11a vs SCP11b — what changes for the operator:
//
//   - SCP11b is one-way auth. The host validates the card; the card
//     does not validate the host. Read-only against the SD.
//   - SCP11a is mutual auth. The host validates the card AND the
//     card validates the host's OCE certificate chain against an
//     OCE root that was previously installed on the card (see
//     `bootstrap-oce` for that step). After SCP11a opens, the
//     session is OCE-authenticated and can drive SD writes (PUT
//     KEY, STORE CERTIFICATE, etc.).
//
// Pre-conditions for this command to succeed against real hardware:
//
//  1. The card has an OCE root + key reference provisioned at
//     KID=0x10 (default; override with --oce-kid). On factory-fresh
//     YubiKey, this is NOT the case; bootstrap with `bootstrap-oce`
//     using an SCP03 session first.
//  2. The OCE private key file referenced by --oce-key corresponds
//     to the leaf certificate in --oce-cert.
//  3. The cert chain in --oce-cert ends in a leaf signed by the OCE
//     root the card has installed.
//
// If any of those is wrong, the card's PERFORM SECURITY OPERATION
// will reject the chain (SW 6982 or 6985 typically) and the open
// will fail with a clear error.
func cmdSCP11aSDRead(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("scp11a-sd-read", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	oceKeyPath := fs.String("oce-key", "",
		"Path to OCE private key PEM (PKCS#8 or SEC1). REQUIRED. Must be P-256.")
	oceCertPath := fs.String("oce-cert", "",
		"Path to OCE certificate chain PEM, leaf last. REQUIRED.")
	oceKID := fs.Int("oce-kid", 0x10,
		"OCE Key ID on the card (P2 of PERFORM SECURITY OPERATION). Default 0x10 (KeyIDOCE per GP §7.1.1).")
	oceKVN := fs.Int("oce-kvn", 0x03,
		"OCE Key Version Number on the card (P1 of PERFORM SECURITY OPERATION). Default 0x03 matches Yubico factory provisioning.")
	trust := registerTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *oceKeyPath == "" || *oceCertPath == "" {
		return &usageError{msg: "--oce-key and --oce-cert are required for scp11a-sd-read"}
	}
	if *oceKID < 0 || *oceKID > 0xFF || *oceKVN < 0 || *oceKVN > 0xFF {
		return &usageError{msg: "--oce-kid and --oce-kvn must be in 0x00..0xFF"}
	}

	report := &Report{Subcommand: "scp11a-sd-read", Reader: *reader}
	data := &scp11aSDReadData{}
	report.Data = data

	oceKey, err := loadOCEPrivateKey(*oceKeyPath)
	if err != nil {
		report.Fail("load OCE key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("load OCE key: %w", err)
	}
	report.Pass("load OCE key", "")

	oceChain, err := loadOCECertChain(*oceCertPath)
	if err != nil {
		report.Fail("load OCE cert chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("load OCE cert chain: %w", err)
	}
	report.Pass("load OCE cert chain", fmt.Sprintf("%d cert(s), leaf last", len(oceChain)))

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	cfg := &scp11.Config{
		Variant:         scp11.SCP11a,
		OCEPrivateKey:   oceKey,
		OCECertificates: oceChain,
		OCEKeyReference: scp11.KeyRef{KID: byte(*oceKID), KVN: byte(*oceKVN)},
	}
	proceed, err := trust.applyTrust(cfg, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	sd, err := securitydomain.OpenSCP11(ctx, t, cfg)
	if err != nil {
		report.Fail("open SCP11a SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP11a SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP11a SD", "")

	// SCP11a-specific invariant: the card validated our OCE chain,
	// so the session MUST be OCE-authenticated. If it isn't, either
	// the protocol layer regressed (silent downgrade to SCP11b-shape
	// session) or we somehow opened the wrong variant; either way
	// this is a hard failure for the smoke test, not a soft warn.
	data.OCEAuthenticated = sd.OCEAuthenticated()
	if !sd.OCEAuthenticated() {
		report.Fail("SCP11a is OCE-authenticated", "Session.OCEAuthenticated() = false (silent downgrade?)")
	} else {
		report.Pass("SCP11a is OCE-authenticated", "")
	}

	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		report.Fail("GetKeyInformation over SCP11a", err.Error())
	} else {
		data.KeyEntries = len(keys)
		report.Pass("GetKeyInformation over SCP11a", fmt.Sprintf("%d entries", len(keys)))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("scp11a-sd-read reported failures")
	}
	return nil
}
