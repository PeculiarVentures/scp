package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport/trace"
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
	sdKID := fs.Int("sd-kid", 0x11,
		"Card-side SCP11a SD key reference, KID. This is the key the card uses on its end of the channel — distinct from the OCE key reference. Default 0x11 (GP Amendment F §7.1.1 SCP11a slot, used by YubiKey).")
	sdKVN := fs.Int("sd-kvn", 0x01,
		"Card-side SCP11a SD key reference, KVN. Default 0x01 matches Yubico factory provisioning. Pass 0x00 to mean 'any version' (GP-spec literal).")
	apduTrace := fs.String("apdu-trace", "",
		"If set, write every wire-level APDU exchange to this path as a JSON "+
			"trace. Recorder sits at the transport layer, so it captures bytes "+
			"AS THE CARD RECEIVES THEM — including the failing PSO APDU. Used to "+
			"diagnose SCP11a PSO SW=6A80 failures by inspecting the exact bytes "+
			"of the rejected certificate APDU. No effect when the chain fails to "+
			"load or trust evaluation refuses (no APDUs are sent in those cases).")
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
	if *sdKID < 0 || *sdKID > 0xFF || *sdKVN < 0 || *sdKVN > 0xFF {
		return &usageError{msg: "--sd-kid and --sd-kvn must be in 0x00..0xFF"}
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

	// Wire-level APDU trace, parallel to the same flag on
	// bootstrap-scp11a. Wraps the transport at the layer below
	// SCP secure messaging — the recorded bytes are exactly what
	// the card sees on the wire. Most useful here for diagnosing
	// PSO SW=6A80 by inspecting the exact failing PSO APDU
	// (CLA/INS/P1/P2/Lc/data field) so we can compare it against
	// what the GP Amendment F §7.5 spec says the card should
	// accept.
	if *apduTrace != "" {
		rec := trace.NewRecorder(t, trace.RecorderConfig{
			Profile: "scpctl smoke scp11a-sd-read",
			Reader:  *reader,
			Notes: "Captured for diagnosis of SCP11a PSO SW=6A80. Trace " +
				"includes the failing PSO APDU when the chain is rejected " +
				"by the card's certificate verifier.",
		})
		defer func() {
			if ferr := rec.FlushFile(*apduTrace); ferr != nil {
				fmt.Fprintf(env.errOut, "scpctl: --apdu-trace flush: %v\n", ferr)
			} else {
				fmt.Fprintf(env.errOut, "scpctl: APDU trace written to %s\n", *apduTrace)
			}
		}()
		t = rec
	}

	cfg := scp11.YubiKeyDefaultSCP11aConfig()
	cfg.OCEPrivateKey = oceKey
	cfg.OCECertificates = oceChain
	cfg.OCEKeyReference = scp11.KeyRef{KID: byte(*oceKID), KVN: byte(*oceKVN)}
	// Override the card-side SCP11a key reference. The default from
	// YubiKeyDefaultSCP11aConfig is KID=0x11 KVN=0x01, which matches
	// Yubico factory provisioning when SCP11a has been installed; the
	// flags exist so non-Yubico cards or cards with a custom KVN can
	// still be exercised by this smoke test.
	cfg.KeyID = byte(*sdKID)
	cfg.KeyVersion = byte(*sdKVN)
	proceed, err := trust.applyTrust(cfg, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	// Preflight: read the card's Key Information Template via an
	// unauthenticated SD session. If the requested SCP11a SD key
	// (KID/KVN from --sd-kid/--sd-kvn) isn't installed, the SCP11a
	// open below would fail with an opaque card status. Catching it
	// here turns the failure into a clear SKIP that names the
	// missing reference and points the operator at SCP11a SD-key
	// provisioning.
	//
	// Best effort: cards that refuse unauthenticated KIT, or any
	// other transient error, leave preflight as a SKIP-with-warning
	// and the open is attempted as before. Preflight never fails
	// the smoke run on its own.
	if skipped := preflightSCP11aSDKey(ctx, t, byte(*sdKID), byte(*sdKVN), report); skipped {
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
