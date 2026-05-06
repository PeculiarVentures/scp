package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// gpDeleteData is the JSON payload for `gp delete`.
type gpDeleteData struct {
	Protocol string `json:"protocol,omitempty"`
	AID      string `json:"aid"`
	Related  bool   `json:"related"`
	DryRun   bool   `json:"dry_run"`
}

// cmdGPDelete removes a registered AID from the card. Wraps
// securitydomain.Session.Delete behind the standard --confirm-write
// idiom so a dry-run is read-only.
//
// Flags:
//
//	--aid <hex>            AID to delete (required, 5..16 bytes)
//	--related              cascade: also remove applets instantiated
//	                       from a deleted load file
//	--reader <name>        PC/SC reader substring
//	--json                 emit JSON output
//	--scp03-keys-default   YubiKey factory keys (test only)
//	--scp03-{enc,mac,dek}  split-key inputs
//	--scp03-key            single shared SCP03 key
//	--scp03-kvn            key version number on the card
//	--confirm-write        commit the delete. Without this flag
//	                       the command is read-only and reports
//	                       what it would have sent.
//
// SW=6A88 ("referenced data not found") is a normal outcome when
// the AID isn't on the card; the command surfaces it as a FAIL
// check with the SW spelled out so the operator can decide
// whether to retry against a different AID. Other SWs surface as
// FAIL with the SW value in the detail.
func cmdGPDelete(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("gp delete", env)
	aidHex := fs.String("aid", "",
		"AID to delete, hex (5..16 bytes). Required.")
	related := fs.Bool("related", false,
		"Cascade delete: also remove applets instantiated from this load file. Use when deleting a load file rather than an applet.")
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	sdAIDHex := fs.String("sd-aid", "",
		"Override the Security Domain AID, hex (5..16 bytes). Default is the GP ISD AID.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	scp03Keys := registerSCP03KeyFlags(fs)
	expectedCardID := fs.String("expected-card-id", "",
		"If set, abort before sending DELETE when the card's CIN (GET DATA 0x0045) does not match this hex value.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, gp delete runs in dry-run mode (validates inputs and reports what would be sent without transmitting any APDU that mutates card state).")

	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *aidHex == "" {
		return &usageError{msg: "gp delete requires --aid <hex>"}
	}
	if !scp03Keys.explicitlyConfigured() {
		return &usageError{msg: "gp delete requires an explicit SCP03 key choice: pass " +
			"--scp03-keys-default for YubiKey/test-card factory keys, " +
			"--scp03-kvn with --scp03-key for single-key cards, or " +
			"--scp03-kvn with --scp03-{enc,mac,dek} for split-key cards"}
	}

	report := &Report{Subcommand: "gp delete", Reader: *reader}
	data := &gpDeleteData{Related: *related, DryRun: !*confirm}
	report.Data = data

	aid, err := decodeHexAID(*aidHex, "aid")
	if err != nil {
		report.Fail("aid", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	data.AID = strings.ToUpper(hex.EncodeToString(aid))
	report.Pass("aid", data.AID)
	if *related {
		report.Pass("cascade", "delete-related flag set; linked applets will also be removed")
	}

	if !*confirm {
		report.Skip("DELETE", "dry-run; pass --confirm-write to actually delete")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}
	sdAID, err := decodeSDAIDFlag(*sdAIDHex)
	if err != nil {
		report.Fail("sd-aid", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	if sdAID != nil {
		cfg.SelectAID = sdAID
		report.Pass("sd-aid", strings.ToUpper(hex.EncodeToString(sdAID)))
	}
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report.Pass("SCP03 keys", scp03Keys.describeKeys(cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, cfg)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP03 SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP03 SD", scp03Keys.describeKeys(cfg))

	// Optional CIN pin.
	if err := verifyExpectedCardID(ctx, sd, *expectedCardID, report); err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return err
	}

	if err := sd.Delete(ctx, aid, *related); err != nil {
		var ae *securitydomain.APDUError
		if errors.As(err, &ae) && ae.SW == 0x6A88 {
			report.Fail("DELETE",
				fmt.Sprintf("AID %s not on card (SW=6A88). If the AID is correct the object may already be absent.", data.AID))
		} else {
			report.Fail("DELETE", err.Error())
		}
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("DELETE", fmt.Sprintf("AID %s removed", data.AID))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return errors.New("gp delete: one or more checks failed")
	}
	return nil
}
