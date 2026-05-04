package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/scp11"
)

type pivVerifyData struct {
	Protocol string `json:"protocol,omitempty"`
}

// cmdSCP11bPIVVerify opens an SCP11b session targeting the PIV
// applet (NOT the ISD), then sends VERIFY PIN through the secure
// channel. A successful return proves three things at once:
//
//  1. SCP11b can establish a secure channel against an applet other
//     than the Issuer Security Domain.
//  2. The PIV APDU builders produce wire bytes that survive SCP11
//     secure-messaging wrap.
//  3. The card's PIV applet accepts the supplied PIN through the
//     wrapped channel.
//
// SCP is applet-scoped on YubiKey: do NOT open SCP on the SD and
// then SELECT PIV inside the secure channel. Set SelectAID = AIDPIV
// on the Config and let the handshake target PIV directly.
//
// Reference: docs.yubico.com/yesdk on PIV-over-SCP setup.
func cmdSCP11bPIVVerify(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("scp11b-piv-verify", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	trust := registerTrustFlags(fs)
	pin := fs.String("pin", "",
		"PIV PIN (required). Default retail PINs are well-known; pass yours explicitly.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *pin == "" {
		return &usageError{msg: "--pin is required"}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "scp11b-piv-verify", Reader: *reader}
	data := &pivVerifyData{}
	report.Data = data

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	proceed, err := trust.applyTrust(cfg, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	sess, err := scp11.Open(ctx, t, cfg)
	if err != nil {
		report.Fail("open SCP11b vs PIV", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP11b vs PIV: %w", err)
	}
	defer sess.Close()
	data.Protocol = "SCP11b"
	report.Pass("open SCP11b vs PIV", "")

	// VerifyPIN may return an error if the PIN bytes are an invalid
	// shape (wrong length / non-numeric). Surface that as a usage
	// error rather than a card error; we never reached the card.
	cmd, err := piv.VerifyPIN([]byte(*pin))
	if err != nil {
		return &usageError{msg: fmt.Sprintf("invalid PIN: %v", err)}
	}

	resp, err := sess.Transmit(ctx, cmd)
	if err != nil {
		report.Fail("VERIFY PIN over SCP11b", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN: %w", err)
	}
	if !resp.IsSuccess() {
		// 63Cx = wrong PIN, x retries left. Surface that distinctly
		// so the user can tell "wire works, PIN is wrong" from
		// "wire failed."
		report.Fail("VERIFY PIN over SCP11b",
			fmt.Sprintf("card returned SW=%04X", resp.StatusWord()))
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN: SW=%04X", resp.StatusWord())
	}
	report.Pass("VERIFY PIN over SCP11b", "")

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("scp11b-piv-verify reported failures")
	}
	return nil
}
