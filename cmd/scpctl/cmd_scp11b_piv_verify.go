package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/piv/session"
)

type pivVerifyData struct {
	Protocol string `json:"protocol,omitempty"`
}

// cmdSCP11bPIVVerify opens an SCP11b session against the PIV applet
// and sends VERIFY PIN through the secure channel. A successful return
// proves three things at once:
//
//  1. SCP11b can establish a secure channel against an applet other
//     than the Issuer Security Domain.
//  2. The PIV APDU builders produce wire bytes that survive SCP11
//     secure-messaging wrap.
//  3. The card's PIV applet accepts the supplied PIN through the
//     wrapped channel.
//
// Wire layering: the SCP11 certificate (CERT.SD.ECKA) lives on the
// Security Domain, not on PIV — GET DATA BF21 against PIV returns
// SW=6D00. session.OpenSCP11bPIV handles this by fetching and
// verifying PK.SD.ECKA via an unauthenticated SD session first, then
// running the SCP11b handshake against PIV using the pre-supplied
// public key.
//
// Reference: docs.yubico.com/yesdk on PIV-over-SCP setup.
func cmdSCP11bPIVVerify(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("test scp11b-piv-verify", env)
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

	report := &Report{Subcommand: "test scp11b-piv-verify", Reader: *reader}
	data := &pivVerifyData{}
	report.Data = data

	opts := session.SCP11bPIVOptions{}
	proceed, err := trust.applyTrustToPIV(&opts, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	sess, err := session.OpenSCP11bPIV(ctx, t, opts)
	if err != nil {
		report.Fail("open SCP11b vs PIV", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP11b vs PIV: %w", err)
	}
	defer sess.Close()
	data.Protocol = "SCP11b"
	report.Pass("open SCP11b vs PIV", "")

	if err := sess.VerifyPIN(ctx, []byte(*pin)); err != nil {
		// piv/session.VerifyPIN distinguishes wrong-PIN (with retries
		// remaining) from wire/handshake errors. Surface the error
		// verbatim — the caller can tell "wire works, PIN wrong" from
		// "wire failed" via the message.
		report.Fail("VERIFY PIN over SCP11b", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN: %w", err)
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
