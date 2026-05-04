package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/scp11"
)

type pivResetData struct {
	Protocol        string `json:"protocol,omitempty"`
	PINBlocked      bool   `json:"pin_blocked"`
	PUKBlocked      bool   `json:"puk_blocked"`
	PINAttemptsUsed int    `json:"pin_attempts_used"`
	PUKAttemptsUsed int    `json:"puk_attempts_used"`
	ResetSuccess    bool   `json:"reset_success"`
}

// cmdPIVReset performs a YubiKey PIV applet reset, returning the
// PIV applet to factory state. After a successful reset the PIN
// is "123456", the PUK is "12345678", and on YubiKey 5.7+ the
// management key is regenerated to a random AES-192 value stored
// in protected metadata; on older firmware the management key
// returns to the well-known 3DES default.
//
// The flow:
//
//  1. Open SCP11b session targeting the PIV applet.
//  2. Block the PIN by sending VERIFY PIN with deliberately wrong
//     PINs until the card returns 6983 (PIN blocked).
//  3. Block the PUK by sending RESET RETRY COUNTER with deliberately
//     wrong PUKs until the card returns 6983 (PUK blocked).
//  4. Send the YubiKey-specific PIV reset APDU (INS 0xFB).
//
// The card's own foot-gun guard is the precondition that BOTH PIN
// and PUK retry counters must be exhausted before INS 0xFB is
// accepted. A casual operator can't accidentally wipe the slot by
// sending one APDU; they have to first deliberately block both
// credentials, which this command does only when --confirm-write
// is supplied.
//
// What gets erased:
//   - All 24 PIV slot keypairs and certificates
//   - The slot's PIN, PUK, and management key (returned to defaults)
//   - Any installed OCE roots or chains? No — those live on the
//     Issuer Security Domain, not the PIV applet, and survive a
//     PIV reset.
//
// Use case: provisioned a slot with the wrong cert or wrong slot,
// or want to re-run piv-provision against a clean card without
// physically swapping hardware.
func cmdPIVReset(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv-reset", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	trust := registerTrustFlags(fs)
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, piv-reset runs in dry-run mode and prints what would happen.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	report := &Report{Subcommand: "piv-reset", Reader: *reader}
	data := &pivResetData{}
	report.Data = data

	if !*confirm {
		report.Skip("block PIN", "dry-run; pass --confirm-write to actually run")
		report.Skip("block PUK", "dry-run")
		report.Skip("PIV reset", "dry-run — would erase ALL 24 PIV slots, certs, and reset PIN/PUK/management key")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

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

	// Step 1: block PIN.
	pinAttempts, err := blockPIVPIN(ctx, sess)
	data.PINAttemptsUsed = pinAttempts
	if err != nil {
		report.Fail("block PIN", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PIN: %w", err)
	}
	data.PINBlocked = true
	report.Pass("block PIN", fmt.Sprintf("blocked after %d wrong attempts", pinAttempts))

	// Step 2: block PUK.
	pukAttempts, err := blockPIVPUK(ctx, sess)
	data.PUKAttemptsUsed = pukAttempts
	if err != nil {
		report.Fail("block PUK", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PUK: %w", err)
	}
	data.PUKBlocked = true
	report.Pass("block PUK", fmt.Sprintf("blocked after %d wrong attempts", pukAttempts))

	// Step 3: send the reset APDU.
	resetCmd := piv.Reset()
	resp, err := sess.Transmit(ctx, resetCmd)
	if err != nil {
		report.Fail("PIV reset (transmit)", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("piv reset: %w", err)
	}
	if !resp.IsSuccess() {
		report.Fail("PIV reset", fmt.Sprintf("SW=%04X (both PIN and PUK should now be blocked)", resp.StatusWord()))
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("piv reset: SW=%04X", resp.StatusWord())
	}
	data.ResetSuccess = true
	report.Pass("PIV reset", "applet returned to factory state (PIN=123456, PUK=12345678)")

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	return nil
}

// sessionTransmitter is the minimal subset of *scp11.Session this
// command actually needs — a single Transmit method. Defined as
// a local interface so the helpers can take a stub session in tests.
type sessionTransmitter interface {
	Transmit(context.Context, *apdu.Command) (*apdu.Response, error)
}

// blockPIVPIN sends VERIFY PIN with a deliberately wrong PIN until
// the card returns 6983 (PIN blocked) or runs out of attempts.
// The "wrong" PIN here is "00000000" — distinct from any of the
// common factory defaults (123456, 999999, etc.) so we don't
// accidentally succeed on a card someone left at a non-default
// retail PIN.
//
// Returns the number of attempts made before blocking. The retry
// counter on YubiKey defaults to 3, so 3 attempts is the typical
// answer; the loop caps at 10 to avoid infinite spinning if the
// card returns something unexpected.
func blockPIVPIN(ctx context.Context, sess sessionTransmitter) (int, error) {
	wrong := []byte("00000000")
	for attempt := 1; attempt <= 10; attempt++ {
		cmd, err := piv.VerifyPIN(wrong)
		if err != nil {
			return attempt - 1, fmt.Errorf("build VERIFY PIN: %w", err)
		}
		resp, err := sess.Transmit(ctx, cmd)
		if err != nil {
			return attempt - 1, err
		}
		if resp.StatusWord() == 0x6983 {
			return attempt, nil
		}
		// 63CX = wrong PIN, X retries left. Anything else (9000,
		// 6A86, etc) is unexpected against a card whose PIN we're
		// trying to block; surface it.
		if resp.SW1 != 0x63 {
			return attempt, fmt.Errorf("unexpected SW=%04X attempting to block PIN", resp.StatusWord())
		}
	}
	return 10, errors.New("PIN did not block within 10 attempts")
}

// blockPIVPUK sends RESET RETRY COUNTER with deliberately wrong
// PUK until 6983. Same loop shape as blockPIVPIN; the data field
// of RESET RETRY COUNTER also requires a "new PIN" buffer, which
// we fill with 0xFF — the card never gets to that step because
// it rejects the wrong PUK first.
func blockPIVPUK(ctx context.Context, sess sessionTransmitter) (int, error) {
	wrongPUK := []byte("00000000")
	dummyPIN := []byte("11111111")
	for attempt := 1; attempt <= 10; attempt++ {
		cmd, err := piv.ResetRetryCounter(wrongPUK, dummyPIN)
		if err != nil {
			return attempt - 1, fmt.Errorf("build RESET RETRY COUNTER: %w", err)
		}
		resp, err := sess.Transmit(ctx, cmd)
		if err != nil {
			return attempt - 1, err
		}
		if resp.StatusWord() == 0x6983 {
			return attempt, nil
		}
		if resp.SW1 != 0x63 {
			return attempt, fmt.Errorf("unexpected SW=%04X attempting to block PUK", resp.StatusWord())
		}
	}
	return 10, errors.New("PUK did not block within 10 attempts")
}
