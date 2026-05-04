package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	pivapdu "github.com/PeculiarVentures/scp/piv/apdu"
	pivsession "github.com/PeculiarVentures/scp/piv/session"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
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
	maxAttempts := fs.Int("max-block-attempts", 16,
		"Maximum wrong-PIN/wrong-PUK attempts before giving up trying to block "+
			"a credential. YubiKey defaults to 3 retries, so 3 attempts is the typical "+
			"answer; the cap exists so a card returning unexpected status doesn't loop "+
			"forever. Yubico supports retry counts up to 255; raise this for cards "+
			"configured with high retry counts.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *maxAttempts < 1 || *maxAttempts > 255 {
		return &usageError{msg: fmt.Sprintf(
			"--max-block-attempts must be in [1, 255]; got %d", *maxAttempts)}
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

	// SCP11b-on-PIV layering: the SD owns the SCP11 cert/key
	// material (BF21), not PIV. Selecting PIV first and asking it
	// for BF21 returns SW=6D00. The fix from PR #74: discover the
	// card's SD static public key over an unauthenticated SD
	// session first, then open SCP11b against PIV with the
	// pre-verified key supplied via PreverifiedCardStaticPublicKey
	// so scp11.Open skips its SD round-trip.
	//
	// Inlined here (rather than going through piv/session.OpenSCP11bPIV)
	// because the helpers below need raw *scp11.Session.Transmit:
	// blockPIVPIN/blockPIVPUK inspect SW=6983 and 63Cx directly,
	// statuses that piv/session.Session.transmit translates into
	// errors. Inlining keeps the high-level wrapper for normal PIV
	// flows and gives this lower-level command direct wire access.
	pivOpts := pivsession.SCP11bPIVOptions{}
	proceed, err := trust.applyTrustToPIV(&pivOpts, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	pubKey, err := securitydomain.FetchCardPublicKey(ctx, t, securitydomain.FetchCardPublicKeyOptions{
		KeyReference:                   securitydomain.NewKeyReference(securitydomain.KeyIDSCP11b, 0x01),
		CardTrustPolicy:                pivOpts.CardTrustPolicy,
		InsecureSkipCardAuthentication: pivOpts.InsecureSkipCardAuthentication,
	})
	if err != nil {
		report.Fail("resolve PK.SD.ECKA", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("resolve PK.SD.ECKA: %w", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.SelectAID = scp11.AIDPIV
	cfg.ApplicationAID = nil
	cfg.PreverifiedCardStaticPublicKey = pubKey
	cfg.CardTrustPolicy = pivOpts.CardTrustPolicy
	cfg.InsecureSkipCardAuthentication = pivOpts.InsecureSkipCardAuthentication

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
	pinAttempts, err := blockPIVPIN(ctx, sess, *maxAttempts)
	data.PINAttemptsUsed = pinAttempts
	if err != nil {
		report.Fail("block PIN", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PIN: %w", err)
	}
	data.PINBlocked = true
	report.Pass("block PIN", fmt.Sprintf("blocked after %d wrong attempts", pinAttempts))

	// Step 2: block PUK.
	pukAttempts, err := blockPIVPUK(ctx, sess, *maxAttempts)
	data.PUKAttemptsUsed = pukAttempts
	if err != nil {
		report.Fail("block PUK", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("block PUK: %w", err)
	}
	data.PUKBlocked = true
	report.Pass("block PUK", fmt.Sprintf("blocked after %d wrong attempts", pukAttempts))

	// Step 3: send the reset APDU.
	resetCmd := pivapdu.Reset()
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
// retail PIN. (If somebody's actual PIN really is "00000000", the
// 9000 response triggers the unexpected-SW abort below — safer
// than completing the reset against the wrong assumptions.)
//
// Returns the number of attempts made before blocking. The retry
// counter on YubiKey defaults to 3, so 3 attempts is the typical
// answer; maxAttempts caps the loop so a card returning unexpected
// status doesn't loop forever. Yubico supports retry counts up to
// 255 and the CLI flag exposes that range.
func blockPIVPIN(ctx context.Context, sess sessionTransmitter, maxAttempts int) (int, error) {
	wrong := []byte("00000000")
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd, err := pivapdu.VerifyPIN(wrong)
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
	return maxAttempts, fmt.Errorf("PIN did not block within %d attempts (raise --max-block-attempts if the card has a higher retry counter)", maxAttempts)
}

// blockPIVPUK sends RESET RETRY COUNTER with deliberately wrong
// PUK until 6983. Same loop shape as blockPIVPIN; the data field
// of RESET RETRY COUNTER also requires a "new PIN" buffer, which
// we fill with 0xFF — the card never gets to that step because
// it rejects the wrong PUK first.
func blockPIVPUK(ctx context.Context, sess sessionTransmitter, maxAttempts int) (int, error) {
	wrongPUK := []byte("00000000")
	dummyPIN := []byte("11111111")
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cmd, err := pivapdu.ResetRetryCounter(wrongPUK, dummyPIN)
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
	return maxAttempts, fmt.Errorf("PUK did not block within %d attempts (raise --max-block-attempts if the card has a higher retry counter)", maxAttempts)
}
