package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
)

type scp11bSDReadData struct {
	Protocol         string `json:"protocol,omitempty"`
	OCEAuthenticated bool   `json:"oce_authenticated"`
	KeyEntries       int    `json:"key_entries,omitempty"`
}

// cmdSCP11bSDRead opens an SCP11b SD session and verifies a read works.
//
// SCP11b authenticates the card to the host but NOT the host (OCE) to
// the card; this command therefore deliberately verifies that
// Session.OCEAuthenticated() is false. SCP11b is appropriate for
// read-only Security Domain operations and PIV traffic, but not for
// SD writes — the smoke test only exercises the read path.
//
// Trust model:
//
//	--lab-skip-scp11-trust skips the card-certificate validation that
//	would otherwise verify the card's SCP11 certificate against a
//	pinned root or trust policy. Use only in lab settings where the
//	intent is to separate SCP11 wire-protocol failures from
//	trust-bootstrap failures. For production confidence, leave the
//	flag off and configure trust roots.
//
// References:
//   - Yubico Android docs: SCP11 supported, requires firmware 5.7.2+,
//     extended APDU support over NFC.
//   - GP Card Spec v2.3.1 Amendment F (SCP11 specification).
func cmdSCP11bSDRead(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("scp11b-sd-read", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	trust := registerTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "scp11b-sd-read", Reader: *reader}
	data := &scp11bSDReadData{}
	report.Data = data

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
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
		report.Fail("open SCP11b SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP11b SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP11b SD", "")

	// SCP11b must NOT be OCE-authenticated. If it is, either we
	// opened the wrong protocol or the library has a bug — either
	// way the smoke test should fail loudly.
	data.OCEAuthenticated = sd.OCEAuthenticated()
	if sd.OCEAuthenticated() {
		report.Fail("SCP11b is not OCE-authenticated", "Session.OCEAuthenticated() = true")
	} else {
		report.Pass("SCP11b is not OCE-authenticated", "")
	}

	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		report.Fail("GetKeyInformation over SCP11b", err.Error())
	} else {
		data.KeyEntries = len(keys)
		report.Pass("GetKeyInformation over SCP11b", fmt.Sprintf("%d entries", len(keys)))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("scp11b-sd-read reported failures")
	}
	return nil
}
