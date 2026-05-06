package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// scp03SDReadData is the JSON payload — count of key info entries
// observed and the protocol string from Session.Protocol().
type scp03SDReadData struct {
	Protocol   string `json:"protocol,omitempty"`
	KeyEntries int    `json:"key_entries,omitempty"`
	CRDBytes   int    `json:"crd_bytes,omitempty"`
}

// cmdSCP03SDRead opens an SCP03 Security Domain session using factory
// YubiKey credentials by default, then verifies that two read-only
// commands succeed: GetKeyInformation and GetCardRecognitionData.
//
// Why both? GetKeyInformation exercises the SD-specific read path
// and confirms the card's key inventory is reachable. GetCardRecognitionData
// over an authenticated session confirms the secure-messaging wrap
// is correctly applied to the same APDU that the unauthenticated
// probe used — a cheap way to catch SCP03 wrap bugs that only show
// up under real card behavior.
//
// References:
//   - YubiKey Technical Manual: factory SCP03 KVN 0xFF, key bytes
//     404142434445464748494A4B4C4D4E4F.
//     https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-scp-specifics.html
//   - Yubico .NET SDK: SecurityDomainSession.GetCardRecognitionData,
//     GetKeyInformation; default SCP03 key set is publicly known.
func cmdSCP03SDRead(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("test scp03-sd-read", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	scp03Keys := registerSCP03KeyFlags(fs, scp03Required)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "test scp03-sd-read", Reader: *reader}
	data := &scp03SDReadData{}
	report.Data = data
	report.Pass("SCP03 keys", scp03Keys.describeKeys(cfg))

	sd, err := securitydomain.OpenSCP03(ctx, t, cfg)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP03 SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP03 SD", "factory KVN 0xFF")

	if !sd.IsAuthenticated() {
		report.Fail("authenticated", "Session.IsAuthenticated() is false after Open")
	} else {
		report.Pass("authenticated", "")
	}

	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		report.Fail("GetKeyInformation", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("get key information: %w", err)
	}
	data.KeyEntries = len(keys)
	report.Pass("GetKeyInformation", fmt.Sprintf("%d entries", len(keys)))

	crd, err := sd.GetCardRecognitionData(ctx)
	if err != nil {
		report.Fail("GetCardRecognitionData over SCP03", err.Error())
	} else {
		data.CRDBytes = len(crd)
		report.Pass("GetCardRecognitionData over SCP03", fmt.Sprintf("%d bytes", len(crd)))
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("scp03-sd-read reported failures")
	}
	return nil
}
