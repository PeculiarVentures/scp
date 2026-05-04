package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/piv/session"
)

// pivInfoData is the JSON-friendly payload of a `piv info` report.
type pivInfoData struct {
	Profile        string `json:"profile"`
	YubiKeyVersion string `json:"yubikey_version,omitempty"`
	PIVVersion     string `json:"piv_version,omitempty"`
	SelectRawHex   string `json:"select_raw_hex,omitempty"`

	// Capabilities is a flattened list of feature names the active
	// profile claims. Stable strings ('reset', 'attestation',
	// 'pin-policy', etc.) so machine consumers don't have to follow
	// a Go struct shape.
	Capabilities []string `json:"capabilities"`
}

// cmdPIVInfo opens a raw transport to the card, runs the
// non-destructive PIV probe (SELECT AID PIV + GET VERSION on
// YubiKey), and reports what was found plus the resulting
// capability profile.
//
// This is the user-facing equivalent of the lower-level `probe`
// command, which probes the Security Domain and parses Card
// Recognition Data. `piv info` answers a different question:
// 'what does the PIV applet on this card look like and what
// operations can the library safely run against it?'
//
// No authentication is performed. No state-changing APDU is
// emitted. Two APDUs total: SELECT AID PIV, GET VERSION (the
// latter returns 6D00 on Standard PIV cards and the probe falls
// through to the Standard PIV profile).
func cmdPIVInfo(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv info", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "piv info", Reader: *reader}

	// session.New runs SELECT AID PIV and (when no profile is
	// pre-supplied) calls profile.Probe internally. We want the raw
	// probe result for diagnostics, so call Probe explicitly and
	// then construct the session with the result.
	probeRes, err := profile.Probe(ctx, t)
	if err != nil {
		report.Fail("probe", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("probe", fmt.Sprintf("profile=%s", probeRes.Profile.Name()))

	sess, err := session.New(ctx, t, session.Options{
		Profile:   probeRes.Profile,
		SkipProbe: true,
	})
	if err != nil {
		report.Fail("session", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	defer sess.Close()

	caps := probeRes.Profile.Capabilities()
	data := pivInfoData{
		Profile:      probeRes.Profile.Name(),
		Capabilities: capabilityNames(caps),
	}
	if probeRes.YubiKeyFW != nil {
		data.YubiKeyVersion = probeRes.YubiKeyFW.String()
	}
	if probeRes.PIVVersion != nil {
		data.PIVVersion = hex.EncodeToString(probeRes.PIVVersion)
	}
	if probeRes.SelectResponse != nil {
		data.SelectRawHex = hex.EncodeToString(probeRes.SelectResponse)
	}
	report.Data = data
	report.Pass("capabilities", strings.Join(data.Capabilities, ", "))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("piv info had failures")
	}
	return nil
}

// capabilityNames flattens a Capabilities struct into the list of
// short names the JSON consumer sees. Order is deterministic so JSON
// diffs are stable across runs.
func capabilityNames(caps profile.Capabilities) []string {
	var names []string
	if caps.StandardPIV {
		names = append(names, "standard-piv")
	}
	if caps.KeyImport {
		names = append(names, "key-import")
	}
	if caps.KeyDelete {
		names = append(names, "key-delete")
	}
	if caps.KeyMove {
		names = append(names, "key-move")
	}
	if caps.Reset {
		names = append(names, "reset")
	}
	if caps.Attestation {
		names = append(names, "attestation")
	}
	if caps.PINPolicy {
		names = append(names, "pin-policy")
	}
	if caps.TouchPolicy {
		names = append(names, "touch-policy")
	}
	if caps.ProtectedManagementKey {
		names = append(names, "protected-mgmt-key")
	}
	if caps.SCP11bPIV {
		names = append(names, "scp11b-piv")
	}
	for _, a := range caps.Algorithms {
		names = append(names, "alg:"+a.String())
	}
	return names
}
