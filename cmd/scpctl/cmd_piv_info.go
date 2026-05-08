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

	// Notes carries human- and machine-readable advisories about the
	// detected profile. The Standard PIV profile's identity detection
	// and capability classification are hardware-verified against a
	// non-YubiKey card; cryptographic operations (PIN verify, mgmt-key
	// auth, GENERATE KEY, certificate operations, attestation) are
	// not yet hardware-verified against a non-YubiKey card. That fact
	// surfaces here so operators and automation see it without
	// consulting docs/piv-compatibility.md.
	Notes []string `json:"notes,omitempty"`
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
	// Standard PIV identity detection and capability classification
	// are spec-implemented and have been hardware-verified against
	// non-YubiKey cards (GoldKey Security PIV Token, Feitian-built
	// Taglio PIVKey; both May 2026). Cryptographic operations
	// (PIN verify, mgmt-key auth, GENERATE KEY, certificate
	// operations, attestation) are not yet hardware-verified
	// against a non-YubiKey card. Surface the precise scope in
	// the machine output and human report so it does not require
	// consulting docs/piv-compatibility.md.
	if caps.StandardPIV {
		data.Notes = append(data.Notes,
			"standard-piv profile: identity detection and capability classification verified against non-YubiKey hardware; cryptographic operations (PIN verify, mgmt-key auth, GENERATE KEY, certificate operations, attestation) not yet hardware-verified against a non-YubiKey card. See docs/piv-compatibility.md.")
	}

	// ROCA (CVE-2017-15361 / Yubico YSA-2017-01) affects YubiKey
	// firmware 4.2.6 through 4.3.4 inclusive. RSA keys generated
	// on-card in this firmware range are factorable in practice.
	// Surface this on the operator's first contact with the card,
	// not buried in a doc, because the failure mode is silent: a
	// 'piv info' that doesn't mention it will let an operator
	// proceed to GENERATE KEY (RSA) and produce a key that looks
	// fine but is compromised. ECC keys and imported RSA keys are
	// unaffected, so the disclosure has to be precise about scope.
	if probeRes.YubiKeyFW != nil && probeRes.YubiKeyFW.IsROCAAffected() {
		data.Notes = append(data.Notes,
			fmt.Sprintf("YubiKey firmware %s is in the ROCA-affected range (4.2.6 through 4.3.4 inclusive, "+
				"per Yubico Security Advisory YSA-2017-01 / CVE-2017-15361). RSA keys GENERATED on-card by "+
				"this firmware are factorable in practice. ECC keys (P-256, P-384) and RSA keys IMPORTED "+
				"onto the card are unaffected. Yubico fixed the issue in firmware 4.3.5+.",
				probeRes.YubiKeyFW))
	}
	report.Data = data
	report.Pass("capabilities", strings.Join(data.Capabilities, ", "))
	for _, note := range data.Notes {
		report.Skip("note", note)
	}

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
