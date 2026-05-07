package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/yubikey"
)

type scp11bSDReadData struct {
	Protocol         string `json:"protocol,omitempty"`
	OCEAuthenticated bool   `json:"oce_authenticated"`
	KeyEntries       int    `json:"key_entries,omitempty"`
	BF21Hex          string `json:"bf21_hex,omitempty"`
	BF21Certs        int    `json:"bf21_certs,omitempty"`
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
// Diagnostic flags:
//
//	--dump-bf21 issues an unauthenticated SELECT-SD + GET DATA BF21
//	with the configured key reference before opening SCP11, and
//	prints the raw response hex plus the count of decoded
//	certificates. Useful when SCP11 open fails with a parser error
//	("no EC public key found in data") and you need to see what
//	shape the card actually returned. Independent of trust mode.
//
// References:
//   - Yubico Android docs: SCP11 supported, requires firmware 5.7.2+,
//     extended APDU support over NFC.
//   - GP Card Spec v2.3.1 Amendment F (SCP11 specification).
func cmdSCP11bSDRead(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("test scp11b-sd-read", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	dumpBF21 := fs.Bool("dump-bf21", false,
		"Diagnostic: dump the raw GET DATA BF21 response from the Security "+
			"Domain before opening SCP11. Helps when the SCP11 open fails "+
			"in the certificate parser — the hex shows what the card "+
			"actually returned.")
	trust := registerTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report := &Report{Subcommand: "test scp11b-sd-read", Reader: *reader}
	data := &scp11bSDReadData{}
	report.Data = data

	if *dumpBF21 {
		if err := dumpSCP11bCertStore(ctx, t, data, report); err != nil {
			// Diagnostic dump failures are reported on the report
			// but don't abort the smoke; SCP11 open may still
			// succeed if the card spoke up on the second try.
			report.Fail("dump BF21", err.Error())
		}
	}

	cfg := yubikey.SCP11bConfig()
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

// dumpSCP11bCertStore performs an unauthenticated SELECT-SD followed
// by GET DATA BF21 with the SCP11b key reference (KID=0x13, KVN=0x01),
// and records the raw response on the report. This runs *before*
// SCP11 open so it can surface the bytes even when the SCP11 cert
// parser would reject them.
//
// The SD session is closed before returning so it doesn't conflict
// with the subsequent SCP11 open against the same transport.
func dumpSCP11bCertStore(
	ctx context.Context,
	t transport.Transport,
	data *scp11bSDReadData,
	report *Report,
) error {
	sd, err := securitydomain.OpenUnauthenticated(ctx, t)
	if err != nil {
		return fmt.Errorf("open SD: %w", err)
	}
	defer sd.Close()

	ref := securitydomain.NewKeyReference(securitydomain.KeyIDSCP11b, 0x01)
	raw, err := sd.GetData(ctx, 0xBF21, buildBF21Request(ref))
	if err != nil {
		return fmt.Errorf("GET DATA BF21: %w", err)
	}
	data.BF21Hex = hex.EncodeToString(raw)

	// Best-effort cert count for the report; failure here is not
	// fatal — the hex dump is the primary diagnostic.
	if certs, _ := securitydomain.OpenUnauthenticated(ctx, t); certs != nil {
		certs.Close()
	}
	if list, err := sd.GetCertificates(ctx, ref); err == nil {
		data.BF21Certs = len(list)
	}

	report.Pass("dump BF21", fmt.Sprintf("%d bytes (%d cert(s) decoded)",
		len(raw), data.BF21Certs))
	return nil
}

// buildBF21Request builds the data field for GET DATA BF21:
// A6 04 83 02 KID KVN — the control reference template with the key
// identifier sub-TLV. Matches Yubico yubikit's get_certificate_bundle
// shape.
func buildBF21Request(ref securitydomain.KeyReference) []byte {
	return []byte{0xA6, 0x04, 0x83, 0x02, ref.ID, ref.Version}
}
