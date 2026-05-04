package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/scp11"
)

type pivProvisionData struct {
	Protocol        string `json:"protocol,omitempty"`
	Slot            string `json:"slot,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
	KeyGenerated    bool   `json:"key_generated"`
	CertInstalled   bool   `json:"cert_installed,omitempty"`
	CertSkipped     bool   `json:"cert_skipped,omitempty"`
	AttestRetrieved bool   `json:"attest_retrieved,omitempty"`
	AttestSkipped   bool   `json:"attest_skipped,omitempty"`
}

// cmdPIVProvision provisions a PIV slot over an SCP-secured channel:
// VERIFY PIN, GENERATE KEY, optionally PUT CERTIFICATE, optionally
// fetch the YubiKey attestation. The whole flow runs through the
// SCP11b session so PIV traffic gets confidentiality and integrity
// from the wire layer.
//
// PIV authorization model (real cards):
//
//   - VERIFY PIN unlocks PIN-gated operations.
//   - GENERATE KEY and PUT CERTIFICATE require PIV management-key
//     auth on stock cards. The piv package does not yet expose a
//     management-key authentication builder, so against a card with
//     a non-default management key, these writes will be refused
//     with 6982. On YubiKey 5.7+ with SCP11 sessions, the card may
//     accept SCP-authenticated provisioning in lieu of management
//     auth — this varies by firmware and configuration.
//
// The mock card does not enforce PIV authorization, so this command
// will appear to succeed end-to-end against the mock regardless of
// what a real card would do. The smoke test value is "did the host
// sequence the right APDUs and survive secure messaging?", not
// "would the card accept this in production?" — the latter requires
// real hardware.
//
// Destructive: writes a freshly generated keypair into the named
// slot, replacing whatever was there. Gated by --confirm-write.
func cmdPIVProvision(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("piv-provision", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	labSkipTrust := fs.Bool("lab-skip-scp11-trust", false,
		"Skip SCP11 card certificate validation. Lab use only.")
	pin := fs.String("pin", "",
		"PIV PIN (required for GENERATE KEY and PUT CERTIFICATE).")
	slotStr := fs.String("slot", "9a",
		"PIV slot in hex (9a=Authentication, 9c=Signature, 9d=KeyMgmt, 9e=CardAuth).")
	algoStr := fs.String("algorithm", "eccp256",
		"Key algorithm: rsa2048, eccp256, eccp384, ed25519 (5.7+), x25519 (5.7+).")
	certPath := fs.String("cert", "",
		"Optional PEM cert to install in the slot after key generation.")
	doAttest := fs.Bool("attest", false,
		"After key generation, request the YubiKey attestation cert.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, piv-provision runs in dry-run mode.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *pin == "" {
		return &usageError{msg: "--pin is required"}
	}
	slot, err := parsePIVSlot(*slotStr)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	algo, algoName, err := parsePIVAlgorithm(*algoStr)
	if err != nil {
		return &usageError{msg: err.Error()}
	}

	report := &Report{Subcommand: "piv-provision", Reader: *reader}
	data := &pivProvisionData{
		Slot:      fmt.Sprintf("0x%02X", slot),
		Algorithm: algoName,
	}
	report.Data = data

	var cert *x509.Certificate
	if *certPath != "" {
		cert, err = loadOneCert(*certPath)
		if err != nil {
			report.Fail("load cert", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("load cert: %w", err)
		}
		report.Pass("load cert", fmt.Sprintf("CN=%q", cert.Subject.CommonName))
	}

	if !*confirm {
		report.Skip("VERIFY PIN", "dry-run; pass --confirm-write to actually run")
		report.Skip("GENERATE KEY", "dry-run")
		if cert != nil {
			report.Skip("PUT CERTIFICATE", "dry-run")
		}
		if *doAttest {
			report.Skip("attestation", "dry-run")
		}
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
	if *labSkipTrust {
		cfg.InsecureSkipCardAuthentication = true
		report.Pass("trust mode", "lab-skip (card cert NOT validated)")
	} else {
		report.Skip("trust mode", "no trust roots configured; use --lab-skip-scp11-trust for wire-protocol smoke")
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

	verifyCmd, err := piv.VerifyPIN([]byte(*pin))
	if err != nil {
		report.Fail("VERIFY PIN (build)", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN build: %w", err)
	}
	resp, err := sess.Transmit(ctx, verifyCmd)
	if err != nil {
		report.Fail("VERIFY PIN (transmit)", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN transmit: %w", err)
	}
	if !resp.IsSuccess() {
		report.Fail("VERIFY PIN", fmt.Sprintf("SW=%04X", resp.StatusWord()))
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("VERIFY PIN: SW=%04X", resp.StatusWord())
	}
	report.Pass("VERIFY PIN", "")

	genCmd := piv.GenerateKey(slot, algo)
	resp, err = sess.Transmit(ctx, genCmd)
	if err != nil {
		report.Fail("GENERATE KEY (transmit)", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("generate key transmit: %w", err)
	}
	if !resp.IsSuccess() {
		report.Fail("GENERATE KEY", fmt.Sprintf("SW=%04X (often 6982 — PIV management auth required)", resp.StatusWord()))
	} else {
		data.KeyGenerated = true
		report.Pass("GENERATE KEY", fmt.Sprintf("slot 0x%02X, %s, %d bytes pubkey returned", slot, algoName, len(resp.Data)))
	}

	if cert != nil && data.KeyGenerated {
		putCmd, err := piv.PutCertificate(slot, cert)
		if err != nil {
			report.Fail("PUT CERTIFICATE (build)", err.Error())
		} else {
			resp, err = sess.Transmit(ctx, putCmd)
			switch {
			case err != nil:
				report.Fail("PUT CERTIFICATE (transmit)", err.Error())
			case !resp.IsSuccess():
				report.Fail("PUT CERTIFICATE", fmt.Sprintf("SW=%04X", resp.StatusWord()))
			default:
				data.CertInstalled = true
				report.Pass("PUT CERTIFICATE", "")
			}
		}
	} else if cert != nil {
		report.Skip("PUT CERTIFICATE", "GENERATE KEY did not succeed")
	} else {
		data.CertSkipped = true
		report.Skip("PUT CERTIFICATE", "--cert not supplied")
	}

	if *doAttest && data.KeyGenerated {
		attestCmd := piv.Attest(slot)
		resp, err = sess.Transmit(ctx, attestCmd)
		switch {
		case err != nil:
			report.Fail("ATTESTATION (transmit)", err.Error())
		case !resp.IsSuccess():
			report.Fail("ATTESTATION", fmt.Sprintf("SW=%04X", resp.StatusWord()))
		default:
			data.AttestRetrieved = true
			report.Pass("ATTESTATION", fmt.Sprintf("%d bytes", len(resp.Data)))
		}
	} else if *doAttest {
		report.Skip("ATTESTATION", "GENERATE KEY did not succeed")
	} else {
		data.AttestSkipped = true
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("piv-provision reported failures")
	}
	return nil
}

// parsePIVSlot parses a hex slot ID like "9a" or "0x9C" into a byte.
// Validates against the small set of PIV slots the piv package knows
// about; an unknown slot is rejected at the CLI boundary so
// PutCertificate doesn't fail later with a less specific error.
func parsePIVSlot(s string) (byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	v, err := strconv.ParseUint(s, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("--slot %q is not a valid hex byte", s)
	}
	slot := byte(v)
	switch slot {
	case piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement,
		piv.SlotCardAuth, piv.SlotRetired1, piv.SlotAttestation:
		return slot, nil
	default:
		return 0, fmt.Errorf("--slot 0x%02X is not a recognized PIV slot (try 9a, 9c, 9d, 9e)", slot)
	}
}

// parsePIVAlgorithm maps a friendly algorithm name to the byte
// constant the piv package uses, plus a display name for the report.
func parsePIVAlgorithm(s string) (byte, string, error) {
	switch strings.ToLower(s) {
	case "rsa2048":
		return piv.AlgoRSA2048, "RSA-2048", nil
	case "eccp256", "ecc-p256", "p256":
		return piv.AlgoECCP256, "ECC P-256", nil
	case "eccp384", "ecc-p384", "p384":
		return piv.AlgoECCP384, "ECC P-384", nil
	case "ed25519":
		return piv.AlgoEd25519, "Ed25519", nil
	case "x25519":
		return piv.AlgoX25519, "X25519", nil
	default:
		return 0, "", fmt.Errorf("--algorithm %q not recognized (rsa2048, eccp256, eccp384, ed25519, x25519)", s)
	}
}

// loadOneCert reads a PEM file expected to contain exactly one
// CERTIFICATE block. Multi-cert chains belong in bootstrap-oce; the
// PIV slot accepts a single leaf cert.
func loadOneCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%q: no PEM block", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%q: PEM type %q, want CERTIFICATE", path, block.Type)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	return c, nil
}

// (apdu import retained because the doc comment references *apdu.Command;
// the actual apdu package usage is via piv.* builders.)
var _ = (*apdu.Command)(nil)
