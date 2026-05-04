package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
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
	MgmtAuthDone    bool   `json:"mgmt_auth_done,omitempty"`
	MgmtAuthSkipped bool   `json:"mgmt_auth_skipped,omitempty"`
	KeyGenerated    bool   `json:"key_generated"`
	CertInstalled   bool   `json:"cert_installed,omitempty"`
	CertSkipped     bool   `json:"cert_skipped,omitempty"`
	AttestRetrieved bool   `json:"attest_retrieved,omitempty"`
	AttestSkipped   bool   `json:"attest_skipped,omitempty"`
}

// cmdPIVProvision provisions a PIV slot over an SCP-secured channel:
// optional management-key mutual auth, VERIFY PIN, GENERATE KEY,
// optionally PUT CERTIFICATE, optionally fetch the YubiKey
// attestation. The whole flow runs through the SCP11b session so PIV
// traffic gets confidentiality and integrity from the wire layer.
//
// PIV authorization model (real cards):
//
//   - GENERATE KEY and PUT CERTIFICATE require PIV management-key
//     auth on stock cards. Pass --mgmt-key (hex) and
//     --mgmt-key-algorithm to run the mutual-auth flow before
//     issuing the writes. Without --mgmt-key, the flow is skipped
//     and writes will fail with 6982 against any card whose
//     management auth is enforced — useful for testing the rest of
//     the sequence against a card you've already authenticated to
//     out of band, or against the mock.
//   - VERIFY PIN unlocks PIN-gated operations. Required for slots
//     9a/9c/9d/9e on the YubiKey.
//
// The mock card does not enforce PIV authorization or verify the
// management-key challenge cryptographically — it ACKs GENERAL
// AUTHENTICATE with synthetic responses so the host's wire flow can
// be smoke-tested. The piv package's own tests cover the crypto
// correctness of the mutual-auth exchange.
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
	mgmtKeyHex := fs.String("mgmt-key", "",
		"PIV management key as hex (e.g. 010203...). If set, runs mutual-auth before GENERATE KEY/PUT CERTIFICATE. "+
			"Pass 'default' to use the well-known pre-5.7 YubiKey factory 3DES key.")
	mgmtKeyAlgoStr := fs.String("mgmt-key-algorithm", "3des",
		"Management-key algorithm: 3des (pre-5.7 default), aes128, aes192 (5.7+ default), aes256.")
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
	var mgmtKey []byte
	var mgmtKeyAlgo byte
	var mgmtKeyAlgoName string
	if *mgmtKeyHex != "" {
		mgmtKey, mgmtKeyAlgo, mgmtKeyAlgoName, err = parseMgmtKey(*mgmtKeyHex, *mgmtKeyAlgoStr)
		if err != nil {
			return &usageError{msg: err.Error()}
		}
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
		if mgmtKey != nil {
			report.Skip("MGMT-KEY AUTH", "dry-run; pass --confirm-write to actually run")
		}
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

	if mgmtKey != nil {
		if err := runMgmtKeyMutualAuth(ctx, sess, mgmtKey, mgmtKeyAlgo, mgmtKeyAlgoName, report); err != nil {
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		data.MgmtAuthDone = true
	} else {
		data.MgmtAuthSkipped = true
		report.Skip("MGMT-KEY AUTH", "no --mgmt-key supplied; GENERATE KEY/PUT CERTIFICATE may be refused with 6982")
	}

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
		hint := ""
		if mgmtKey == nil {
			hint = " (likely needs --mgmt-key to authenticate first)"
		}
		report.Fail("GENERATE KEY", fmt.Sprintf("SW=%04X%s", resp.StatusWord(), hint))
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

// runMgmtKeyMutualAuth orchestrates the two-APDU PIV management-key
// mutual auth exchange. Reports each step to `report` so failures
// surface specifically (challenge-build, parse-witness, response-build,
// or final-verify) rather than collapsing into one opaque "auth
// failed."
func runMgmtKeyMutualAuth(ctx context.Context, sess interface {
	Transmit(context.Context, *apdu.Command) (*apdu.Response, error)
}, mgmtKey []byte, algo byte, algoName string, report *Report) error {
	// Step 1: request witness.
	chal := piv.MgmtKeyMutualAuthChallenge(algo)
	resp, err := sess.Transmit(ctx, chal)
	if err != nil {
		report.Fail("MGMT-KEY AUTH (request witness)", err.Error())
		return fmt.Errorf("mgmt-key auth request witness: %w", err)
	}
	if !resp.IsSuccess() {
		report.Fail("MGMT-KEY AUTH (request witness)", fmt.Sprintf("SW=%04X", resp.StatusWord()))
		return fmt.Errorf("mgmt-key auth request witness: SW=%04X", resp.StatusWord())
	}
	witness, err := piv.ParseMutualAuthWitness(resp.Data, algo)
	if err != nil {
		report.Fail("MGMT-KEY AUTH (parse witness)", err.Error())
		return fmt.Errorf("parse witness: %w", err)
	}

	// Step 2: respond with decrypted witness + fresh challenge.
	respCmd, hostChallenge, err := piv.MgmtKeyMutualAuthRespond(witness, mgmtKey, algo)
	if err != nil {
		report.Fail("MGMT-KEY AUTH (build response)", err.Error())
		return fmt.Errorf("build response: %w", err)
	}
	resp, err = sess.Transmit(ctx, respCmd)
	if err != nil {
		report.Fail("MGMT-KEY AUTH (transmit response)", err.Error())
		return fmt.Errorf("mgmt-key auth transmit response: %w", err)
	}
	if !resp.IsSuccess() {
		report.Fail("MGMT-KEY AUTH (response)", fmt.Sprintf("SW=%04X", resp.StatusWord()))
		return fmt.Errorf("mgmt-key auth response: SW=%04X", resp.StatusWord())
	}

	// Step 3: verify the card's response under our challenge.
	if err := piv.VerifyMutualAuthResponse(resp.Data, hostChallenge, mgmtKey, algo); err != nil {
		report.Fail("MGMT-KEY AUTH (verify card)", err.Error())
		return fmt.Errorf("verify card response: %w", err)
	}

	report.Pass("MGMT-KEY AUTH", algoName)
	return nil
}

// parseMgmtKey decodes the --mgmt-key flag value and validates it
// matches the algorithm's expected length. Accepts the literal
// string "default" as a shortcut for the well-known pre-5.7 YubiKey
// 3DES factory key, which only makes sense with --mgmt-key-algorithm
// 3des.
func parseMgmtKey(hexStr, algoStr string) ([]byte, byte, string, error) {
	algo, name, err := parseMgmtKeyAlgorithm(algoStr)
	if err != nil {
		return nil, 0, "", err
	}
	var key []byte
	if strings.EqualFold(hexStr, "default") {
		if algo != piv.AlgoMgmt3DES {
			return nil, 0, "", fmt.Errorf("--mgmt-key=default is only valid with --mgmt-key-algorithm=3des")
		}
		key = append([]byte{}, piv.DefaultMgmt3DESKey...)
	} else {
		// Allow whitespace/colons in the hex for paste-from-docs convenience.
		clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(hexStr)
		key, err = hex.DecodeString(clean)
		if err != nil {
			return nil, 0, "", fmt.Errorf("--mgmt-key not valid hex: %w", err)
		}
	}
	wantLen := map[byte]int{
		piv.AlgoMgmt3DES:   24,
		piv.AlgoMgmtAES128: 16,
		piv.AlgoMgmtAES192: 24,
		piv.AlgoMgmtAES256: 32,
	}[algo]
	if len(key) != wantLen {
		return nil, 0, "", fmt.Errorf("--mgmt-key length %d does not match --mgmt-key-algorithm=%s (want %d bytes)",
			len(key), algoStr, wantLen)
	}
	return key, algo, name, nil
}

func parseMgmtKeyAlgorithm(s string) (byte, string, error) {
	switch strings.ToLower(s) {
	case "3des", "tdes":
		return piv.AlgoMgmt3DES, "3DES", nil
	case "aes128", "aes-128":
		return piv.AlgoMgmtAES128, "AES-128", nil
	case "aes192", "aes-192":
		return piv.AlgoMgmtAES192, "AES-192", nil
	case "aes256", "aes-256":
		return piv.AlgoMgmtAES256, "AES-256", nil
	default:
		return 0, "", fmt.Errorf("--mgmt-key-algorithm %q not recognized (3des, aes128, aes192, aes256)", s)
	}
}
