package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/scp/piv"
	pivsession "github.com/PeculiarVentures/scp/piv/session"
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
	fs := newSubcommandFlagSet("piv provision", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	trust := registerTrustFlags(fs)
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

	report := &Report{Subcommand: "piv provision", Reader: *reader}
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

	// Open SCP11b against PIV via the SD-first-then-PIV path.
	// pivsession.OpenSCP11bPIV resolves PK.SD.ECKA from the
	// Security Domain (where BF21 actually lives), validates the
	// chain, then opens scp11 against PIV with the preverified
	// key — bypassing the broken "GET DATA BF21 against PIV
	// returns 6D00" path that the deprecated
	// scp11.Open(cfg{SelectAID:AIDPIV}) shape would hit.
	//
	// Per the fourth external review, cross-branch issue #2:
	// 'A later commit documents that piv-reset was still using
	//  an old path: set SelectAID = PIV, then scp11.Open, which
	//  tried to fetch BF21 from PIV and got 6D00. The fix was to
	//  fetch the SD public key from the SD first, then open
	//  SCP11b against PIV with the preverified key.'
	//
	// Other piv operator commands (piv reset, piv pin, etc.)
	// already migrated to OpenSCP11bPIV via openPIVSession; this
	// brings piv provision in line. Mock tests passed against
	// the deprecated shape because mockcard answered BF21 from
	// any selected applet; real cards (including YubiKey 5.7+)
	// return 6D00 for BF21 against PIV per the comment in
	// scp11/scp11.go on PreverifiedCardStaticPublicKey.
	var sessOpts pivsession.SCP11bPIVOptions
	proceed, err := trust.applyTrustToPIV(&sessOpts, report)
	if err != nil {
		return err
	}
	if !proceed {
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	sess, err := pivsession.OpenSCP11bPIV(ctx, t, sessOpts)
	if err != nil {
		report.Fail("open SCP11b vs PIV", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP11b vs PIV: %w", err)
	}
	defer sess.Close()
	data.Protocol = "SCP11b"
	report.Pass("open SCP11b vs PIV", "")

	if mgmtKey != nil {
		mk := piv.ManagementKey{
			Algorithm: piv.ManagementKeyAlgorithm(mgmtKeyAlgo),
			Key:       mgmtKey,
		}
		if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
			report.Fail("MGMT-KEY AUTH", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("mgmt-key auth: %w", err)
		}
		report.Pass("MGMT-KEY AUTH", mgmtKeyAlgoName)
		data.MgmtAuthDone = true
	} else {
		data.MgmtAuthSkipped = true
		report.Skip("MGMT-KEY AUTH", "no --mgmt-key supplied; GENERATE KEY/PUT CERTIFICATE may be refused with 6982")
	}

	if err := sess.VerifyPIN(ctx, []byte(*pin)); err != nil {
		report.Fail("VERIFY PIN", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("verify PIN: %w", err)
	}
	report.Pass("VERIFY PIN", "")

	generatedPub, err := sess.GenerateKey(ctx, piv.Slot(slot), pivsession.GenerateKeyOptions{
		Algorithm: piv.Algorithm(algo),
	})
	if err != nil {
		hint := ""
		if mgmtKey == nil {
			hint = " (likely needs --mgmt-key to authenticate first)"
		}
		report.Fail("GENERATE KEY", err.Error()+hint)
	} else {
		data.KeyGenerated = true
		report.Pass("GENERATE KEY", fmt.Sprintf("slot 0x%02X, %s", slot, algoName))
		report.Pass("parse pubkey", describePub(generatedPub))
	}

	if cert != nil && data.KeyGenerated {
		// Cert-to-pubkey binding check is now performed by
		// pivsession.PutCertificate when RequirePubKeyBinding is
		// set. ExpectedPublicKey defaults to the most recent
		// GenerateKey result on the same slot, which is exactly
		// what we want here.
		err := sess.PutCertificate(ctx, piv.Slot(slot), cert, pivsession.PutCertificateOptions{
			RequirePubKeyBinding: true,
			ExpectedPublicKey:    generatedPub,
		})
		switch {
		case err != nil && strings.Contains(err.Error(), "public key does not match"):
			// Library-side cert-to-pubkey binding refusal —
			// pivsession.PutCertificate returns this when
			// RequirePubKeyBinding is set and the cert's SPKI
			// doesn't match ExpectedPublicKey. The error has no
			// sentinel today; matching the substring is the
			// only way to distinguish from a card-side SW
			// failure that happens to mention "public key".
			// String-matching is fragile; if a sentinel error
			// gets added in piv/session/keys.go, switch to
			// errors.Is at that point.
			report.Fail("cert binding", fmt.Sprintf(
				"cert public key does not match slot 0x%02X generated key — refusing to install",
				slot))
			data.CertInstalled = false
			_ = report.Emit(env.out, *jsonMode)
			return fmt.Errorf("cert/pubkey mismatch on slot 0x%02X: %w", slot, err)
		case err != nil:
			report.Fail("PUT CERTIFICATE", err.Error())
		default:
			report.Pass("cert binding", "cert matches generated slot key")
			data.CertInstalled = true
			report.Pass("PUT CERTIFICATE", "")
		}
	} else if cert != nil {
		report.Skip("PUT CERTIFICATE", "GENERATE KEY did not succeed")
	} else {
		data.CertSkipped = true
		report.Skip("PUT CERTIFICATE", "--cert not supplied")
	}

	if *doAttest && data.KeyGenerated {
		// pivsession.Attest internally drives GET RESPONSE
		// chaining for SW=61xx (which is what real YubiKey 5.7+
		// returns for ATTEST because the cert chain spans
		// multiple frames) and parses the result into a
		// *x509.Certificate. The earlier raw-APDU path used
		// apdu.TransmitWithChaining and returned bytes; the
		// high-level method does both pieces.
		attestCert, err := sess.Attest(ctx, piv.Slot(slot))
		switch {
		case err != nil:
			report.Fail("ATTESTATION", err.Error())
		default:
			data.AttestRetrieved = true
			report.Pass("ATTESTATION", fmt.Sprintf("CN=%q", attestCert.Subject.CommonName))
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
		piv.SlotCardAuth, piv.SlotAttestation:
		return slot, nil
	}
	// Retired key management slots 1..20 (0x82..0x95) per
	// SP 800-73-4 Part 1 Table 4b. The piv package's slotToObjectID
	// already supports the full range; the CLI was previously only
	// accepting SlotRetired1, which made the other 19 retired slots
	// unreachable from the command line.
	if slot >= piv.SlotRetired1 && slot <= piv.SlotRetired20 {
		return slot, nil
	}
	return 0, fmt.Errorf("--slot 0x%02X is not a recognized PIV slot "+
		"(try 9a/9c/9d/9e for primary slots, 82-95 for retired key management 1-20, "+
		"or f9 for YubiKey attestation)", slot)
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
		// Per Yubico's PIV docs, the well-known default management
		// key value is shared by 3DES (firmware < 5.7) and AES-192
		// (firmware 5.7+) — both are 24 bytes and use the same
		// 010203040506070801020304050607080102030405060708 value.
		// AES-128 (16 bytes) and AES-256 (32 bytes) have different
		// lengths, so "default" doesn't apply to them; reject those
		// combinations at the CLI boundary.
		if algo != piv.AlgoMgmt3DES && algo != piv.AlgoMgmtAES192 {
			return nil, 0, "", fmt.Errorf(
				"--mgmt-key=default is only valid with --mgmt-key-algorithm=3des or aes192 " +
					"(the well-known default value is 24 bytes; AES-128/256 use different key lengths)")
		}
		key = append([]byte{}, piv.DefaultMgmtKey...)
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

// describePub renders a parsed public key in a human-readable form
// for the report. Just enough to give the operator confidence the
// right shape came back.
func describePub(k crypto.PublicKey) string {
	switch v := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", v.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", v.Curve.Params().Name)
	case ed25519.PublicKey:
		return fmt.Sprintf("Ed25519 (%d bytes)", len(v))
	default:
		return fmt.Sprintf("%T", k)
	}
}
