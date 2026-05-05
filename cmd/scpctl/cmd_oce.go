// Off-card OCE chain diagnostics + a known-good chain generator.
//
// Why this exists: SCP11a PERFORM SECURITY OPERATION rejects an
// OCE leaf with SW=6A80 when the leaf's signature does not verify
// against the CA-KLOC public key installed at KID=0x10. The card
// gives no further information. The two ways to land in that state
// are (a) the leaf was actually signed by a different CA than the
// one in chain[0], or (b) the cert profile contains something the
// card's strict ECDSA / X.509 parser rejects.
//
// 'scpctl oce verify' answers (a) off-card. If the leaf signature
// verifies against chain[0]'s public key here, the card SHOULD
// also accept it per GP Amendment F §6 ("the SD shall verify [...]
// the signature of the certificate, using the PK.CA-KLOC.ECDSA
// referenced in the command. [...] All other fields of the
// certificate may be ignored by the SD"). If it doesn't verify
// here, no point trying it on hardware: the chain is broken.
//
// 'scpctl oce gen' produces a chain that follows the canonical
// SCP11a OCE profile (P-256 ECDSA-SHA256, BasicConstraints CA:TRUE
// on the root, KeyUsage keyAgreement on the leaf, AKI/SKI in the
// usual extension form). This is the reference fixture: if scpctl
// oce verify says it's clean and PSO still 6A80s with the same
// material on hardware, the bug is in scpctl's PutECPublicKey or
// StoreCaIssuer wire shape, not the cert.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 SKI computation requires SHA-1
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// oceCommands maps the oce-group subcommand names. The 'oce' group
// is operator-facing and host-only — none of these subcommands
// touch a card. They exist purely to diagnose / produce the OCE
// material that subsequent on-card flows (bootstrap-scp11a,
// scp11a-sd-read) consume.
var oceCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"verify": cmdOCEVerify,
	"gen":    cmdOCEGen,
}

func oceUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl oce - Off-card OCE certificate diagnostics and generation

Usage:
  scpctl oce <subcommand> [flags]

Subcommands:
  verify   Validate an OCE certificate chain off-card. Confirms
           chain[0] is self-signed, every leaf-towards-root signature
           verifies, and surfaces extension and signature-encoding
           details that the card may be strict about. Does NOT touch
           a card.
  gen      Generate a fresh, known-good OCE certificate chain
           following the canonical SCP11a OCE profile. Use this
           when you suspect your existing OCE material is the
           reason PSO is rejecting your leaf cert with SW=6A80.

Use "scpctl oce <subcommand> -h" for per-command flags.
`)
}

// --- verify -----------------------------------------------------------------

// cmdOCEVerify is the off-card chain validator. It loads a PEM file
// of one or more X.509 certificates in leaf-last order and reports
// whether the chain is internally consistent in the ways that
// matter for SCP11a PSO.
func cmdOCEVerify(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("oce verify", env)
	chainPath := fs.String("chain", "", "Path to PEM file containing the OCE certificate chain (leaf-last).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *chainPath == "" {
		return &usageError{msg: "--chain is required"}
	}

	report := &Report{Subcommand: "oce verify"}

	chain, err := loadCertChainPEM(*chainPath)
	if err != nil {
		report.Fail("load chain", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("load chain", fmt.Sprintf("%d certs from %s", len(chain), *chainPath))

	if len(chain) == 0 {
		report.Fail("chain length", "no certs in PEM file")
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("no certs in %s", *chainPath)
	}

	// Anchor: chain[0] must be self-signed for SCP11a OCE installation.
	// scpctl's bootstrap installs chain[0]'s public key at KID=0x10 as
	// PK.CA-KLOC.ECDSA. The card uses that key to verify the leaf's
	// signature during PSO. So chain[0] must be (a) ECDSA P-256 and
	// (b) self-signed (otherwise the chain is half-rooted at some
	// implicit anchor we can't see).
	root := chain[0]
	if root.PublicKeyAlgorithm != x509.ECDSA {
		report.Fail("chain[0] key algorithm",
			fmt.Sprintf("got %s; SCP11a CA-KLOC must be ECDSA P-256", root.PublicKeyAlgorithm))
	} else if rootKey, ok := root.PublicKey.(*ecdsa.PublicKey); !ok || rootKey.Curve != elliptic.P256() {
		report.Fail("chain[0] curve",
			"public key is not ECDSA P-256 (SCP11a CA-KLOC must be P-256)")
	} else {
		report.Pass("chain[0] key algorithm",
			fmt.Sprintf("ECDSA P-256, CN=%q", root.Subject.CommonName))
	}

	if !bytesEqual(root.RawIssuer, root.RawSubject) {
		report.Fail("chain[0] self-signed",
			fmt.Sprintf("issuer DN does not match subject DN (issuer=%q, subject=%q); "+
				"chain is not rooted at chain[0]",
				root.Issuer.String(), root.Subject.String()))
	} else {
		// Verify the self-signature against the cert's own public key.
		if err := root.CheckSignature(root.SignatureAlgorithm, root.RawTBSCertificate, root.Signature); err != nil {
			report.Fail("chain[0] self-signature",
				fmt.Sprintf("self-signed claim is not valid: %v", err))
		} else {
			report.Pass("chain[0] self-signature",
				fmt.Sprintf("verifies against own public key (%s)", root.SignatureAlgorithm))
		}
	}

	// Walk the chain and verify each cert's signature against the
	// previous cert's public key. This is the OFF-CARD equivalent
	// of what the YubiKey does at PSO time.
	for i := 1; i < len(chain); i++ {
		issuer := chain[i-1]
		cert := chain[i]
		if !bytesEqual(cert.RawIssuer, issuer.RawSubject) {
			report.Fail(fmt.Sprintf("chain[%d] issuer DN", i),
				fmt.Sprintf("does not match chain[%d] subject DN (cert.Issuer=%q, signer.Subject=%q)",
					i-1, cert.Issuer.String(), issuer.Subject.String()))
			continue
		}
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			report.Fail(fmt.Sprintf("chain[%d] signature", i),
				fmt.Sprintf("does NOT verify against chain[%d] public key: %v "+
					"-- this is the most likely cause of PSO SW=6A80",
					i-1, err))
		} else {
			report.Pass(fmt.Sprintf("chain[%d] signature", i),
				fmt.Sprintf("verifies against chain[%d] public key (%s)",
					i-1, cert.SignatureAlgorithm))
		}
	}

	// Report SKI for chain[0] in both forms (extension and computed).
	// scpctl bootstrap registers the SKI via STORE CA-IDENTIFIER; the
	// card uses it to look up which CA validates which OCE leaf.
	// If the extension is present, scpctl uses that. If absent, it
	// falls back to SHA-1(SPKI) per RFC 5280 §4.2.1.2.
	if len(root.SubjectKeyId) > 0 {
		report.Pass("chain[0] SKI (extension)",
			fmt.Sprintf("%X (%d bytes)", root.SubjectKeyId, len(root.SubjectKeyId)))
	} else {
		report.Skip("chain[0] SKI (extension)",
			"not present; scpctl will compute SHA-1 of the subjectPublicKey BIT STRING per RFC 5280 §4.2.1.2 method 1")
	}
	// RFC 5280 §4.2.1.2 method 1: the SubjectKeyIdentifier is "the
	// 160-bit SHA-1 hash of the value of the BIT STRING
	// subjectPublicKey (excluding the tag, length, and number of
	// unused bits)." For an ECDSA public key that's the SEC1
	// uncompressed point (0x04 || X || Y).
	if rootKey, ok := root.PublicKey.(*ecdsa.PublicKey); ok {
		ecdhKey, err := rootKey.ECDH()
		if err != nil {
			report.Fail("chain[0] SKI (computed)",
				fmt.Sprintf("convert ECDSA→ECDH for BIT STRING extraction: %v", err))
		} else {
			h := sha1.Sum(ecdhKey.Bytes()) //nolint:gosec // RFC 5280 §4.2.1.2 method 1
			report.Pass("chain[0] SKI (computed RFC 5280 method 1)",
				fmt.Sprintf("%X (%d bytes)", h[:], len(h)))
			if len(root.SubjectKeyId) > 0 && !bytesEqual(root.SubjectKeyId, h[:]) {
				// Surface, but don't fail — the card uses the extension
				// value when present. RFC 5280 explicitly permits other
				// SKI computation methods (§4.2.1.2: "Other methods of
				// generating unique numbers are also acceptable.").
				report.Skip("chain[0] SKI (extension vs computed)",
					"extension SKI does not match RFC 5280 method 1; this is "+
						"permitted by RFC 5280 (other methods are acceptable). "+
						"scpctl bootstrap registers the EXTENSION value.")
			}
		}
	} else {
		report.Skip("chain[0] SKI (computed)",
			"chain[0] is not ECDSA; method-1 computation needs the EC point")
	}

	// CA-cert profile reporting. Per GP Amendment F §6 the SD only
	// verifies the leaf signature against PK.CA-KLOC; "all other
	// fields of the certificate may be ignored." But Yubico's
	// implementation may be stricter than the GP minimum, so
	// surface what's actually present so we can correlate with
	// hardware behavior.
	if root.BasicConstraintsValid {
		if root.IsCA {
			report.Pass("chain[0] BasicConstraints",
				fmt.Sprintf("CA:TRUE (PathLen=%d, PathLenSet=%t)",
					root.MaxPathLen, root.MaxPathLenZero || root.MaxPathLen > 0))
		} else {
			report.Fail("chain[0] BasicConstraints",
				"CA:FALSE — chain[0] is NOT marked as a CA. Some implementations refuse "+
					"to use a non-CA cert as a trust anchor.")
		}
	} else {
		report.Skip("chain[0] BasicConstraints",
			"extension not present. Strict implementations may require BasicConstraints CA:TRUE.")
	}
	rootKU := keyUsageNames(root.KeyUsage)
	if len(rootKU) == 0 {
		report.Skip("chain[0] KeyUsage",
			"no KeyUsage extension. Strict implementations may require keyCertSign for a CA.")
	} else {
		hasCertSign := root.KeyUsage&x509.KeyUsageCertSign != 0
		detail := strings.Join(rootKU, ", ")
		if !hasCertSign {
			detail += " (note: no keyCertSign — some implementations require it for CA certs)"
		}
		report.Pass("chain[0] KeyUsage", detail)
	}

	// Leaf details. The leaf is what gets sent to the card via
	// PSO. Yubico's docs say only the signature is verified, but
	// surfacing the details lets us spot anything unusual.
	leaf := chain[len(chain)-1]
	if leaf == root {
		// Single-cert chain: the leaf IS the CA. SCP11a doesn't
		// strictly require this, but it's an unusual configuration
		// and worth surfacing.
		report.Skip("leaf details", "single-cert chain; leaf is also the CA")
	} else {
		report.Pass("leaf subject", leaf.Subject.String())
		report.Pass("leaf serial", fmt.Sprintf("%X (%d bytes)", leaf.SerialNumber, len(leaf.SerialNumber.Bytes())))
		report.Pass("leaf signature alg", leaf.SignatureAlgorithm.String())

		// Extract leaf's public key and report curve.
		if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			curveName := "(unknown)"
			if pk.Curve == elliptic.P256() {
				curveName = "P-256"
			}
			report.Pass("leaf public key", fmt.Sprintf("ECDSA %s", curveName))
		} else {
			report.Fail("leaf public key",
				fmt.Sprintf("not ECDSA; got %T -- SCP11a OCE leaf must be ECDSA P-256",
					leaf.PublicKey))
		}

		// Surface KeyUsage. GP says fields other than the signature
		// "may be ignored", but Yubico's strict parser may not.
		ku := keyUsageNames(leaf.KeyUsage)
		if len(ku) == 0 {
			report.Skip("leaf KeyUsage", "no KeyUsage extension or empty bit string")
		} else {
			report.Pass("leaf KeyUsage", strings.Join(ku, ", "))
		}

		// BasicConstraints presence on the leaf. RFC 5280 §4.2.1.9
		// makes this extension OPTIONAL on end-entity certs.
		// Samsung's reference SCP11a OCE leaf — known to be
		// accepted by retail YubiKey 5.7.4 — does NOT have it.
		// Earlier we hypothesized it was load-bearing for PSO
		// (PR #93); hardware testing falsified that. Reporting
		// presence as informational, never as a FAIL.
		switch {
		case !leaf.BasicConstraintsValid:
			report.Skip("leaf BasicConstraints",
				"absent (RFC 5280 §4.2.1.9 OPTIONAL on end-entity certs; "+
					"Samsung's reference OCE leaf accepted by YubiKey 5.7.4 also omits it)")
		case leaf.IsCA:
			report.Fail("leaf BasicConstraints",
				"cA=TRUE on the leaf — the leaf is the chain terminus and must NOT be a CA")
		default:
			report.Pass("leaf BasicConstraints", "cA=FALSE")
		}

		// certificatePolicies with the Yubico-arc OID
		// 1.2.840.114283.100.0.10.2.1.0, marked critical=TRUE.
		// Hardware datum (retail YubiKey 5.7.4): SCP11a PSO
		// rejects an OCE leaf cert WITHOUT this extension with
		// SW=6A80, even when every other field matches GP §6.7
		// and RFC 5280. Both Samsung's reference OCE test cert
		// and Yubico's own SD attestation intermediate carry it.
		// Generated chains must include it to authenticate
		// against retail hardware. This is the most common cause
		// of PSO 6A80 on chains generated by tools (older scpctl,
		// naive openssl, hand-rolled) that don't know about the
		// Yubico-specific policy requirement.
		yubicoPolicyOID := asn1.ObjectIdentifier{1, 2, 840, 114283, 100, 0, 10, 2, 1, 0}
		var policiesExt *pkix.Extension
		for i, ext := range leaf.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 32}) {
				policiesExt = &leaf.Extensions[i]
				break
			}
		}
		switch {
		case policiesExt == nil:
			report.Fail("leaf certificatePolicies",
				"no certificatePolicies extension. YubiKey 5.7+ SCP11 firmware "+
					"rejects PSO with SW=6A80 on OCE leaf certs that omit this "+
					"extension. Regenerate the chain (scpctl oce gen ≥ this "+
					"commit adds it automatically with the Yubico-arc OID "+
					"1.2.840.114283.100.0.10.2.1.0 marked critical) or add it "+
					"manually before retrying SCP11a.")
		case !policiesExt.Critical:
			report.Fail("leaf certificatePolicies",
				"present but critical=FALSE. Samsung's reference cert and "+
					"Yubico's own SD attestation intermediate both mark it "+
					"critical=TRUE; mark it critical to match.")
		default:
			// Walk the policy IDs looking for the Yubico-arc OID.
			var hasYubicoOID bool
			var oidsSeen []string
			type policyInfo struct {
				ID         asn1.ObjectIdentifier
				Qualifiers asn1.RawValue `asn1:"optional"`
			}
			var policies []policyInfo
			if _, err := asn1.Unmarshal(policiesExt.Value, &policies); err == nil {
				for _, p := range policies {
					oidsSeen = append(oidsSeen, p.ID.String())
					if p.ID.Equal(yubicoPolicyOID) {
						hasYubicoOID = true
					}
				}
			}
			if hasYubicoOID {
				report.Pass("leaf certificatePolicies",
					fmt.Sprintf("critical=TRUE, includes Yubico OCE policy OID %s",
						yubicoPolicyOID.String()))
			} else {
				report.Skip("leaf certificatePolicies",
					fmt.Sprintf("critical=TRUE, but Yubico OCE policy OID %s "+
						"not present (saw: %s). YubiKey may still accept "+
						"this chain depending on firmware behavior; if PSO "+
						"returns SW=6A80 try regenerating with the Yubico OID.",
						yubicoPolicyOID.String(), strings.Join(oidsSeen, ", ")))
			}
		}

		// Authority key identifier — should match chain[0] SKI for a
		// well-formed chain. Mismatch is not fatal per GP spec but
		// is a strong signal that the chain was assembled wrong.
		if len(leaf.AuthorityKeyId) == 0 {
			report.Skip("leaf AuthorityKeyIdentifier",
				"no AKI extension; well-formed OCE chains usually have it")
		} else {
			// Compute the RFC 5280 method 1 SKI of chain[0] for
			// comparison alongside the extension value. The leaf's AKI
			// might match either: extension SKI is what scpctl
			// registers on-card, but AKI generation tools sometimes
			// recompute method 1 from the issuer pubkey rather than
			// echoing the SKI extension verbatim.
			rootSKIExt := root.SubjectKeyId
			var rootSKIComputed []byte
			if rootKey, ok := root.PublicKey.(*ecdsa.PublicKey); ok {
				if ecdhKey, err := rootKey.ECDH(); err == nil {
					h := sha1.Sum(ecdhKey.Bytes()) //nolint:gosec // RFC 5280 §4.2.1.2 method 1
					rootSKIComputed = h[:]
				}
			}
			switch {
			case len(rootSKIExt) > 0 && bytesEqual(leaf.AuthorityKeyId, rootSKIExt):
				report.Pass("leaf AuthorityKeyIdentifier",
					fmt.Sprintf("%X — matches chain[0] SKI extension", leaf.AuthorityKeyId))
			case len(rootSKIComputed) > 0 && bytesEqual(leaf.AuthorityKeyId, rootSKIComputed):
				report.Pass("leaf AuthorityKeyIdentifier",
					fmt.Sprintf("%X — matches chain[0] computed RFC 5280 method 1 SKI", leaf.AuthorityKeyId))
			default:
				detail := fmt.Sprintf("AKI=%X does not match chain[0] SKI extension=%X",
					leaf.AuthorityKeyId, rootSKIExt)
				if len(rootSKIComputed) > 0 {
					detail += fmt.Sprintf(" or computed=%X", rootSKIComputed)
				}
				detail += " — chain is internally inconsistent"
				report.Fail("leaf AuthorityKeyIdentifier", detail)
			}
		}
	}

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("oce verify: chain has structural issues; see report")
	}
	return nil
}

// loadCertChainPEM loads one or more concatenated X.509 certificates
// from a PEM file. Returns them in file order (which scpctl
// convention uses as leaf-last).
func loadCertChainPEM(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		block, more := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = more
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// keyUsageNames returns human-readable names for the bits set in a
// KeyUsage. Order matches RFC 5280 §4.2.1.3.
func keyUsageNames(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "decipherOnly")
	}
	return out
}

// bytesEqual is a thin wrapper to avoid pulling bytes.Equal into a
// file that doesn't otherwise import bytes. Equivalent semantics.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- gen --------------------------------------------------------------------

// cmdOCEGen produces a fresh OCE root + leaf chain using the
// canonical SCP11a OCE profile and writes them to disk.
func cmdOCEGen(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("oce gen", env)
	outDir := fs.String("out-dir", "", "Directory to write the generated chain into.")
	rootCN := fs.String("root-cn", "scpctl OCE Root CA", "Subject CommonName for the generated root CA cert.")
	leafCN := fs.String("leaf-cn", "scpctl OCE Leaf", "Subject CommonName for the generated leaf cert.")
	validDays := fs.Int("valid-days", 365, "Validity period in days for both root and leaf.")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *outDir == "" {
		return &usageError{msg: "--out-dir is required"}
	}
	if *validDays < 1 {
		return &usageError{msg: "--valid-days must be >= 1"}
	}

	report := &Report{Subcommand: "oce gen"}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		report.Fail("create out-dir", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("out-dir", *outDir)

	// --- Root: self-signed P-256 CA ---
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		report.Fail("generate root key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("generate root key", "ECDSA P-256")

	notBefore := time.Now().Add(-1 * time.Hour) // small skew tolerance
	notAfter := notBefore.Add(time.Duration(*validDays) * 24 * time.Hour)

	rootSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		report.Fail("root serial", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	rootSKI := computeSKI(&rootKey.PublicKey)
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: *rootCN},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          rootSKI,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		report.Fail("create root cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		report.Fail("parse root cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("create root cert",
		fmt.Sprintf("CN=%q, SKI=%X, valid %d days", *rootCN, rootSKI, *validDays))

	// --- Leaf: P-256, signed by root ---
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		report.Fail("generate leaf key", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("generate leaf key", "ECDSA P-256")

	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		report.Fail("leaf serial", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	leafSKI := computeSKI(&leafKey.PublicKey)

	// certificatePolicies extension with the Yubico-arc OID
	// 1.2.840.114283.100.0.10.2.1.0, marked critical=TRUE.
	//
	// Hardware datum (retail YubiKey 5.7.4): SCP11a PSO of an OCE
	// leaf cert WITHOUT this extension is rejected with SW=6A80
	// even when every other field matches GP §6.7 / RFC 5280 (key
	// usage critical=keyAgreement, AKI matching the registered CA
	// SKI, ECDSA-SHA256 over P-256, valid signature). Samsung's
	// reference SCP11a OCE test cert (hex pinned in
	// scp11/samsung_scp11a_transcript_test.go, oceLeafDER) and
	// Yubico's own SD attestation intermediate both carry this
	// extension. Ours did not, and that was the trailing byte
	// difference behind the 6A80 we kept reading as a framing bug.
	//
	// Encoding: CertificatePolicies SEQUENCE OF PolicyInformation,
	// one PolicyInformation containing only the policy OID. Result
	// bytes: 30 10 30 0E 06 0C 2A 86 48 86 FC 6B 64 00 0A 02 01 00.
	// Bytewise identical to Samsung's reference cert's same
	// extension. Built via x509.ExtraExtensions because
	// x509.Certificate.PolicyIdentifiers emits with critical=FALSE,
	// which doesn't match what the YubiKey wants.
	yubicoOCEPolicyOID := asn1.ObjectIdentifier{1, 2, 840, 114283, 100, 0, 10, 2, 1, 0}
	type policyInfo struct {
		ID asn1.ObjectIdentifier
	}
	policiesDER, err := asn1.Marshal([]policyInfo{{ID: yubicoOCEPolicyOID}})
	if err != nil {
		report.Fail("encode certificatePolicies", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	certPoliciesExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 32}, // certificatePolicies
		Critical: true,
		Value:    policiesDER,
	}

	leafTmpl := &x509.Certificate{
		SerialNumber:   leafSerial,
		Subject:        pkix.Name{CommonName: *leafCN},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageKeyAgreement,
		SubjectKeyId:   leafSKI,
		AuthorityKeyId: rootSKI, // chains AKI to root SKI per RFC 5280
		// BasicConstraints is intentionally OMITTED. The Samsung
		// reference OCE leaf — which is known to authenticate
		// successfully against retail YubiKey 5.7.4 — has no
		// BasicConstraints extension at all. RFC 5280 §4.2.1.9
		// makes BasicConstraints optional on end-entity certs;
		// adding it as cA=FALSE was an earlier hypothesis that
		// turned out to be wrong (PR #93). Keeping the leaf
		// minimal-and-spec-clean matches Samsung's working
		// reference and avoids extra surface for the firmware
		// to reject.
		ExtraExtensions: []pkix.Extension{certPoliciesExt},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		report.Fail("create leaf cert", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("create leaf cert",
		fmt.Sprintf("CN=%q, SKI=%X, AKI=%X, signed by root", *leafCN, leafSKI, rootSKI))

	// --- Write files ---
	files := []struct {
		name string
		data []byte
	}{
		{"oce-root.key.pem", pemEncodePrivKey(rootKey)},
		{"oce-root.cert.pem", pemEncodeCert(rootDER)},
		{"oce-leaf.key.pem", pemEncodePrivKey(leafKey)},
		{"oce-leaf.cert.pem", pemEncodeCert(leafDER)},
		// chain leaf-last: root first, leaf last
		{"oce-chain-leaf-last.pem", append(pemEncodeCert(rootDER), pemEncodeCert(leafDER)...)},
	}
	for _, f := range files {
		path := filepath.Join(*outDir, f.name)
		mode := os.FileMode(0o644)
		if strings.HasSuffix(f.name, ".key.pem") {
			mode = 0o600 // private keys
		}
		if err := os.WriteFile(path, f.data, mode); err != nil {
			report.Fail("write "+f.name, err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
		report.Pass("wrote "+f.name, path)
	}

	return report.Emit(env.out, *jsonMode)
}

// computeSKI returns the SubjectKeyIdentifier of an ECDSA public
// key per RFC 5280 §4.2.1.2 method 1: SHA-1 of the value of the
// BIT STRING subjectPublicKey, excluding the tag, length, and
// number of unused bits.
//
// For an EC key, the BIT STRING value is the SEC1 uncompressed
// point (0x04 || X || Y). crypto/ecdh's PublicKey.Bytes()
// produces exactly that.
//
// Earlier revisions hashed the full SubjectPublicKeyInfo
// (algorithm + BIT STRING) which produces a different value.
// That was wrong: cards and tooling compute method 1 against the
// BIT STRING value alone, so a "computed" SKI that hashed SPKI
// would never match the extension SKI of a properly-formed cert.
func computeSKI(pub *ecdsa.PublicKey) []byte {
	ecdhKey, err := pub.ECDH()
	if err != nil {
		return nil
	}
	h := sha1.Sum(ecdhKey.Bytes()) //nolint:gosec // RFC 5280 §4.2.1.2 method 1
	return h[:]
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodePrivKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
