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
			"not present; scpctl will compute SHA-1(SPKI) per RFC 5280 §4.2.1.2")
	}
	if len(root.RawSubjectPublicKeyInfo) > 0 {
		h := sha1.Sum(root.RawSubjectPublicKeyInfo) //nolint:gosec // RFC 5280 §4.2.1.2 specifies SHA-1
		report.Pass("chain[0] SKI (computed SHA-1(SPKI))",
			fmt.Sprintf("%X (%d bytes)", h[:], len(h)))
	} else {
		report.Fail("chain[0] SKI computation",
			"RawSubjectPublicKeyInfo is empty; cannot compute fallback SKI")
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

		// Authority key identifier — should match chain[0] SKI for a
		// well-formed chain. Mismatch is not fatal per GP spec but
		// is a strong signal that the chain was assembled wrong.
		if len(leaf.AuthorityKeyId) == 0 {
			report.Skip("leaf AuthorityKeyIdentifier",
				"no AKI extension; well-formed OCE chains usually have it")
		} else {
			rootSKI := root.SubjectKeyId
			if len(rootSKI) == 0 {
				h := sha1.Sum(root.RawSubjectPublicKeyInfo) //nolint:gosec
				rootSKI = h[:]
			}
			if bytesEqual(leaf.AuthorityKeyId, rootSKI) {
				report.Pass("leaf AuthorityKeyIdentifier",
					fmt.Sprintf("%X — matches chain[0] SKI", leaf.AuthorityKeyId))
			} else {
				report.Fail("leaf AuthorityKeyIdentifier",
					fmt.Sprintf("AKI=%X does not match chain[0] SKI=%X — "+
						"chain is internally inconsistent", leaf.AuthorityKeyId, rootSKI))
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
	leafTmpl := &x509.Certificate{
		SerialNumber:   leafSerial,
		Subject:        pkix.Name{CommonName: *leafCN},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageKeyAgreement,
		SubjectKeyId:   leafSKI,
		AuthorityKeyId: rootSKI, // chains AKI to root SKI per RFC 5280
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

// computeSKI returns SHA-1 of the SubjectPublicKeyInfo for an
// ECDSA public key. Uses x509.MarshalPKIXPublicKey to produce the
// SPKI byte sequence. RFC 5280 §4.2.1.2 method 1.
func computeSKI(pub *ecdsa.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	h := sha1.Sum(spki) //nolint:gosec // RFC 5280 §4.2.1.2 specifies SHA-1
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
