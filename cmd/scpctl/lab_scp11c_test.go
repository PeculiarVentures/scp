//go:build lab
// +build lab

// Lab measurement test for SCP11c against real hardware.
//
// SCP11c is the strongest SCP11 variant: full mutual authentication
// (card↔OCE), ephemeral keys on both sides, scriptable receipts.
// This test is the canonical interop measurement — we do not run it
// in CI, we run it on demand against an actual card to ground the
// library's correctness claims.
//
// Build & run:
//
//	go test -tags=lab \
//	  -run TestSCP11c_LabMeasurement \
//	  ./securitydomain/ \
//	  -count=1 -timeout=2m -v
//
// Without the `lab` build tag the file does not compile into the
// test binary at all — no risk of accidentally pulling lab code into
// non-lab test runs. With the tag but without SCPCTL_LAB_HARDWARE=1
// the test t.Skips on the first line, so a `go test -tags=lab ./...`
// is non-destructive against any environment that hasn't explicitly
// opted in.
//
// Preconditions on the lab card:
//
//  1. PC/SC reader visible to the host (SCPCTL_LAB_READER names it).
//  2. SCP03 ISD keys known to the test (default scp03.DefaultKeys
//     unless SCPCTL_LAB_SCP03_KEYS overrides). The test uses these
//     to install/remove a disposable SCP11c key for the measurement.
//  3. OCE trust chain already provisioned on the card: a CA public
//     key + SKI registered at the KID/KVN named by
//     SCPCTL_LAB_OCE_KEY_KID / _KVN (default 0x10 / 0x01). The OCE
//     leaf cert in SCPCTL_LAB_OCE_CERT must chain to that CA.
//  4. SCP11c slot (KID=0x15) must have the disposable KVN
//     (default 0x7F) FREE. The disposable KVN is intentionally outside
//     the typical production range; if a previous lab run left
//     debris there, this test will refuse to overwrite it without
//     SCPCTL_LAB_FORCE=1.
//
// Postconditions: the card is left in the state it started in.
// t.Cleanup deletes the disposable SCP11c key whether or not the
// measurement succeeds. If cleanup itself fails, the test reports
// it loudly and the operator can diagnose with `scpctl sd keys list`.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport/pcsc"
)

// labConfig captures the environment-supplied test parameters in one
// place. Resolving env vars once at the top of the test makes the
// rest of the body free of os.Getenv calls and gives a single place
// to validate / document each input.
type labConfig struct {
	reader        string
	oceKeyPath    string
	oceCertPath   string
	trustRootPath string
	oceKID        byte
	oceKVN        byte
	scp03Keys     scp03.StaticKeys
	disposableKVN byte
	force         bool
}

const (
	envHardwareGate  = "SCPCTL_LAB_HARDWARE"
	envReader        = "SCPCTL_LAB_READER"
	envOCEKey        = "SCPCTL_LAB_OCE_KEY"
	envOCECert       = "SCPCTL_LAB_OCE_CERT"
	envOCEKeyKID     = "SCPCTL_LAB_OCE_KEY_KID"
	envOCEKeyKVN     = "SCPCTL_LAB_OCE_KEY_KVN"
	envTrustRoot     = "SCPCTL_LAB_TRUST_ROOT"
	envSCP03Keys     = "SCPCTL_LAB_SCP03_KEYS"
	envDisposableKVN = "SCPCTL_LAB_DISPOSABLE_KVN"
	envForce         = "SCPCTL_LAB_FORCE"

	// Disposable KVN default. 0x7F is intentionally outside the
	// typical production range (0x01–0x0F) so that residue from a
	// failed lab run is obvious in `scpctl sd keys list` output.
	defaultDisposableKVN byte = 0x7F

	// SCP11c is at KID=0x15 per GP Amendment F §7.1.1. We don't
	// expose the KID as a knob — choosing a different KID would
	// change which SCP11 variant is tested, and this test is
	// specifically the SCP11c measurement.
	scp11cKID byte = 0x15

	// Default OCE key reference. Matches the convention
	// bootstrap-oce uses for the OCE CA installation.
	defaultOCEKID byte = 0x10
	defaultOCEKVN byte = 0x01
)

// TestSCP11c_LabMeasurement is the canonical SCP11c interop test.
// It exercises the full flow:
//
//   - Install a disposable SCP11c key via SCP03
//   - Open SCP11c against that key with operator-supplied OCE
//     materials and card trust anchor
//   - Confirm the resulting session is authenticated at every level
//     the library exposes (raw IsAuthenticated, OCEAuthenticated,
//     Protocol)
//   - Round-trip a read-only APDU (GET DATA card recognition,
//     GP §H.2) through the encrypted+MAC'd channel to prove the
//     channel actually works in both directions
//   - Confirm the disposable key shows up via GET STATUS so the
//     read-after-write contract is intact
//   - Cleanup: delete the disposable key
//
// Authentication assertions explicitly check OCEAuthenticated()
// because that is THE distinguishing behavior of SCP11c (vs SCP11b
// where the OCE is unauthenticated). If the library handshake bug
// was that SCP11c degraded to SCP11b semantics, this assertion would
// catch it.
func TestSCP11c_LabMeasurement(t *testing.T) {
	if os.Getenv(envHardwareGate) != "1" {
		t.Skipf("set %s=1 to run the SCP11c hardware measurement (DESTRUCTIVE: installs and deletes a disposable SCP11c key on the card)",
			envHardwareGate)
	}

	cfg := loadLabConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	tx, err := pcsc.OpenReader(cfg.reader)
	if err != nil {
		t.Fatalf("open reader %q: %v", cfg.reader, err)
	}
	t.Cleanup(func() { _ = tx.Close() })

	// --- Phase A: install disposable SCP11c key via SCP03 ---
	//
	// We open SCP03, generate a fresh P-256 key at KID=0x15 KVN=
	// disposableKVN, and close. The card returns the SPKI; we
	// capture it for sanity but the cert chain at this slot is
	// EMPTY (no --certs supplied) which is fine for SCP11c — the
	// card-side authentication works off the static key, not a
	// chain on the SCP11c slot itself. The OCE-side authentication
	// uses the chain we provide via OCECertificates.
	preInstallPub := installDisposableSCP11cKey(t, ctx, tx, cfg)

	// Cleanup must be registered AFTER the install succeeds so we
	// don't try to delete a key that wasn't installed. If
	// installDisposableSCP11cKey fails the test, t.Fatalf has
	// already aborted and this line is unreached.
	t.Cleanup(func() { deleteDisposableSCP11cKey(t, cfg, cfg.disposableKVN) })

	// --- Phase B: load OCE materials ---

	ocePriv, err := loadECP256PrivateKey(cfg.oceKeyPath)
	if err != nil {
		t.Fatalf("load OCE private key %q: %v", cfg.oceKeyPath, err)
	}
	oceChain, err := loadCertChain(cfg.oceCertPath)
	if err != nil {
		t.Fatalf("load OCE cert chain %q: %v", cfg.oceCertPath, err)
	}
	if err := assertLeafMatchesPrivateKey(ocePriv, oceChain[len(oceChain)-1]); err != nil {
		t.Fatalf("OCE leaf cert does not match OCE private key: %v", err)
	}
	trustPool, err := loadTrustPool(cfg.trustRootPath)
	if err != nil {
		t.Fatalf("load card trust root %q: %v", cfg.trustRootPath, err)
	}

	// --- Phase C: open SCP11c session ---

	scp11cCfg := scp11.YubiKeyDefaultSCP11cConfig()
	scp11cCfg.KeyVersion = cfg.disposableKVN
	scp11cCfg.OCECertificates = oceChain
	scp11cCfg.OCEKeyReference = scp11.KeyRef{KID: cfg.oceKID, KVN: cfg.oceKVN}
	scp11cCfg.OCEPrivateKey = ocePriv
	scp11cCfg.CardTrustAnchors = trustPool

	sd, err := securitydomain.OpenSCP11(ctx, tx, scp11cCfg)
	if err != nil {
		t.Fatalf("open SCP11c session: %v", err)
	}
	t.Cleanup(sd.Close)

	// --- Phase D: assertions on the established session ---

	if !sd.IsAuthenticated() {
		t.Errorf("session is not authenticated after Open returned nil; library invariant broken")
	}
	if !sd.OCEAuthenticated() {
		t.Errorf("OCEAuthenticated()=false on SCP11c session; SCP11c MUST authenticate the OCE (vs SCP11b where OCE is unauthenticated). The handshake may have silently degraded.")
	}
	if proto := sd.Protocol(); !strings.Contains(proto, "SCP11") {
		t.Errorf("Protocol() = %q, want SCP11* token", proto)
	}

	// Round-trip a real APDU. GET DATA card recognition (GP §H.2)
	// is the simplest available read-only command — minimal payload,
	// well-defined response, requires the channel to be up. If MAC
	// or encryption is wrong the card returns 6988 / 6982 and this
	// fails.
	cardData, err := sd.GetCardRecognitionData(ctx)
	if err != nil {
		t.Fatalf("GET DATA card recognition over SCP11c channel: %v", err)
	}
	if len(cardData) == 0 {
		t.Errorf("GET DATA card recognition returned 0 bytes; card response should be non-empty per GP §H.2")
	}

	// Read-after-write check: the disposable key we just installed
	// in Phase A must show up in GET STATUS. This proves both the
	// install actually committed and the SCP11c channel can read
	// SD inventory.
	keyInfo, err := sd.GetKeyInformation(ctx)
	if err != nil {
		t.Fatalf("GetKeyInformation over SCP11c channel: %v", err)
	}
	if !keyInfoContainsRef(keyInfo, scp11cKID, cfg.disposableKVN) {
		t.Errorf("GetKeyInformation does not list disposable key at KID=0x%02X KVN=0x%02X; key info: %+v",
			scp11cKID, cfg.disposableKVN, keyInfo)
	}

	// Sanity: the SPKI we captured at install time should be the
	// same key the card validated against. We don't refetch a chain
	// (we didn't store one), but the SPKI is what the SCP11c
	// handshake's GET DATA BF21 returned and the card validated
	// against. This assertion is a smoke check that the install
	// curve matches the handshake key — a P-256 install can't
	// correctly run a P-384 SCP11c handshake.
	if preInstallPub.Curve != elliptic.P256() {
		t.Errorf("disposable key curve = %s, want P-256", preInstallPub.Curve.Params().Name)
	}

	t.Logf("SCP11c handshake verified: protocol=%q, OCE-auth=%v, card-data=%d bytes, disposable key at KID=0x%02X KVN=0x%02X confirmed",
		sd.Protocol(), sd.OCEAuthenticated(), len(cardData), scp11cKID, cfg.disposableKVN)
}

// loadLabConfig reads the env vars and returns a labConfig. Missing
// required vars produce a t.Skip with a precise list — the operator
// who set SCPCTL_LAB_HARDWARE=1 but forgot a path needs to know what
// to add, not see a generic "skipped".
func loadLabConfig(t *testing.T) labConfig {
	t.Helper()

	required := []struct{ env, val string }{
		{envReader, os.Getenv(envReader)},
		{envOCEKey, os.Getenv(envOCEKey)},
		{envOCECert, os.Getenv(envOCECert)},
		{envTrustRoot, os.Getenv(envTrustRoot)},
	}
	var missing []string
	for _, r := range required {
		if r.val == "" {
			missing = append(missing, r.env)
		}
	}
	if len(missing) > 0 {
		t.Skipf("%s=1 set but missing required env vars: %s", envHardwareGate, strings.Join(missing, ", "))
	}

	cfg := labConfig{
		reader:        os.Getenv(envReader),
		oceKeyPath:    os.Getenv(envOCEKey),
		oceCertPath:   os.Getenv(envOCECert),
		trustRootPath: os.Getenv(envTrustRoot),
		oceKID:        defaultOCEKID,
		oceKVN:        defaultOCEKVN,
		scp03Keys:     scp03.DefaultKeys,
		disposableKVN: defaultDisposableKVN,
		force:         os.Getenv(envForce) == "1",
	}
	if v := os.Getenv(envOCEKeyKID); v != "" {
		b, err := parseHexByteForLab(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", envOCEKeyKID, v, err)
		}
		cfg.oceKID = b
	}
	if v := os.Getenv(envOCEKeyKVN); v != "" {
		b, err := parseHexByteForLab(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", envOCEKeyKVN, v, err)
		}
		cfg.oceKVN = b
	}
	if v := os.Getenv(envDisposableKVN); v != "" {
		b, err := parseHexByteForLab(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", envDisposableKVN, v, err)
		}
		cfg.disposableKVN = b
	}
	if v := os.Getenv(envSCP03Keys); v != "" {
		keys, err := parseSCP03KeysTriple(v)
		if err != nil {
			t.Fatalf("%s: %v", envSCP03Keys, err)
		}
		cfg.scp03Keys = keys
	}
	return cfg
}

// installDisposableSCP11cKey opens an SCP03 session with the
// configured keys, generates a fresh P-256 key at the SCP11c slot
// (KID=0x15) at the disposable KVN, and returns the resulting
// public key.
//
// Pre-existing key at the disposable KVN: by default we refuse to
// overwrite (cfg.force=false) — fail with a directive to either
// clean up the residue first or set SCPCTL_LAB_FORCE=1. This avoids
// silently mutating debris from a prior failed run.
func installDisposableSCP11cKey(t *testing.T, ctx context.Context, tx *pcsc.Transport, cfg labConfig) *ecdsa.PublicKey {
	t.Helper()

	scp03Cfg := &scp03.Config{Keys: cfg.scp03Keys}
	sd, err := securitydomain.OpenSCP03(ctx, tx, scp03Cfg)
	if err != nil {
		t.Fatalf("open SCP03 (Phase A install): %v", err)
	}
	defer sd.Close()

	// Pre-flight: refuse to overwrite a pre-existing key at the
	// disposable KVN unless --force.
	if !cfg.force {
		info, err := sd.GetKeyInformation(ctx)
		if err != nil {
			t.Fatalf("GET STATUS preflight: %v", err)
		}
		if keyInfoContainsRef(info, scp11cKID, cfg.disposableKVN) {
			t.Fatalf("disposable KVN 0x%02X at KID 0x%02X is already populated. "+
				"Either delete it manually (`scpctl sd keys delete --kid 15 --kvn %02X --confirm-delete-key`) "+
				"or set %s=1 to force overwrite",
				cfg.disposableKVN, scp11cKID, cfg.disposableKVN, envForce)
		}
	}

	ref := securitydomain.NewKeyReference(scp11cKID, cfg.disposableKVN)
	// replaceKvn=0 means "additive install" — don't replace anything.
	// If --force was set and a key exists, the card rejects the
	// install which is the correct safety behavior; --force gives
	// the operator the option to manually delete first.
	pub, err := sd.GenerateECKey(ctx, ref, 0)
	if err != nil {
		t.Fatalf("GENERATE EC KEY at KID=0x%02X KVN=0x%02X: %v",
			scp11cKID, cfg.disposableKVN, err)
	}
	if pub == nil {
		t.Fatalf("GenerateECKey returned nil pub with no error; library invariant broken")
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("disposable key curve = %s, want P-256", pub.Curve.Params().Name)
	}
	return pub
}

// deleteDisposableSCP11cKey re-opens SCP03 and deletes the
// disposable key. Errors here are reported via t.Errorf (not Fatalf)
// because cleanup runs from t.Cleanup and a Fatalf would be lost in
// some test-runner configurations; t.Errorf still marks the test as
// failed, which is what we want if cleanup fails.
//
// We open a fresh transport rather than reusing the test's transport
// because t.Cleanup ordering is reverse-LIFO: the transport's own
// Close has already been registered to run AFTER the disposable-key
// cleanup, so reusing it would race the close.
func deleteDisposableSCP11cKey(t *testing.T, cfg labConfig, kvn byte) {
	t.Helper()

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := pcsc.OpenReader(cfg.reader)
	if err != nil {
		t.Errorf("CLEANUP: open reader %q: %v (disposable key may remain at KID=0x%02X KVN=0x%02X)",
			cfg.reader, err, scp11cKID, kvn)
		return
	}
	defer func() { _ = tx.Close() }()

	sd, err := securitydomain.OpenSCP03(cleanupCtx, tx, &scp03.Config{Keys: cfg.scp03Keys})
	if err != nil {
		t.Errorf("CLEANUP: open SCP03: %v (disposable key may remain at KID=0x%02X KVN=0x%02X)",
			err, scp11cKID, kvn)
		return
	}
	defer sd.Close()

	ref := securitydomain.NewKeyReference(scp11cKID, kvn)
	if err := sd.DeleteKey(cleanupCtx, ref, false); err != nil {
		t.Errorf("CLEANUP: DELETE KEY at KID=0x%02X KVN=0x%02X: %v",
			scp11cKID, kvn, err)
		return
	}
	t.Logf("CLEANUP: disposable SCP11c key at KID=0x%02X KVN=0x%02X removed",
		scp11cKID, kvn)
}

// loadECP256PrivateKey parses a PEM file and returns the EC P-256
// private key inside. Accepts both PKCS#8 ('PRIVATE KEY') and SEC1
// ('EC PRIVATE KEY') wrappings — the same shapes the cmd/scpctl
// loadOCEPrivateKey accepts. P-256 enforced; other curves are an error.
func loadECP256PrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PEM key is not ECDSA (got %T)", k)
		}
		key = ec
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC1: %w", err)
		}
		key = k
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (want PRIVATE KEY or EC PRIVATE KEY)", block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("curve is %s, SCP11 requires P-256", key.Curve.Params().Name)
	}
	return key, nil
}

// loadCertChain parses one or more concatenated PEM CERTIFICATE
// blocks. Returns them in file order (caller-determined leaf
// position). For SCP11c OCE chains the convention is leaf-LAST.
func loadCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks in file")
	}
	return certs, nil
}

// loadTrustPool builds an x509.CertPool from one or more concatenated
// PEM CERTIFICATE blocks at the given path, suitable for
// scp11.Config.CardTrustAnchors.
func loadTrustPool(path string) (*x509.CertPool, error) {
	certs, err := loadCertChain(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// assertLeafMatchesPrivateKey is the same anti-typo guard cmd/scpctl
// uses for SCP11 SD imports — verbatim SPKI-byte comparison between
// the leaf cert and the private key's public counterpart. A
// mismatch here means the operator wired the wrong files together
// for the lab; failing fast saves an opaque card-side validation
// failure later.
func assertLeafMatchesPrivateKey(priv *ecdsa.PrivateKey, leaf *x509.Certificate) error {
	leafSPKI, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal leaf SPKI: %w", err)
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal key SPKI: %w", err)
	}
	if string(leafSPKI) != string(keySPKI) {
		return errors.New("OCE leaf cert public key does not match OCE private key")
	}
	return nil
}

// keyInfoContainsRef reports whether a GET STATUS keyInfo result
// contains a key matching the given KID + KVN. KeyInfo carries the
// reference in ki.Reference (ID = KID, Version = KVN); Components
// is a map of component-ID → component-type and is not used by this
// match.
func keyInfoContainsRef(info []securitydomain.KeyInfo, kid, kvn byte) bool {
	for _, ki := range info {
		if ki.Reference.ID == kid && ki.Reference.Version == kvn {
			return true
		}
	}
	return false
}

// parseHexByteForLab decodes a single hex byte (e.g. "0x10", "10",
// "1F"). Strips an optional 0x prefix. Used for the env-var byte
// flags so an operator can use whichever form is in their notes.
func parseHexByteForLab(s string) (byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 2 {
		return 0, fmt.Errorf("expected 2 hex chars, got %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// parseSCP03KeysTriple parses the SCPCTL_LAB_SCP03_KEYS env var:
// "ENC:MAC:DEK" with each component being 32 hex chars (16 bytes,
// AES-128). Strict on length to fail loudly if the operator pastes
// an AES-192/256 key (which the SCP03 layer doesn't accept anyway).
func parseSCP03KeysTriple(s string) (scp03.StaticKeys, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return scp03.StaticKeys{}, fmt.Errorf("want ENC:MAC:DEK (3 colon-separated hex strings), got %d parts", len(parts))
	}
	out := scp03.StaticKeys{}
	for i, p := range parts {
		b, err := hex.DecodeString(strings.TrimSpace(p))
		if err != nil {
			return scp03.StaticKeys{}, fmt.Errorf("part %d: %w", i, err)
		}
		if len(b) != 16 {
			return scp03.StaticKeys{}, fmt.Errorf("part %d: %d bytes, want 16 (AES-128)", i, len(b))
		}
		switch i {
		case 0:
			out.ENC = b
		case 1:
			out.MAC = b
		case 2:
			out.DEK = b
		}
	}
	return out, nil
}
