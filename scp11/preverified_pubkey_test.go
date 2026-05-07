package scp11

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/trust"
)

// TestOpen_PreverifiedKey_SkipsBF21 is the regression assertion for
// the SCP11b-on-PIV layering fix. When PreverifiedCardStaticPublicKey
// is set on Config, scp11.Open must not issue GET DATA BF21 against
// the selected applet — that's exactly the bug that caused PIV to
// return SW=6D00 against retail YubiKey 5.7+.
//
// The test runs Open with a pre-supplied key and a transport that
// records every APDU. The handshake won't complete (no real card),
// but completing isn't the assertion: the assertion is that no APDU
// matching INS=0xCA P1=0xBF P2=0x21 ever leaves the host. SELECT and
// the eventual INTERNAL AUTHENTICATE are expected.
func TestOpen_PreverifiedKey_SkipsBF21(t *testing.T) {
	pubKey := mustGenerateP256ECDHPub(t)

	tr := &noBF21Transport{
		// Canned responses: SELECT response (any 9000), then any
		// subsequent APDU also returns 9000 with a small body. The
		// SCP11 handshake will fail downstream because the body
		// doesn't decode as a valid AUTHENTICATE response, and that
		// failure is the exit point for the test.
		responses: [][]byte{
			{0x90, 0x00},             // SELECT response
			{0x00, 0x00, 0x6A, 0x80}, // AUTHENTICATE: malformed, fail-stop
		},
	}

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDPIV
	cfg.PreverifiedCardStaticPublicKey = pubKey
	cfg.InsecureSkipCardAuthentication = true

	_, err := Open(context.Background(), tr, cfg)
	if err == nil {
		t.Fatal("Open unexpectedly succeeded against fake transport")
	}

	for i, sent := range tr.sent {
		if isGetDataBF21(sent) {
			t.Fatalf("Open sent GET DATA BF21 (APDU #%d, %X) despite "+
				"PreverifiedCardStaticPublicKey being set; the cert-fetch "+
				"path must be skipped to support SCP11b-on-PIV",
				i+1, sent)
		}
	}

	// Defense in depth: SELECT must have been the first APDU. A
	// regression that re-introduces GET DATA before SELECT would also
	// indicate a layering bug worth flagging.
	if len(tr.sent) == 0 {
		t.Fatal("transport observed zero APDUs")
	}
	if first := tr.sent[0]; !isSelect(first) {
		t.Errorf("first APDU was %X, expected SELECT", first)
	}
}

// TestOpen_NoPreverifiedKey_StillFetchesBF21 asserts the inverse: when
// PreverifiedCardStaticPublicKey is nil, Open does perform the
// cert-fetch (so the existing SD-targeted code path is unchanged).
// This pins down the conditional behavior so a future refactor can't
// silently delete the cert-fetch entirely.
func TestOpen_NoPreverifiedKey_StillFetchesBF21(t *testing.T) {
	tr := &noBF21Transport{
		responses: [][]byte{
			{0x90, 0x00},             // SELECT 9000
			{0x90, 0x00},             // GET DATA BF21 returns 9000 with empty body
			{0x00, 0x00, 0x6A, 0x80}, // (any subsequent APDU fails)
		},
	}

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDSecurityDomain
	cfg.InsecureSkipCardAuthentication = true
	// PreverifiedCardStaticPublicKey deliberately left nil.

	_, _ = Open(context.Background(), tr, cfg)

	sawBF21 := false
	for _, sent := range tr.sent {
		if isGetDataBF21(sent) {
			sawBF21 = true
			break
		}
	}
	if !sawBF21 {
		t.Fatal("Open with nil PreverifiedCardStaticPublicKey did NOT issue " +
			"GET DATA BF21; the legacy cert-fetch path appears to have been " +
			"removed")
	}
}

// TestOpen_NoTrustPosture_FailsClosed asserts the upfront posture
// guard: even with PreverifiedCardStaticPublicKey set, Open refuses
// to proceed unless the caller declares one of CardTrustPolicy,
// CardTrustAnchors, or InsecureSkipCardAuthentication. This prevents
// the new pre-supplied-key path from becoming a trust-bypass shortcut.
func TestOpen_NoTrustPosture_FailsClosed(t *testing.T) {
	pubKey := mustGenerateP256ECDHPub(t)

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDPIV
	cfg.PreverifiedCardStaticPublicKey = pubKey
	// All three trust fields deliberately unset.

	_, err := Open(context.Background(), &noBF21Transport{}, cfg)
	if err == nil {
		t.Fatal("Open succeeded with no trust posture configured; the " +
			"upfront guard must reject this configuration")
	}
	if !strings.Contains(err.Error(), "trust posture") {
		t.Errorf("error should mention trust posture; got: %v", err)
	}
}

// noBF21Transport is a Transport that records every APDU and replays
// canned responses. Named after its primary use (verifying BF21 is
// not sent), but generic enough for any "what did Open transmit"
// regression assertion.
type noBF21Transport struct {
	sent      [][]byte
	responses [][]byte
	idx       int
}

func (n *noBF21Transport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	n.sent = append(n.sent, encoded)
	return n.fetch()
}

func (n *noBF21Transport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	n.sent = append(n.sent, raw)
	resp, err := n.fetch()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, resp.Data...)
	return append(out, resp.SW1, resp.SW2), nil
}

func (n *noBF21Transport) fetch() (*apdu.Response, error) {
	if n.idx >= len(n.responses) {
		return nil, errors.New("noBF21Transport: out of canned responses")
	}
	raw := n.responses[n.idx]
	n.idx++
	return apdu.ParseResponse(raw)
}

func (n *noBF21Transport) Close() error { return nil }
func (n *noBF21Transport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// isGetDataBF21 reports whether the encoded APDU is a GET DATA BF21
// command (CLA=any, INS=0xCA, P1=0xBF, P2=0x21).
func isGetDataBF21(encoded []byte) bool {
	if len(encoded) < 4 {
		return false
	}
	return encoded[1] == 0xCA && encoded[2] == 0xBF && encoded[3] == 0x21
}

// isSelect reports whether the encoded APDU is a SELECT command
// (INS=0xA4 P1=0x04 P2=0x00).
func isSelect(encoded []byte) bool {
	if len(encoded) < 4 {
		return false
	}
	return encoded[1] == 0xA4 && encoded[2] == 0x04 && encoded[3] == 0x00
}

// mustGenerateP256ECDHPub generates a fresh P-256 ECDH public key for
// use as a stand-in PK.SD.ECKA in tests.
func mustGenerateP256ECDHPub(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 ECDH key: %v", err)
	}
	return priv.PublicKey()
}

// TestOpen_PreverifiedKey_RejectsCardTrustPolicy asserts that a
// caller setting both PreverifiedCardStaticPublicKey AND
// CardTrustPolicy is failed closed. The combination is incoherent —
// the preverified path skips the cert-fetch, so there is no chain
// for CardTrustPolicy to validate against. Earlier the policy was
// silently dropped, which made the API look like it would validate
// the supplied pubkey when in fact validation was bypassed. The
// rejection forces the caller to make the trust posture explicit:
// either drop the preverified key (so the policy actually runs
// against a fetched chain) or set InsecureSkipCardAuthentication=true
// to acknowledge the validation already happened upstream.
func TestOpen_PreverifiedKey_RejectsCardTrustPolicy(t *testing.T) {
	pubKey := mustGenerateP256ECDHPub(t)

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDPIV
	cfg.PreverifiedCardStaticPublicKey = pubKey
	cfg.CardTrustPolicy = &trust.Policy{Roots: x509.NewCertPool()}

	_, err := Open(context.Background(), &noBF21Transport{}, cfg)
	if err == nil {
		t.Fatal("Open succeeded with both PreverifiedCardStaticPublicKey and CardTrustPolicy set; the combination must be rejected")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig; got: %v", err)
	}
	if !strings.Contains(err.Error(), "PreverifiedCardStaticPublicKey") {
		t.Errorf("error should name the offending field; got: %v", err)
	}
	if !strings.Contains(err.Error(), "InsecureSkipCardAuthentication") {
		t.Errorf("error should suggest InsecureSkipCardAuthentication as the alternative; got: %v", err)
	}
}

// TestOpen_PreverifiedKey_RejectsCardTrustAnchors mirrors the
// CardTrustPolicy rejection for the anchors path. Same rationale:
// the preverified path skips the cert fetch; CardTrustAnchors has
// no chain to validate.
func TestOpen_PreverifiedKey_RejectsCardTrustAnchors(t *testing.T) {
	pubKey := mustGenerateP256ECDHPub(t)

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDPIV
	cfg.PreverifiedCardStaticPublicKey = pubKey
	cfg.CardTrustAnchors = x509.NewCertPool()

	_, err := Open(context.Background(), &noBF21Transport{}, cfg)
	if err == nil {
		t.Fatal("Open succeeded with both PreverifiedCardStaticPublicKey and CardTrustAnchors set; the combination must be rejected")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig; got: %v", err)
	}
	if !strings.Contains(err.Error(), "PreverifiedCardStaticPublicKey") {
		t.Errorf("error should name the offending field; got: %v", err)
	}
}

// TestOpen_PreverifiedKey_AcceptsInsecureSkipCardAuthentication is
// the inverse pin: the documented happy-path pairing must continue
// to work. The handshake won't complete against the canned-response
// transport (intentionally — we just need Open to get past config
// validation), but the failure must NOT come from ErrInvalidConfig.
// If a future refactor accidentally tightens the rejection rule and
// also blocks this combination, this test catches it.
func TestOpen_PreverifiedKey_AcceptsInsecureSkipCardAuthentication(t *testing.T) {
	pubKey := mustGenerateP256ECDHPub(t)

	cfg := testYubiKeySCP11bConfig()
	cfg.SelectAID = AIDPIV
	cfg.PreverifiedCardStaticPublicKey = pubKey
	cfg.InsecureSkipCardAuthentication = true

	_, err := Open(context.Background(), &noBF21Transport{
		responses: [][]byte{
			{0x90, 0x00},             // SELECT response
			{0x00, 0x00, 0x6A, 0x80}, // AUTHENTICATE: malformed, fail-stop
		},
	}, cfg)
	if err == nil {
		t.Fatal("Open unexpectedly succeeded; expected handshake failure downstream of config validation")
	}
	if errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Open rejected the documented happy-path pairing "+
			"(PreverifiedCardStaticPublicKey + InsecureSkipCardAuthentication) "+
			"with ErrInvalidConfig; this combination must be accepted: %v", err)
	}
}
