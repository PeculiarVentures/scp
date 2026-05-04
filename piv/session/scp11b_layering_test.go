package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport"
)

// TestOpenSCP11bPIV_BF21_NeverAgainstPIV is the headline regression
// test for the SCP11b-on-PIV layering fix. The bug:
// scp11.Open(SelectAID=PIV, ...) selected the PIV applet and then
// issued GET DATA BF21 against it, which the YubiKey PIV applet
// rejects with SW=6D00 because BF21 isn't part of its dispatch table.
//
// The fix: OpenSCP11bPIV fetches and validates PK.SD.ECKA via an
// unauthenticated Security Domain session first, then opens SCP11
// against PIV with the pre-supplied public key. This test pins the
// fix down so a future refactor can't silently regress to the old
// behavior.
//
// Assertion: BF21 must appear in the recorded APDU stream only
// before the SELECT for the PIV AID, never after. SELECT for SD AID
// (A000000151000000) and SELECT for PIV AID (A000000308) are both
// expected; the order matters.
func TestOpenSCP11bPIV_BF21_NeverAgainstPIV(t *testing.T) {
	// SD response for GET DATA BF21: a single self-signed P-256 cert
	// in yubikit shape (no 7F21/BF21 wrapper). InsecureSkipCardAuth
	// is set in the options below, so the chain isn't validated and
	// any well-formed cert with a P-256 public key works.
	cert := mustP256Cert(t)

	tr := &orderedTransport{
		responses: [][]byte{
			{0x90, 0x00},                    // SELECT SD: 9000
			appendSW(cert, 0x90, 0x00),      // GET DATA BF21 → cert (yubikit shape)
			{0x90, 0x00},                    // SELECT PIV: 9000
			{0x00, 0x00, 0x6A, 0x80},        // INTERNAL AUTHENTICATE: malformed → fail-stop
		},
	}

	opts := SCP11bPIVOptions{
		InsecureSkipCardAuthentication: true,
	}
	_, err := OpenSCP11bPIV(context.Background(), tr, opts)
	if err == nil {
		t.Fatal("OpenSCP11bPIV unexpectedly succeeded against fake transport")
	}

	// Find the SELECT-PIV index in the recorded APDUs. Anything after
	// it is on PIV; BF21 in that range is the bug.
	pivSelectIdx := -1
	for i, sent := range tr.sent {
		if isSelect(sent) && containsAID(sent, scp11.AIDPIV) {
			pivSelectIdx = i
			break
		}
	}
	if pivSelectIdx < 0 {
		t.Fatalf("no SELECT-PIV observed in %d APDU(s); flow never reached PIV phase",
			len(tr.sent))
	}

	for i := pivSelectIdx + 1; i < len(tr.sent); i++ {
		if isGetDataBF21(tr.sent[i]) {
			t.Fatalf("GET DATA BF21 sent after SELECT PIV (APDU #%d, %X) — "+
				"this is exactly the SCP11b-on-PIV layering bug; the cert "+
				"fetch must complete via SD before SELECT PIV",
				i+1, tr.sent[i])
		}
	}

	// Defense in depth: a well-behaved flow sends exactly one BF21,
	// and it sits before the SELECT-PIV, after the SELECT-SD.
	bf21Count := 0
	bf21FirstIdx := -1
	for i, sent := range tr.sent {
		if isGetDataBF21(sent) {
			bf21Count++
			if bf21FirstIdx < 0 {
				bf21FirstIdx = i
			}
		}
	}
	if bf21Count == 0 {
		t.Error("no GET DATA BF21 ever sent — SD discovery path was skipped entirely")
	}
	if bf21FirstIdx >= pivSelectIdx {
		t.Errorf("BF21 first sent at APDU #%d, after SELECT-PIV at APDU #%d",
			bf21FirstIdx+1, pivSelectIdx+1)
	}
}

// TestOpenSCP11bPIV_PreverifiedKey_SkipsSD asserts the production
// short-circuit: when the caller supplies CardStaticPublicKey, the
// SD-side discovery is skipped entirely. No SELECT-SD, no BF21 — the
// flow goes straight to SELECT-PIV.
func TestOpenSCP11bPIV_PreverifiedKey_SkipsSD(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert to ECDH: %v", err)
	}

	tr := &orderedTransport{
		responses: [][]byte{
			{0x90, 0x00},             // SELECT PIV
			{0x00, 0x00, 0x6A, 0x80}, // AUTHENTICATE fail-stop
		},
	}

	opts := SCP11bPIVOptions{
		InsecureSkipCardAuthentication: true,
		CardStaticPublicKey:            pub,
	}
	_, _ = OpenSCP11bPIV(context.Background(), tr, opts)

	for i, sent := range tr.sent {
		if isGetDataBF21(sent) {
			t.Errorf("BF21 sent (APDU #%d) despite CardStaticPublicKey "+
				"being supplied; SD discovery should have been skipped",
				i+1)
		}
		if isSelect(sent) && containsAID(sent, scp11.AIDSecurityDomain) {
			t.Errorf("SELECT-SD sent (APDU #%d) despite CardStaticPublicKey "+
				"being supplied", i+1)
		}
	}
}

// TestOpenSCP11bPIV_NoTrustPosture_FailsBeforeAnyAPDU pins down the
// trust-posture guard at the helper level. With neither
// CardTrustPolicy nor InsecureSkipCardAuthentication set, the helper
// must reject the call without sending any APDUs to the card.
func TestOpenSCP11bPIV_NoTrustPosture_FailsBeforeAnyAPDU(t *testing.T) {
	tr := &orderedTransport{}

	_, err := OpenSCP11bPIV(context.Background(), tr, SCP11bPIVOptions{})
	if err == nil {
		t.Fatal("OpenSCP11bPIV succeeded with no trust posture configured")
	}
	if !strings.Contains(err.Error(), "CardTrustPolicy") &&
		!strings.Contains(err.Error(), "InsecureSkipCardAuthentication") {
		t.Errorf("error should mention required trust fields; got: %v", err)
	}
	if len(tr.sent) > 0 {
		t.Errorf("transport saw %d APDU(s) before the trust-posture guard "+
			"rejected the call; guard must run pre-wire", len(tr.sent))
	}
}

// orderedTransport records every APDU and replays canned responses.
type orderedTransport struct {
	sent      [][]byte
	responses [][]byte
	idx       int
}

func (o *orderedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	o.sent = append(o.sent, encoded)
	return o.fetch()
}

func (o *orderedTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	o.sent = append(o.sent, raw)
	resp, err := o.fetch()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, resp.Data...)
	return append(out, resp.SW1, resp.SW2), nil
}

func (o *orderedTransport) fetch() (*apdu.Response, error) {
	if o.idx >= len(o.responses) {
		return nil, errors.New("orderedTransport: out of canned responses")
	}
	raw := o.responses[o.idx]
	o.idx++
	return apdu.ParseResponse(raw)
}

func (o *orderedTransport) Close() error { return nil }
func (o *orderedTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

func appendSW(body []byte, sw1, sw2 byte) []byte {
	out := append([]byte{}, body...)
	return append(out, sw1, sw2)
}

func isGetDataBF21(encoded []byte) bool {
	if len(encoded) < 4 {
		return false
	}
	return encoded[1] == 0xCA && encoded[2] == 0xBF && encoded[3] == 0x21
}

func isSelect(encoded []byte) bool {
	if len(encoded) < 4 {
		return false
	}
	return encoded[1] == 0xA4 && encoded[2] == 0x04 && encoded[3] == 0x00
}

// containsAID reports whether the SELECT command's data field
// contains the given AID. The data field is everything after the
// 5-byte header (CLA INS P1 P2 Lc).
func containsAID(encoded, aid []byte) bool {
	if len(encoded) < 5+len(aid) {
		return false
	}
	return bytes.Contains(encoded[5:], aid)
}

// mustP256Cert returns a self-signed P-256 X.509 cert as DER bytes.
func mustP256Cert(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scp11-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}
