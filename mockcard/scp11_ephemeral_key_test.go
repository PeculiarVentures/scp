package mockcard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/session"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// recordingTransport wraps an underlying transport and captures the
// raw bytes of every command APDU sent through it. Used to verify
// wire-format properties of session.Open() and Transmit().
type recordingTransport struct {
	inner transport.Transport
	sent  [][]byte
}

func (r *recordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	r.sent = append(r.sent, encoded)
	return r.inner.Transmit(ctx, cmd)
}

func (r *recordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	r.sent = append(r.sent, raw)
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *recordingTransport) Close() error { return r.inner.Close() }

// extractOCEEphemeralPubkey finds an AUTHENTICATE APDU (INS=0x88
// INTERNAL_AUTHENTICATE or 0x82 MUTUAL_AUTHENTICATE) in a list of
// recorded CAPDUs and returns the OCE ephemeral public key bytes
// from its 5F49 TLV. SCP11 AUTHENTICATE embeds the host's ephemeral
// pubkey at this exact tag per GP §7.6.2.3, so capturing this value
// lets a test verify the host actually put the expected ephemeral
// on the wire.
func extractOCEEphemeralPubkey(sent [][]byte) []byte {
	for _, capdu := range sent {
		if len(capdu) < 5 {
			continue
		}
		ins := capdu[1]
		if ins != 0x82 && ins != 0x88 {
			continue
		}
		lc := int(capdu[4])
		if lc == 0 || len(capdu) < 5+lc {
			continue
		}
		data := capdu[5 : 5+lc]
		nodes, err := tlv.Decode(data)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			if n.Tag == 0x5F49 {
				return n.Value
			}
		}
	}
	return nil
}

// TestSCP11_InsecureTestOnlyEphemeralKey_ProducesExpectedOCEPubkey
// confirms the InsecureTestOnlyEphemeralKey seam actually puts the
// expected OCE ephemeral public key on the wire — not just that the
// session opens. Earlier this test only sanity-checked that the fixed
// scalar derives Samsung's published public point in isolation, which
// proved nothing about whether session.Open() routed the override
// through to the AUTHENTICATE APDU.
//
// This version drives session.Open through a recording transport,
// finds the AUTHENTICATE APDU, parses its 5F49 (EPK.OCE) TLV, and
// asserts byte-exact equality with Samsung's published EPK_OCE_ECKA_P256
// uncompressed point.
//
// Vector source: Samsung OpenSCP-Java
// src/test/java/com/samsung/openscp/testdata/Scp11TestData.java
func TestSCP11_InsecureTestOnlyEphemeralKey_ProducesExpectedOCEPubkey(t *testing.T) {
	scalar, _ := hex.DecodeString("B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5")
	fixedKey, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("parse ephemeral key: %v", err)
	}

	wantEPK, _ := hex.DecodeString(
		"0470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5DBBF8A32" +
			"F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C92")

	card, err := New()
	if err != nil {
		t.Fatalf("New mock card: %v", err)
	}
	rec := &recordingTransport{inner: card.Transport()}

	sess, err := session.Open(context.Background(), rec, &session.Config{
		Variant:                        session.SCP11b,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
		InsecureTestOnlyEphemeralKey:   fixedKey,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	gotEPK := extractOCEEphemeralPubkey(rec.sent)
	if gotEPK == nil {
		t.Fatal("could not find 5F49 OCE ephemeral pubkey in any recorded APDU")
	}
	if !bytes.Equal(gotEPK, wantEPK) {
		t.Errorf("OCE ephemeral pubkey on wire does not match Samsung's vector:\n  got  %X\n  want %X",
			gotEPK, wantEPK)
	}
}

// TestSCP11_EphemeralKey_NilProducesFreshHostKey confirms that with
// InsecureTestOnlyEphemeralKey nil, two successive opens against fresh
// mock cards produce DIFFERENT host ephemeral public keys.
//
// Earlier the test compared SENC across two sessions, but the mock
// card's own ephemeral key is also random — so SENC could differ even
// if the host accidentally reused the same ephemeral. This version
// captures the host's 5F49 EPK.OCE bytes directly, isolating host-side
// randomness from card-side randomness.
func TestSCP11_EphemeralKey_NilProducesFreshHostKey(t *testing.T) {
	openAndExtract := func() []byte {
		t.Helper()
		card, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rec := &recordingTransport{inner: card.Transport()}
		sess, err := session.Open(context.Background(), rec, &session.Config{
			Variant:                        session.SCP11b,
			SelectAID:                      session.AIDSecurityDomain,
			KeyID:                          0x13,
			KeyVersion:                     0x01,
			InsecureSkipCardAuthentication: true,
			// InsecureTestOnlyEphemeralKey intentionally nil
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer sess.Close()
		return extractOCEEphemeralPubkey(rec.sent)
	}

	a := openAndExtract()
	b := openAndExtract()
	if a == nil || b == nil {
		t.Fatal("missing OCE ephemeral pubkey in recorded APDUs")
	}
	if bytes.Equal(a, b) {
		t.Errorf("two opens produced the SAME host ephemeral pubkey (randomness broken):\n  %X", a)
	}
}

// TestSCP11_InsecureTestOnlyEphemeralKey_RejectsNonP256 confirms the
// curve check at Open time: passing a non-P-256 ECDH key (e.g. P-384)
// must fail before any APDU is constructed, rather than producing a
// malformed EPK.OCE on the wire that the card would reject anyway.
func TestSCP11_InsecureTestOnlyEphemeralKey_RejectsNonP256(t *testing.T) {
	p384k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = session.Open(context.Background(), card.Transport(), &session.Config{
		Variant:                        session.SCP11b,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
		InsecureTestOnlyEphemeralKey:   p384k,
	})
	if err == nil {
		t.Fatal("Open with P-384 ephemeral key should fail (P-256 only)")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should mention P-256 curve requirement, got: %v", err)
	}
}

// TestSCP11a_PSO_WireFormat confirms the PERFORM SECURITY OPERATION
// APDUs sent during SCP11a OCE certificate upload match the layout
// from yubikit-android/yubikit Python's reference SCP11 implementation
// and GP §7.5.2:
//
//   - One PSO APDU per certificate (no chunking of a single cert).
//   - CLA = 0x80 throughout.
//   - INS = 0x2A.
//   - P1 = OCEKeyReference.KVN.
//   - P2 = OCEKeyReference.KID, with bit 0x80 set on every cert
//     EXCEPT the last (leaf).
//   - Data = the cert's DER bytes.
//
// Earlier this code chunked a single cert into 255-byte pieces with
// GP CLA-chaining (0x90/0x80). This test documents the corrected
// behavior and would have caught the regression.
func TestSCP11a_PSO_WireFormat(t *testing.T) {
	// Build a synthetic 3-cert chain for the test. Real OCE certs
	// would be intermediates + OCE leaf; the wire format work doesn't
	// depend on them being real-issued, so we use generated certs.
	mkCert := func(t *testing.T, n int) *x509.Certificate {
		t.Helper()
		k, _ := ecdsaP256(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(n)),
			Subject:      pkixName(fmt.Sprintf("OCE-%d", n)),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		c, _ := x509.ParseCertificate(der)
		return c
	}
	leafKey, _ := ecdsaP256(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkixName("OCE-Leaf"),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &leafKey.PublicKey, leafKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	chain := []*x509.Certificate{
		mkCert(t, 1), // intermediate 1
		mkCert(t, 2), // intermediate 2
		leaf,         // leaf — must come last
	}

	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &recordingTransport{inner: card.Transport()}

	// SCP11a needs the OCE private key to match the leaf cert; we
	// pass the leaf's actual private key. Open may fail at a later
	// step (e.g. the mock doesn't synthesize a receipt) but we only
	// care that PSO went out correctly before any failure — capture
	// the recorded APDUs regardless.
	sess, _ := session.Open(context.Background(), rec, &session.Config{
		Variant:                        session.SCP11a,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x11,
		KeyVersion:                     0x01,
		OCECertificates:                chain,
		OCEKeyReference:                session.KeyRef{KID: 0x10, KVN: 0x03},
		OCEPrivateKey:                  leafKey,
		InsecureSkipCardAuthentication: true,
	})
	if sess != nil {
		defer sess.Close()
	}

	// Pull out every PSO (INS=0x2A) APDU we actually sent.
	var pso [][]byte
	for _, capdu := range rec.sent {
		if len(capdu) >= 2 && capdu[1] == 0x2A {
			pso = append(pso, capdu)
		}
	}
	if len(pso) != 3 {
		t.Fatalf("expected 3 PSO APDUs (one per cert), got %d", len(pso))
	}

	// Per-APDU header checks.
	for i, capdu := range pso {
		isLast := i == len(pso)-1
		wantP2 := byte(0x10)
		if !isLast {
			wantP2 |= 0x80
		}
		if capdu[0] != 0x80 {
			t.Errorf("PSO %d: CLA = %02X, want 80", i, capdu[0])
		}
		if capdu[1] != 0x2A {
			t.Errorf("PSO %d: INS = %02X, want 2A", i, capdu[1])
		}
		if capdu[2] != 0x03 {
			t.Errorf("PSO %d: P1 = %02X, want 03 (KVN)", i, capdu[2])
		}
		if capdu[3] != wantP2 {
			t.Errorf("PSO %d: P2 = %02X, want %02X (KID=10, chain-bit %v)",
				i, capdu[3], wantP2, !isLast)
		}
	}
}

// helpers used by TestSCP11a_PSO_WireFormat above
func ecdsaP256(t *testing.T) (*ecdsa.PrivateKey, error) {
	t.Helper()
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func pkixName(cn string) (n pkix.Name) {
	n.CommonName = cn
	return
}

// TestSCP11b_ForgedReceipt_Rejected confirms the host verifies any
// receipt the card returns, even for SCP11b where receipts are
// optional. Earlier the code used a receipt as the MAC chain seed
// without verification — so a card sending arbitrary bytes as the
// receipt would have its bytes accepted as MAC chain state. That
// would let a malicious card forge the post-handshake MAC chain
// state without holding the receipt key.
//
// This test injects a forged receipt into the SCP11b INTERNAL
// AUTHENTICATE response and asserts session.Open rejects it.
func TestSCP11b_ForgedReceipt_Rejected(t *testing.T) {
	// Build a transport that wraps the mock and injects a fake
	// receipt TLV (0x86 || 0x10 || 16 bytes of 0xAB) into the
	// INTERNAL AUTHENTICATE response. Everything else passes through.
	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wrap := &receiptInjector{inner: card.Transport()}

	_, err = session.Open(context.Background(), wrap, &session.Config{
		Variant:                        session.SCP11b,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
	})
	if err == nil {
		t.Fatal("Open should reject a forged receipt; instead succeeded")
	}
	if !strings.Contains(err.Error(), "receipt") {
		t.Errorf("error should mention receipt verification; got: %v", err)
	}
}

// receiptInjector wraps a transport and rewrites the INTERNAL
// AUTHENTICATE response (INS=0x88) to append a fake receipt TLV
// before the SW1/SW2.
type receiptInjector struct {
	inner transport.Transport
}

func (r *receiptInjector) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := r.inner.Transmit(ctx, cmd)
	if err != nil || cmd.INS != 0x88 || !resp.IsSuccess() {
		return resp, err
	}
	// Append a fake receipt TLV: 86 10 ABABAB...
	fakeReceipt := bytes.Repeat([]byte{0xAB}, 16)
	resp.Data = append(resp.Data, 0x86, 0x10)
	resp.Data = append(resp.Data, fakeReceipt...)
	return resp, nil
}

func (r *receiptInjector) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *receiptInjector) Close() error { return r.inner.Close() }
