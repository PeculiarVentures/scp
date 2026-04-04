package mockcard

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/session"
)

func TestEndToEnd_SCP11b_Handshake(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}

	ctx := context.Background()
	transport := card.Transport()

	// Open an SCP11b session. This performs the full protocol:
	//   1. SELECT Security Domain (unencrypted)
	//   2. GET DATA for BF21 certificate
	//   3. INTERNAL AUTHENTICATE (ECDH key agreement)
	//   4. Session key derivation + receipt verification
	//   5. SELECT PIV application (encrypted + MACed)
	sess, err := session.Open(ctx, transport, session.DefaultConfig())
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	t.Log("SCP11b session established successfully")
	t.Logf("  S-ENC:  %X", sess.SessionKeys().SENC)
	t.Logf("  S-MAC:  %X", sess.SessionKeys().SMAC)
	t.Logf("  S-RMAC: %X", sess.SessionKeys().SRMAC)
}

func TestEndToEnd_SCP11b_EchoCommand(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), &session.Config{
		Variant:           session.SCP11b,
		SecurityDomainAID: session.AIDSecurityDomain,
		ApplicationAID:    nil, // Don't auto-select an app
		KeyID:             0x13,
		KeyVersion:        0x01,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	// Send an echo command through the secure channel.
	// The mock card's INS=0xFD echoes back the data.
	testData := []byte("Hello from SCP11b secure channel!")
	echoCmd := &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: testData,
		Le:   -1,
	}

	resp, err := sess.Transmit(ctx, echoCmd)
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}

	if !resp.IsSuccess() {
		t.Fatalf("echo command failed: SW=%04X", resp.StatusWord())
	}

	if !bytes.Equal(resp.Data, testData) {
		t.Errorf("echo mismatch:\n  got:  %X\n  want: %X", resp.Data, testData)
	}

	t.Logf("Echo round-trip: %d bytes through SCP11b secure channel", len(testData))
}

func TestEndToEnd_SCP11b_MultipleCommands(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), &session.Config{
		Variant:           session.SCP11b,
		SecurityDomainAID: session.AIDSecurityDomain,
		ApplicationAID:    nil,
		KeyID:             0x13,
		KeyVersion:        0x01,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	// Send multiple echo commands to verify counter advancement and
	// MAC chaining work correctly across a sequence.
	for i := 0; i < 10; i++ {
		data := []byte{byte(i), byte(i * 2), byte(i * 3)}
		cmd := &apdu.Command{
			CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
			Data: data, Le: -1,
		}

		resp, err := sess.Transmit(ctx, cmd)
		if err != nil {
			t.Fatalf("command %d: Transmit: %v", i, err)
		}
		if !resp.IsSuccess() {
			t.Fatalf("command %d: SW=%04X", i, resp.StatusWord())
		}
		if !bytes.Equal(resp.Data, data) {
			t.Fatalf("command %d: echo mismatch", i)
		}
	}

	t.Log("10 sequential encrypted commands completed successfully")
}

func TestEndToEnd_SCP11b_PIVGenerateKey(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), session.DefaultConfig())
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	// PIV GENERATE ASYMMETRIC KEY PAIR for slot 9A.
	genCmd := &apdu.Command{
		CLA: 0x00, INS: 0x47, P1: 0x00, P2: 0x9A,
		Data: []byte{0xAC, 0x03, 0x80, 0x01, 0x11}, // EC P-256
		Le:   -1,
	}

	resp, err := sess.Transmit(ctx, genCmd)
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("generate key failed: SW=%04X", resp.StatusWord())
	}

	// Mock card returns a 65-byte uncompressed P-256 point.
	if len(resp.Data) < 65 {
		t.Fatalf("generated key too short: %d bytes", len(resp.Data))
	}

	t.Logf("PIV key generated via SCP11b: %d bytes response", len(resp.Data))
}

func TestEndToEnd_SCP11b_EmptyPayload(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}
	// Explicitly set SCP11b (no receipt).
	card.Variant = 0

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), &session.Config{
		Variant:           session.SCP11b,
		SecurityDomainAID: session.AIDSecurityDomain,
		ApplicationAID:    nil,
		KeyID:             0x13,
		KeyVersion:        0x01,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	// Send a command with empty data, then one with data.
	// This tests that the encryption counter advances correctly
	// even for empty payloads (GP §5.3.2 counter management).
	emptyCmd := &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: nil, Le: -1,
	}
	resp, err := sess.Transmit(ctx, emptyCmd)
	if err != nil {
		t.Fatalf("empty command: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("empty command failed: SW=%04X", resp.StatusWord())
	}

	// Now a command with data — counters must still be in sync.
	dataCmd := &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: []byte{0xDE, 0xAD}, Le: -1,
	}
	resp, err = sess.Transmit(ctx, dataCmd)
	if err != nil {
		t.Fatalf("data command after empty: %v", err)
	}
	if !bytes.Equal(resp.Data, []byte{0xDE, 0xAD}) {
		t.Fatalf("echo mismatch after empty command")
	}

	t.Log("Empty + data command sequence completed (counter sync verified)")
}

func TestEndToEnd_SCP11b_NoReceipt(t *testing.T) {
	// SCP11b specifically: the card does NOT send a receipt.
	// The session must handle this — no receipt verification,
	// and macChain starts at zeros.
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}
	card.Variant = 0 // SCP11b

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), &session.Config{
		Variant:           session.SCP11b,
		SecurityDomainAID: session.AIDSecurityDomain,
		ApplicationAID:    nil,
		KeyID:             0x13,
		KeyVersion:        0x01,
	})
	if err != nil {
		t.Fatalf("session.Open (SCP11b, no receipt): %v", err)
	}
	defer sess.Close()

	// Verify macChain is zeros (not receipt).
	if sess.SessionKeys().MACChain == nil {
		t.Fatal("macChain is nil")
	}
	for _, b := range sess.SessionKeys().MACChain {
		if b != 0 {
			t.Fatalf("SCP11b macChain should be zeros, got %X", sess.SessionKeys().MACChain)
		}
	}

	// Encrypted echo should still work.
	testData := []byte("SCP11b no-receipt test")
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: testData, Le: -1,
	})
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(resp.Data, testData) {
		t.Errorf("echo mismatch:\n  got:  %s\n  want: %s", resp.Data, testData)
	}

	t.Log("SCP11b (no receipt) session + encrypted echo verified")
}

func TestEndToEnd_SCP11a_WithReceipt(t *testing.T) {
	// SCP11a: card sends receipt, host verifies it.
	// macChain starts at receipt value.
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}
	card.Variant = 1 // SCP11a

	// For SCP11a, we need an OCE private key and certificate.
	oceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate OCE key: %v", err)
	}

	oceCertTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Test OCE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	oceCertDER, err := x509.CreateCertificate(rand.Reader, oceCertTmpl, oceCertTmpl, &oceKey.PublicKey, oceKey)
	if err != nil {
		t.Fatalf("create OCE cert: %v", err)
	}
	oceCert, err := x509.ParseCertificate(oceCertDER)
	if err != nil {
		t.Fatalf("parse OCE cert: %v", err)
	}

	ctx := context.Background()
	sess, err := session.Open(ctx, card.Transport(), &session.Config{
		Variant:           session.SCP11a,
		SecurityDomainAID: session.AIDSecurityDomain,
		ApplicationAID:    nil,
		KeyID:             0x11, // SCP11a KID
		KeyVersion:        0x01,
		OCEPrivateKey:     oceKey,
		OCECertificate:    oceCert,
	})
	if err != nil {
		t.Fatalf("session.Open (SCP11a): %v", err)
	}
	defer sess.Close()

	// macChain should NOT be zeros (it's the receipt).
	allZero := true
	for _, b := range sess.SessionKeys().MACChain {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("SCP11a macChain should be receipt value, not zeros")
	}

	// Encrypted echo.
	testData := []byte("SCP11a mutual auth test")
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: testData, Le: -1,
	})
	if err != nil {
		t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(resp.Data, testData) {
		t.Errorf("echo mismatch")
	}

	t.Log("SCP11a (with receipt) session + encrypted echo verified")
}
