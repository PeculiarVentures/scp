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
	"github.com/PeculiarVentures/scp/scp11"
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
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true // mock card self-signed key
	sess, err := scp11.Open(ctx, transport, cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
	}
	defer sess.Close()

	t.Log("SCP11b session established successfully")
	t.Logf("  S-ENC:  %X", sess.InsecureExportSessionKeysForTestOnly().SENC)
	t.Logf("  S-MAC:  %X", sess.InsecureExportSessionKeysForTestOnly().SMAC)
	t.Logf("  S-RMAC: %X", sess.InsecureExportSessionKeysForTestOnly().SRMAC)
}

func TestEndToEnd_SCP11b_EchoCommand(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}

	ctx := context.Background()
	sess, err := scp11.Open(ctx, card.Transport(), &scp11.Config{
		Variant:                        scp11.SCP11b,
		SelectAID:                      scp11.AIDSecurityDomain,
		ApplicationAID:                 nil, // Don't auto-select an app
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
	})
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
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
	sess, err := scp11.Open(ctx, card.Transport(), &scp11.Config{
		Variant:                        scp11.SCP11b,
		SelectAID:                      scp11.AIDSecurityDomain,
		ApplicationAID:                 nil,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
	})
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
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
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.ApplicationAID = scp11.AIDPIV
	cfg.InsecureSkipCardAuthentication = true
	sess, err := scp11.Open(ctx, card.Transport(), cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
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
	sess, err := scp11.Open(ctx, card.Transport(), &scp11.Config{
		Variant:                        scp11.SCP11b,
		SelectAID:                      scp11.AIDSecurityDomain,
		ApplicationAID:                 nil,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
	})
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
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
	// Legacy SCP11b path: pre-Amendment-F-v1.4 cards that omit the
	// receipt. The host must opt in via InsecureAllowSCP11bWithoutReceipt
	// and the card must be configured to model the legacy behavior;
	// macChain seeds from zeros instead of the receipt.
	card, err := New()
	if err != nil {
		t.Fatalf("create mock card: %v", err)
	}
	card.Variant = 0 // SCP11b
	card.LegacySCP11bNoReceipt = true

	ctx := context.Background()
	sess, err := scp11.Open(ctx, card.Transport(), &scp11.Config{
		Variant:                           scp11.SCP11b,
		SelectAID:                         scp11.AIDSecurityDomain,
		ApplicationAID:                    nil,
		KeyID:                             0x13,
		KeyVersion:                        0x01,
		InsecureSkipCardAuthentication:    true,
		InsecureAllowSCP11bWithoutReceipt: true,
	})
	if err != nil {
		t.Fatalf("scp11.Open (SCP11b, no receipt): %v", err)
	}
	defer sess.Close()

	// Verify macChain is zeros (not receipt) in the legacy path.
	if sess.InsecureExportSessionKeysForTestOnly().MACChain == nil {
		t.Fatal("macChain is nil")
	}
	for _, b := range sess.InsecureExportSessionKeysForTestOnly().MACChain {
		if b != 0 {
			t.Fatalf("legacy SCP11b macChain should be zeros, got %X", sess.InsecureExportSessionKeysForTestOnly().MACChain)
		}
	}

	// Encrypted echo should still work.
	testData := []byte("SCP11b legacy no-receipt test")
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

	t.Log("SCP11b legacy (no receipt) session + encrypted echo verified")
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
	sess, err := scp11.Open(ctx, card.Transport(), &scp11.Config{
		Variant:                        scp11.SCP11a,
		SelectAID:                      scp11.AIDSecurityDomain,
		ApplicationAID:                 nil,
		KeyID:                          0x11, // SCP11a KID
		KeyVersion:                     0x01,
		OCEPrivateKey:                  oceKey,
		OCECertificates:                []*x509.Certificate{oceCert},
		OCEKeyReference:                scp11.KeyRef{KID: 0x10, KVN: 0x03}, // YubiKey default
		InsecureSkipCardAuthentication: true,
	})
	if err != nil {
		t.Fatalf("scp11.Open (SCP11a): %v", err)
	}
	defer sess.Close()

	// macChain should NOT be zeros (it's the receipt).
	allZero := true
	for _, b := range sess.InsecureExportSessionKeysForTestOnly().MACChain {
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

// TestCard_GetData_CRD confirms the SCP11 mock returns Card
// Recognition Data on GET DATA tag 0x0066. Like the SCP03 mock, this
// is permitted before authentication so the host can probe the card
// before deciding which protocol to negotiate.
func TestCard_GetData_CRD(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := card.Transport().Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x66, Le: 0,
	})
	if err != nil {
		t.Fatalf("GET DATA 0x0066: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("SW=%04X", resp.StatusWord())
	}
	if len(resp.Data) == 0 || resp.Data[0] != 0x66 {
		t.Errorf("CRD response should begin with 0x66; got first byte %02X", resp.Data[0])
	}
}

// TestCard_GetData_KeyInfo confirms the SCP11 mock answers GET DATA
// tag 0x00E0 with a key information template that the host parser
// can decode.
func TestCard_GetData_KeyInfo(t *testing.T) {
	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := card.Transport().Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0xE0, Le: 0,
	})
	if err != nil {
		t.Fatalf("GET DATA 0x00E0: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("SW=%04X", resp.StatusWord())
	}
	if len(resp.Data) < 4 || resp.Data[0] != 0xE0 {
		t.Errorf("key info response should begin with 0xE0; got %X", resp.Data)
	}
}

// TestCard_HandshakeINS_RefusedUnderSM is a structural test: the
// SCP11 handshake commands (INTERNAL AUTHENTICATE 0x88, EXTERNAL
// AUTHENTICATE 0x82, PERFORM SECURITY OPERATION 0x2A) must not be
// runnable inside an active session — they only make sense
// pre-handshake. Pre-refactor, the post-auth dispatcher (processPlain)
// silently fell through to 6D00 for these because none of them had
// cases there; the new dispatchINS makes the policy explicit by
// returning 6985 (conditions not satisfied) when invoked under SM.
//
// This test guards against the kind of dispatcher-drift that
// originally hid the GET DATA bug fixed in #50 — if someone adds a
// new INS case to dispatchINS in the future and it should be
// pre-auth-only, omitting the underSM check would let it run
// mid-session unnoticed.
func TestCard_HandshakeINS_RefusedUnderSM(t *testing.T) {
	ctx := context.Background()
	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	sess, err := scp11.Open(ctx, card.Transport(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// Each of these would return 6985 if dispatchINS routed them
	// correctly under SM. Pre-refactor, processPlain had no case for
	// them and they fell through to 6D00; the test now also asserts
	// the SW so a regression to the silent-fallthrough behavior
	// fails loudly.
	for _, ins := range []byte{0x88, 0x82, 0x2A} {
		resp, err := sess.Transmit(ctx, &apdu.Command{
			CLA: 0x80, INS: ins, P1: 0x00, P2: 0x00, Le: 0,
		})
		if err != nil {
			t.Errorf("INS=%02X transmit: %v", ins, err)
			continue
		}
		if resp.StatusWord() != 0x6985 {
			t.Errorf("INS=%02X under SM should return 6985 (conditions not satisfied); got %04X",
				ins, resp.StatusWord())
		}
	}
}

// TestCard_SecureMessaging_ExtendedLcMAC is a regression test for
// the MAC input encoding when wrapped APDU data exceeds 255 bytes.
// Pre-fix, the mock computed the C-MAC with byte(len(data)) for the
// Lc field unconditionally; the host uses extended-length encoding
// (0x00 || hi || lo) for the same Lc, so any command whose
// wrapped data exceeded 255 bytes (cert installs, large STORE DATA
// chunks) failed MAC verification on the mock and got 6982 back.
//
// piv-provision's PUT CERTIFICATE step surfaced this — the cert
// PUT DATA APDU is ~280 bytes — and the fix makes the mock's MAC
// input layout track channel.SecureChannel.Wrap's: extended Lc
// when len(data) > 0xFF.
//
// The test exercises a >255-byte echo round-trip (INS 0xFD echoes
// data back) and asserts the wrapped command verifies and the
// response decrypts cleanly.
func TestCard_SecureMessaging_ExtendedLcMAC(t *testing.T) {
	ctx := context.Background()
	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	sess, err := scp11.Open(ctx, card.Transport(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// 300-byte payload — comfortably over the 255-byte threshold.
	// Echo (INS 0xFD) returns the same data; we just need any
	// command whose wrapped form crosses into extended-Lc territory.
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0, P2: 0,
		Data: payload, Le: 0,
	})
	if err != nil {
		t.Fatalf("transmit large payload: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("SW=%04X (extended-Lc MAC verification failed?)", resp.StatusWord())
	}
	if !bytes.Equal(resp.Data, payload) {
		t.Errorf("echoed data differs from sent (lengths sent=%d got=%d)", len(payload), len(resp.Data))
	}
}
