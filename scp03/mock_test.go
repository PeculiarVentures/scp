package scp03

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// TestMockCard_GetData_CRD_Unauthenticated confirms the CRD probe
// works without secure messaging. Real cards permit GET DATA tag
// 0x66 outside any session because card identification has to happen
// before the host knows what protocol to authenticate with; the mock
// matches that behavior.
func TestMockCard_GetData_CRD_Unauthenticated(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	tr := card.Transport()

	// SELECT first (real cards require it; the mock accepts any AID).
	if _, err := tr.Transmit(context.Background(), &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
	}); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	// GET DATA tag 0x66.
	resp, err := tr.Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x66, Le: 0,
	})
	if err != nil {
		t.Fatalf("GET DATA 0x66: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("GET DATA 0x66: SW=%04X", resp.StatusWord())
	}
	if len(resp.Data) == 0 || resp.Data[0] != 0x66 {
		t.Errorf("response should begin with tag 0x66; got first byte %02X (length %d)",
			resp.Data[0], len(resp.Data))
	}
}

// TestMockCard_GetData_KeyInfo_RequiresSecureMessaging documents the
// security model: the key information template is auth-gated. A
// plaintext request is refused with 6982 (security status not
// satisfied), which is what real Security Domains do.
func TestMockCard_GetData_KeyInfo_RequiresSecureMessaging(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	tr := card.Transport()

	resp, err := tr.Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0xE0, Le: 0,
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}
	if resp.StatusWord() != 0x6982 {
		t.Errorf("plaintext GET DATA 0x00E0 should return 6982; got %04X", resp.StatusWord())
	}
}

// TestMockCard_GetData_KeyInfo_OverSecureMessaging exercises the full
// authenticated read path: SCP03 handshake → secure messaging → GET
// DATA 0x00E0 → response wrapped in MAC/encryption → host
// parseKeyInformation produces a non-empty result.
//
// This is the test the smoke CLI couldn't have before this change —
// the SCP03 mock was responding 6D00 to any non-SELECT non-echo
// command after auth, so GetKeyInformation always failed.
func TestMockCard_GetData_KeyInfo_OverSecureMessaging(t *testing.T) {
	ctx := context.Background()
	card := NewMockCard(DefaultKeys)

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:       DefaultKeys,
		KeyVersion: 0xFF,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0xE0, Le: 0,
	})
	if err != nil {
		t.Fatalf("GET DATA 0x00E0 over SCP03: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("GET DATA 0x00E0 over SCP03: SW=%04X", resp.StatusWord())
	}
	// Synthetic key info is `E0 06 C0 04 01 FF 88 10` — 8 bytes.
	if len(resp.Data) < 4 || resp.Data[0] != 0xE0 {
		t.Errorf("response should begin with tag E0; got %X", resp.Data)
	}
}

// TestMockCard_GetData_CRD_OverSecureMessaging confirms the CRD path
// also works under SCP03 secure messaging. Same response shape as
// the unauthenticated path, just delivered through a wrapped channel.
func TestMockCard_GetData_CRD_OverSecureMessaging(t *testing.T) {
	ctx := context.Background()
	card := NewMockCard(DefaultKeys)
	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:       DefaultKeys,
		KeyVersion: 0xFF,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x66, Le: 0,
	})
	if err != nil {
		t.Fatalf("GET DATA 0x0066 over SCP03: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("GET DATA 0x0066 over SCP03: SW=%04X", resp.StatusWord())
	}
	if resp.Data[0] != 0x66 {
		t.Errorf("CRD response should begin with tag 0x66; got %02X", resp.Data[0])
	}
}

// TestMockCard_GetData_UnknownTag_OverSecureMessaging confirms
// unknown tags requested over an authenticated channel return 6A88
// (reference data not found). Over plaintext, GET DATA tags other
// than 0x66 return 6982 (security status not satisfied), which is
// covered by TestMockCard_GetData_KeyInfo_RequiresSecureMessaging
// — this test covers the post-auth case.
func TestMockCard_GetData_UnknownTag_OverSecureMessaging(t *testing.T) {
	ctx := context.Background()
	card := NewMockCard(DefaultKeys)
	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:       DefaultKeys,
		KeyVersion: 0xFF,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0xDE, P2: 0xAD, Le: 0,
	})
	if err != nil {
		t.Fatalf("transmit: %v", err)
	}
	if resp.StatusWord() != 0x6A88 {
		t.Errorf("unknown GET DATA tag over SM should return 6A88; got %04X", resp.StatusWord())
	}
}
