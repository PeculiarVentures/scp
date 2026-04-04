package scp03

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
)

func TestSCP03_Handshake(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	if sess.Protocol() != "SCP03" {
		t.Errorf("Protocol: got %q, want %q", sess.Protocol(), "SCP03")
	}

	keys := sess.SessionKeys()
	if len(keys.SENC) != 16 {
		t.Errorf("S-ENC length: got %d, want 16", len(keys.SENC))
	}

	t.Logf("SCP03 session established")
	t.Logf("  S-ENC:  %X", keys.SENC)
	t.Logf("  S-MAC:  %X", keys.SMAC)
	t.Logf("  S-RMAC: %X", keys.SRMAC)
}

func TestSCP03_EchoCommand(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	testData := []byte("Hello from SCP03!")
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: testData, Le: -1,
	})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("echo failed: SW=%04X", resp.StatusWord())
	}
	if !bytes.Equal(resp.Data, testData) {
		t.Errorf("echo mismatch:\n  got:  %X\n  want: %X", resp.Data, testData)
	}

	t.Logf("Echo round-trip: %d bytes through SCP03", len(testData))
}

func TestSCP03_MultipleCommands(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	for i := 0; i < 10; i++ {
		data := []byte{byte(i), byte(i * 3), byte(i * 7)}
		resp, err := sess.Transmit(ctx, &apdu.Command{
			CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
			Data: data, Le: -1,
		})
		if err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		if !bytes.Equal(resp.Data, data) {
			t.Fatalf("command %d: echo mismatch", i)
		}
	}

	t.Log("10 sequential SCP03 commands completed")
}

func TestSCP03_WrongKeys(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	wrongKeys := StaticKeys{
		ENC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		MAC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		DEK: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	}

	_, err := Open(ctx, card.Transport(), &Config{
		Keys:          wrongKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err == nil {
		t.Fatal("expected error with wrong keys, got nil")
	}

	t.Logf("Wrong keys correctly rejected: %v", err)
}

func TestSCP03_EmptyPayload(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// Empty payload
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Le: -1,
	})
	if err != nil {
		t.Fatalf("empty command: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("empty command failed: SW=%04X", resp.StatusWord())
	}

	// Followed by data — counters must stay in sync
	data := []byte{0xCA, 0xFE}
	resp, err = sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: data, Le: -1,
	})
	if err != nil {
		t.Fatalf("data after empty: %v", err)
	}
	if !bytes.Equal(resp.Data, data) {
		t.Fatalf("echo mismatch after empty payload")
	}

	t.Log("SCP03 empty + data sequence completed")
}

func TestSCP03_SessionInterface(t *testing.T) {
	// Verify that *Session satisfies the scp.Session interface
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	sess, err := Open(ctx, card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// These calls verify the interface methods exist and work
	_ = sess.Protocol()
	_ = sess.SessionKeys()
	sess.Close()
}
