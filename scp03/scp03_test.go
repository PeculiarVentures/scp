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

// ============================================================
// Regression: parseInitUpdateResponse requires 29 bytes minimum.
//
// Before the fix, the length check was `< 28` but the code slices
// data[21:29] which requires 29 bytes. A 28-byte input would panic.
// ============================================================

func TestParseInitUpdateResponse_MinLength(t *testing.T) {
	// 28 bytes should be rejected (data[21:29] needs 29).
	data28 := make([]byte, 28)
	data28[11] = 0x03 // SCP ID
	_, err := parseInitUpdateResponse(data28)
	if err == nil {
		t.Fatal("28-byte input should be rejected (need 29+)")
	}

	// 29 bytes should be accepted.
	data29 := make([]byte, 29)
	data29[11] = 0x03 // SCP ID
	r, err := parseInitUpdateResponse(data29)
	if err != nil {
		t.Fatalf("29-byte input should be accepted: %v", err)
	}
	if len(r.cardCryptogram) != 8 {
		t.Errorf("cardCryptogram length: got %d, want 8", len(r.cardCryptogram))
	}

	// 32 bytes should include the optional sequence counter.
	data32 := make([]byte, 32)
	data32[11] = 0x03
	r, err = parseInitUpdateResponse(data32)
	if err != nil {
		t.Fatalf("32-byte input should be accepted: %v", err)
	}
	if len(r.sequenceCounter) != 3 {
		t.Errorf("sequenceCounter length: got %d, want 3", len(r.sequenceCounter))
	}
}

// TestOpen_NilConfig_RejectsExplicitly confirms that scp03.Open(ctx, t, nil)
// returns an error rather than silently using DefaultKeys (the well-known
// 0x40..0x4F factory keys). Earlier behavior was to fall through to
// DefaultKeys when cfg was nil, which made it possible for production code
// to open a "secure" channel with publicly-known keys without ever naming
// them. Now the caller has to type DefaultKeys themselves.
func TestOpen_NilConfig_RejectsExplicitly(t *testing.T) {
	_, err := Open(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("Open(nil cfg) should return an error, not silently use DefaultKeys")
	}
}

// TestOpen_EmptyKeys_RejectsExplicitly confirms that a zero-valued
// StaticKeys is also rejected — otherwise &Config{} (no Keys set) would
// hit the same footgun via a different path.
func TestOpen_EmptyKeys_RejectsExplicitly(t *testing.T) {
	_, err := Open(context.Background(), nil, &Config{})
	if err == nil {
		t.Fatal("Open with empty Keys should return an error")
	}
}

// TestOpen_ExplicitDefaultKeys_StillWorks confirms that callers who
// genuinely want the test keys (factory-fresh card, lab work) can still
// get them by typing scp03.DefaultKeys — the act of typing is the
// consent. This is the intended escape hatch.
func TestOpen_ExplicitDefaultKeys_StillWorks(t *testing.T) {
	// Drive Open against a real mock card configured with DefaultKeys
	// so we exercise the full handshake. Earlier the only test for
	// DefaultKeys was the implicit nil-config fallback; that fallback
	// is now gone, so we explicitly cover the supported lab-use path.
	card := NewMockCard(DefaultKeys)
	sess, err := Open(context.Background(), card.Transport(), &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open with explicit DefaultKeys should succeed: %v", err)
	}
	defer sess.Close()
}

// TestSessionKeys_PreservesStaticDEK confirms that the static DEK
// from the caller's StaticKeys flows through to SessionKeys().DEK as
// a clone, not nil and not the same backing array.
//
// Earlier this was nil with a comment "SCP03 secure messaging does
// not derive a session DEK." That's true for the secure messaging
// itself — DEK is not used by Wrap/Unwrap. But operations layered on
// top, like PUT KEY, need the static DEK to wrap fresh key material
// before import. Returning nil from SessionKeys() forced callers to
// either keep their own copy or go through securitydomain.Open just
// to access the DEK. Yubico's yubikit preserves it through derive()
// for the same reason.
func TestSessionKeys_PreservesStaticDEK(t *testing.T) {
	dek := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	keys := StaticKeys{
		ENC: DefaultKeys.ENC,
		MAC: DefaultKeys.MAC,
		DEK: dek,
	}
	card := NewMockCard(keys)
	sess, err := Open(context.Background(), card.Transport(), &Config{
		Keys:          keys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	got := sess.SessionKeys().DEK
	if got == nil {
		t.Fatal("SessionKeys().DEK is nil; expected a clone of the static DEK")
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("SessionKeys().DEK = %X, want %X", got, dek)
	}

	// Confirm it's a defensive copy: mutating the returned slice
	// must not mutate the caller's original DEK.
	got[0] ^= 0xFF
	if dek[0] != 0xAA {
		t.Errorf("mutating SessionKeys().DEK affected caller's static DEK: %X", dek)
	}
}
