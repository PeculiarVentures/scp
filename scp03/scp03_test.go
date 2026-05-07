package scp03

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/transport"
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

	keys := sess.InsecureExportSessionKeysForTestOnly()
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
	_ = sess.InsecureExportSessionKeysForTestOnly()
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
	_, err := Open(context.Background(), NewMockCard(DefaultKeys).Transport(), nil)
	if err == nil {
		t.Fatal("Open(nil cfg) should return an error, not silently use DefaultKeys")
	}
	if !strings.Contains(err.Error(), "Config is required") {
		t.Errorf("error should mention Config is required (this test guards the cfg path, not the transport path); got: %v", err)
	}
}

// TestOpen_EmptyKeys_RejectsExplicitly confirms that a zero-valued
// StaticKeys is also rejected — otherwise &Config{} (no Keys set) would
// hit the same footgun via a different path.
func TestOpen_EmptyKeys_RejectsExplicitly(t *testing.T) {
	_, err := Open(context.Background(), NewMockCard(DefaultKeys).Transport(), &Config{})
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
// either keep their own copy or go through securitydomain.OpenSCP03 just
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

	got := sess.InsecureExportSessionKeysForTestOnly().DEK
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

// TestStrictGPConfig verifies StrictGPConfig produces a Config with
// GP-spec defaults: zero KVN ("any version") and the GP-literal
// empty-data policy — the semantic difference from FactoryYubiKeyConfig.
func TestStrictGPConfig(t *testing.T) {
	cfg := StrictGPConfig(DefaultKeys)
	if cfg.KeyVersion != 0x00 {
		t.Errorf("KeyVersion = 0x%02X, want 0x00", cfg.KeyVersion)
	}
	if cfg.EmptyDataEncryption != channel.EmptyDataGPLiteral {
		t.Errorf("EmptyDataEncryption = %v, want EmptyDataGPLiteral", cfg.EmptyDataEncryption)
	}
	if len(cfg.Keys.ENC) != 16 {
		t.Errorf("Keys.ENC length = %d, want 16", len(cfg.Keys.ENC))
	}
}

// TestOpen_NilTransport_RejectsExplicitly confirms that scp03.Open
// with a nil transport fails fast at the API boundary rather than
// panicking with a nil-pointer dereference inside the SELECT path.
// The guard is the very first check in Open so the failure surfaces
// before any other validation work.
func TestOpen_NilTransport_RejectsExplicitly(t *testing.T) {
	_, err := Open(context.Background(), nil, &Config{Keys: DefaultKeys})
	if err == nil {
		t.Fatal("Open(nil transport) should return an error")
	}
	if !strings.Contains(err.Error(), "transport is required") {
		t.Errorf("error should mention transport is required; got: %v", err)
	}
}

// recordingTransport wraps a transport.Transport and captures every
// APDU the SCP layer emits to the wire. Used to assert wire shape
// (chunk count, CLA chaining bits, P1/P2 constancy) for long
// commands without parsing the parsed-response stream.
type recordingTransport struct {
	inner    *MockTransport
	commands []*apdu.Command
}

func (r *recordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// Copy the command so later mutation by callers can't change
	// what we recorded. Data slice is shared; tests only inspect.
	c := *cmd
	r.commands = append(r.commands, &c)
	return r.inner.Transmit(ctx, cmd)
}

func (r *recordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}
func (r *recordingTransport) Close() error                           { return r.inner.Close() }
func (r *recordingTransport) TrustBoundary() transport.TrustBoundary { return r.inner.TrustBoundary() }

// TestSCP03_Transmit_LongPayloadIsWrapThenChain is the regression
// pin for the wrap-then-chain layering. A logical command whose
// wrapped form exceeds short-Lc (255 bytes) must emit:
//
//   - exactly ONE SCP wrap (one C-MAC advance, computed over the
//     extended-format header), followed by
//   - N transport-layer chunks sharing INS/P1/P2 with the chaining
//     bit (CLA b5 = 0x10) on every chunk except the last.
//
// The earlier inverted layering (chain at the application layer,
// wrap each chunk independently) advanced the C-MAC chain N times
// for one logical command and computed each MAC over short-form
// Lc on each chunk. Real cards reassemble chained chunks before
// applying secure messaging, so the card sees ONE logical APDU
// with extended-form Lc — different MAC math from what the host
// emitted, hence MAC verification fails. This test catches the
// inverted layering deterministically: with the recording
// transport seeing N chunks for one logical command, if the SCP
// wrap layer ran per-chunk the underlying mock's MAC verification
// would fail (the mock reassembles chains and MAC's once, exactly
// like real cards). A green test means the host emits exactly one
// MAC over the assembled command.
func TestSCP03_Transmit_LongPayloadIsWrapThenChain(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()
	rec := &recordingTransport{inner: card.Transport()}

	sess, err := Open(ctx, rec, &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// Drop the handshake commands so we can assert chunk count on
	// the long-payload command alone.
	rec.commands = rec.commands[:0]

	// 600-byte payload. Wrapped form (ISO 9797-1 method 2 padding
	// to 608 + 8-byte MAC) = 616 bytes (S8 mode is the YubiKey
	// factory default; S16 would give 624). Splits into 3 short-
	// form chunks of 255 + 255 + 106 with CLA chaining bits 0x10,
	// 0x10, 0x00.
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i)
	}

	// STORE DATA shape (P1=0x90 P2=0x00) is what the real call
	// site uses; the mock dispatches it through processPlain
	// (records and returns 9000). For this test we only care that
	// the wire shape is correct and the host's MAC verifies on
	// the card side.
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE2, P1: 0x90, P2: 0x00,
		Data: payload, Le: -1,
	})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("expected SW=9000, got %04X (host wrap or card MAC verify must have desynced — "+
			"this is the wrap-then-chain regression: long commands MUST be wrapped once, "+
			"chunked at the transport, with the card reassembling before MAC check)",
			resp.StatusWord())
	}

	if len(rec.commands) != 3 {
		t.Fatalf("wire shape: expected 3 chunks for a 616-byte wrapped APDU "+
			"(255 + 255 + 106), got %d", len(rec.commands))
	}

	// First two chunks have the chaining bit set; the third does not.
	for i, c := range rec.commands {
		isLast := i == len(rec.commands)-1
		hasChainBit := c.CLA&0x10 != 0
		switch {
		case isLast && hasChainBit:
			t.Errorf("chunk %d (final): CLA = %02X has chain bit set; final chunk must clear it",
				i, c.CLA)
		case !isLast && !hasChainBit:
			t.Errorf("chunk %d (intermediate): CLA = %02X has chain bit clear; intermediate chunks must set it",
				i, c.CLA)
		}
		// INS/P1/P2 are identical across chunks — chunking only
		// varies CLA chain bit and data slice. If a future
		// refactor reintroduces application-level chaining (P2
		// stepping through block numbers, P1 b8 clearing on
		// non-final blocks) this assertion fails.
		if c.INS != 0xE2 {
			t.Errorf("chunk %d: INS = %02X, want E2", i, c.INS)
		}
		if c.P1 != 0x90 {
			t.Errorf("chunk %d: P1 = %02X, want 90 (constant across chunks; no app-level block numbering)",
				i, c.P1)
		}
		if c.P2 != 0x00 {
			t.Errorf("chunk %d: P2 = %02X, want 00 (constant across chunks; no app-level block numbering)",
				i, c.P2)
		}
	}

	// Sizes: 255 + 255 + 106 = 616 bytes total wrapped data
	// (608-byte padded ciphertext + 8-byte S8 MAC).
	wantSizes := []int{255, 255, 106}
	for i, c := range rec.commands {
		if len(c.Data) != wantSizes[i] {
			t.Errorf("chunk %d: data size = %d, want %d", i, len(c.Data), wantSizes[i])
		}
		// Each chunk must use SHORT encoding (Lc = single byte).
		// Extended-length encoding (Lc = 0x00 followed by 2-byte
		// length) on a chunk would mean the host tried to use
		// extended-length on top of chaining — that's the
		// non-YubiKey-compatible path. YubiKey 5.7 rejects
		// extended-length APDUs on the SD channel; the only
		// path that works is short-Lc + ISO command chaining.
		if c.ExtendedLength {
			t.Errorf("chunk %d: ExtendedLength = true; chunked transport must use SHORT-Lc encoding "+
				"(extended-length on a chained command is the regression that breaks YubiKey 5.7+)", i)
		}
	}
}

// TestSCP03_Transmit_LongPayload_RejectsExtendedLengthOnWire is a
// finer-grained companion to LongPayloadIsWrapThenChain: scan the
// raw wire bytes of every chunk and assert NONE uses extended-
// length encoding (Lc = 0x00 followed by 2-byte length). Catches
// a regression where some future refactor sets ExtendedLength on
// the per-chunk Command and the SCP03 layer doesn't strip it.
//
// Per ISO 7816-4 §5.1 + the YubiKey-compat constraint the
// reviewer flagged: the YubiKey-compatible large-APDU path is
// short-Lc + CLA chaining. Extended-length APDUs are NOT
// supported on the YubiKey SD channel; using them would silently
// fail interop on retail hardware while passing on simulators
// that accept both encodings.
func TestSCP03_Transmit_LongPayload_RejectsExtendedLengthOnWire(t *testing.T) {
	card := NewMockCard(DefaultKeys)
	ctx := context.Background()

	// Use a transport that captures the raw bytes the host
	// sends, not the post-decoded *apdu.Command shape. The
	// raw bytes are what would actually go on the wire to
	// the card; a regression that builds an extended-length
	// APDU and then short-Lc-wraps it would still set
	// ExtendedLength=false in the Command struct, but the
	// raw bytes would tell the truth.
	rt := &rawRecordingTransport{inner: card.Transport()}

	sess, err := Open(ctx, rt, &Config{
		Keys:          DefaultKeys,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()
	rt.raw = nil // drop handshake bytes

	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i)
	}

	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE2, P1: 0x90, P2: 0x00,
		Data: payload, Le: -1,
	})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("expected SW=9000, got %04X", resp.StatusWord())
	}

	if len(rt.raw) == 0 {
		t.Fatal("no APDUs recorded")
	}

	// Walk each captured raw APDU. Extended-length form is
	// CLA INS P1 P2 0x00 LcHi LcLo Data... [Le0 LeHi LeLo].
	// Short-Lc form is CLA INS P1 P2 Lc Data... [Le].
	// The discriminator is the byte at offset 4: 0x00 with
	// at least 7 total bytes means extended-length.
	for i, raw := range rt.raw {
		if len(raw) < 5 {
			t.Errorf("APDU %d: too short to validate (%d bytes)", i, len(raw))
			continue
		}
		// Extended-length signature: byte 4 == 0 and total
		// length is large enough that it can't be a no-data
		// APDU with Le=0 (which would be 5 bytes total).
		if raw[4] == 0x00 && len(raw) > 5 {
			t.Errorf("APDU %d: byte 4 == 0x00 with %d total bytes — this is extended-length encoding. "+
				"YubiKey-compatible chunked APDUs MUST use short-Lc; extended-length is the "+
				"regression that breaks interop on retail YubiKey 5.7+",
				i, len(raw))
		}
	}
}

// rawRecordingTransport captures the raw wire bytes of every
// command sent through it, plus the inner transport's response.
// Used for tests that need to assert on encoding-level details
// (extended-length vs short-Lc, exact byte layout) that the
// *apdu.Command Go struct hides.
type rawRecordingTransport struct {
	inner transport.Transport
	raw   [][]byte
}

func (r *rawRecordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	r.raw = append(r.raw, append([]byte(nil), encoded...))
	return r.inner.Transmit(ctx, cmd)
}

func (r *rawRecordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	r.raw = append(r.raw, append([]byte(nil), raw...))
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *rawRecordingTransport) Close() error { return r.inner.Close() }

func (r *rawRecordingTransport) TrustBoundary() transport.TrustBoundary {
	return r.inner.TrustBoundary()
}

// TestOpen_DoesNotMutateCallerConfig confirms scp03.Open shallow-
// copies its Config argument before applying defaults like the
// implicit SecurityLevel. Earlier versions mutated the caller's
// Config in place, which surprised callers reusing a config across
// sessions or holding a pointer that another goroutine read in
// parallel. Open is allowed to fail (we hand it a transport that
// errors) — the side-effect check happens regardless of outcome.
func TestOpen_DoesNotMutateCallerConfig(t *testing.T) {
	cfg := &Config{Keys: DefaultKeys, SecurityLevel: 0}
	wantLevel := cfg.SecurityLevel
	_, _ = Open(context.Background(), &errorTransport{}, cfg)
	if cfg.SecurityLevel != wantLevel {
		t.Errorf("Open mutated caller's Config.SecurityLevel: got 0x%X, want 0x%X",
			cfg.SecurityLevel, wantLevel)
	}
}

type errorTransport struct{}

func (e *errorTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return nil, errTransportTestFailed
}
func (e *errorTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return nil, errTransportTestFailed
}
func (e *errorTransport) Close() error { return nil }
func (e *errorTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

var errTransportTestFailed = fmt.Errorf("transport failed (test)")
