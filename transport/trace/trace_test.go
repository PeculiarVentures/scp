package trace_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/transport/trace"
)

// fixedChallenge is the host challenge we pin into both the recording
// session and the replay session. Without this pinning, the second
// SCP03 open would generate a fresh random challenge and the
// replayer would mismatch on INITIALIZE UPDATE. See DESIGN.md
// "the determinism problem" — strict matching plus pinned randomness
// is the contract.
var fixedChallenge = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// TestRecordReplay_SCP03_Echo drives an SCP03 open + one wrapped
// command (echo, INS=0xFD on the mock) against scp03.MockCard,
// captures it through the recorder, then replays the trace against
// the same library code and verifies the second flow succeeds.
//
// This is the round-trip test: it proves the recorder writes
// something the replayer can faithfully serve back, and that the
// SCP03 stack is happy with both ends.
func TestRecordReplay_SCP03_Echo(t *testing.T) {
	ctx := context.Background()

	// 1. Record a session against an in-memory mock card.
	card := scp03.NewMockCard(scp03.DefaultKeys)
	rec := trace.NewRecorder(card.Transport(), trace.RecorderConfig{
		Profile: "mockcard",
		Notes:   "SCP03 default-keys open + echo",
		Determinism: trace.Determinism{
			HostChallenge: fixedChallenge,
		},
	})

	sess, err := scp03.Open(ctx, rec, &scp03.Config{
		Keys:          scp03.DefaultKeys,
		HostChallenge: fixedChallenge,
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("record: scp03.Open: %v", err)
	}

	echoData := []byte("hello-from-trace")
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: echoData, Le: -1,
	})
	if err != nil {
		t.Fatalf("record: transmit echo: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("record: echo returned SW=%04X", resp.StatusWord())
	}
	if !bytes.Equal(resp.Data, echoData) {
		t.Fatalf("record: echo got %q, want %q", resp.Data, echoData)
	}
	sess.Close()

	var buf bytes.Buffer
	if err := rec.Flush(&buf); err != nil {
		t.Fatalf("record: flush: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("record: flushed empty trace")
	}
	t.Logf("recorded trace (%d bytes):\n%s", buf.Len(), buf.String())

	// 2. Replay against a fresh library state.
	rep, err := trace.NewReplayerFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("replay: parse: %v", err)
	}
	if !bytes.Equal(rep.HostChallenge(), fixedChallenge) {
		t.Errorf("replay: host challenge: got %x, want %x", rep.HostChallenge(), fixedChallenge)
	}

	sess2, err := scp03.Open(ctx, rep, &scp03.Config{
		Keys:          scp03.DefaultKeys,
		HostChallenge: rep.HostChallenge(),
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("replay: scp03.Open: %v", err)
	}

	resp2, err := sess2.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: echoData, Le: -1,
	})
	if err != nil {
		t.Fatalf("replay: transmit echo: %v", err)
	}
	if !bytes.Equal(resp2.Data, echoData) {
		t.Fatalf("replay: echo got %q, want %q", resp2.Data, echoData)
	}
	sess2.Close()

	if err := rep.Close(); err != nil {
		t.Errorf("replay: unconsumed exchanges: %v", err)
	}
}

// TestReplay_Mismatch verifies a divergent call produces a structured
// MismatchError with trace position and annotation. This is the
// failure diagnostic CI relies on; if it's noisy or imprecise,
// nobody trusts the trace tests.
func TestReplay_Mismatch(t *testing.T) {
	ctx := context.Background()

	trc := trace.File{
		Schema: trace.SchemaVersion,
		Exchanges: []trace.Exchange{{
			I:           0,
			Kind:        trace.KindTransmit,
			CommandHex:  mustHex(t, "00a4040008a000000151000000"),
			ResponseHex: mustHex(t, "9000"),
			Annotation:  "SELECT ISD",
		}},
	}
	data := mustJSON(t, &trc)

	rep, err := trace.NewReplayerFromBytes(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	wrongCmd := &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00},
		Le:   -1,
	}
	_, err = rep.Transmit(ctx, wrongCmd)

	var mm *trace.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if mm.Index != 0 {
		t.Errorf("Index: got %d, want 0", mm.Index)
	}
	if mm.Annotation != "SELECT ISD" {
		t.Errorf("Annotation: got %q, want %q", mm.Annotation, "SELECT ISD")
	}
}

func TestReplay_KindMismatch(t *testing.T) {
	ctx := context.Background()

	trc := trace.File{
		Schema: trace.SchemaVersion,
		Exchanges: []trace.Exchange{{
			I:           0,
			Kind:        trace.KindTransmitRaw,
			CommandHex:  mustHex(t, "00a4040000"),
			ResponseHex: mustHex(t, "9000"),
		}},
	}
	rep, err := trace.NewReplayerFromBytes(mustJSON(t, &trc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Recorded as TransmitRaw; called as Transmit — kind mismatch.
	_, err = rep.Transmit(ctx, &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Le: -1,
	})
	var mm *trace.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if mm.ExpectedKind != trace.KindTransmitRaw || mm.ActualKind != trace.KindTransmit {
		t.Errorf("kinds: expected=%s actual=%s", mm.ExpectedKind, mm.ActualKind)
	}
}

func TestReplay_Exhausted(t *testing.T) {
	rep, err := trace.NewReplayerFromBytes(mustJSON(t, &trace.File{Schema: trace.SchemaVersion}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = rep.TransmitRaw(context.Background(), []byte{0x00, 0xA4, 0x04, 0x00, 0x00})
	if !errors.Is(err, trace.ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
}

func TestReplay_Unconsumed(t *testing.T) {
	rep, err := trace.NewReplayerFromBytes(mustJSON(t, &trace.File{
		Schema: trace.SchemaVersion,
		Exchanges: []trace.Exchange{{
			I:           0,
			Kind:        trace.KindTransmitRaw,
			CommandHex:  mustHex(t, "00a4040000"),
			ResponseHex: mustHex(t, "9000"),
		}},
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var unc *trace.ErrUnconsumed
	if !errors.As(rep.Close(), &unc) {
		t.Fatalf("expected *ErrUnconsumed, got %v", rep.Close())
	}
	if unc.Consumed != 0 || unc.Total != 1 {
		t.Errorf("ErrUnconsumed: %+v", unc)
	}
}

// TestSchemaVersion_Rejected verifies a trace with the wrong schema
// version is rejected with a clear error rather than parsed loosely.
// We do not silently accept multiple schema versions.
func TestSchemaVersion_Rejected(t *testing.T) {
	bad := []byte(`{"schema":"scp-trace/v0","captured_at":"2026-01-01T00:00:00Z","determinism":{},"exchanges":[]}`)
	_, err := trace.NewReplayerFromBytes(bad)
	if err == nil {
		t.Fatal("expected schema version error")
	}
}

// Compile-time assertions: keep transport import live and assert
// type conformance without runtime cost.
var _ transport.Transport = (*trace.Recorder)(nil)
var _ transport.Transport = (*trace.Replayer)(nil)

// --- helpers ---

func mustHex(t *testing.T, s string) trace.HexBytes {
	t.Helper()
	var hb trace.HexBytes
	if err := hb.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return hb
}

func mustJSON(t *testing.T, f *trace.File) []byte {
	t.Helper()
	if f.Schema == "" {
		f.Schema = trace.SchemaVersion
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// TestRecorder_CaptureCRD confirms CaptureCRD probes the inner
// transport, parses the response, and stores the result in the trace
// header — without showing up as a recorded exchange. The probe is
// metadata, not something the test code did, so it doesn't belong
// in the exchanges list.
func TestRecorder_CaptureCRD(t *testing.T) {
	ctx := context.Background()

	// Synthetic CRD: GP 2.3.1, SCP03 i=0x65. Hand-assembled per
	// GP §H.2: outer 66 LL, inner 73 LL list.
	//
	// Children of the 0x73 list:
	//   06 07 ..  GP RID marker  (9 bytes)
	//   60 0C ..  GP 2.3.1       (14 bytes)
	//   64 0B ..  SCP03 i=0x65   (13 bytes)
	// Total: 36 bytes -> list header 73 24, outer 66 26.
	crd := []byte{
		0x66, 0x26,
		0x73, 0x24,
		0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
		0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
		0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x65,
	}

	inner := &captureCRDTransport{crdResponse: crd}
	rec := trace.NewRecorder(inner, trace.RecorderConfig{Profile: "test"})

	// One normal exchange first, so we can verify it remains at
	// index 0 and the CRD probe didn't push it down.
	if _, err := rec.Transmit(ctx, &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00, Le: -1,
	}); err != nil {
		t.Fatalf("Transmit pre-CRD: %v", err)
	}

	if err := rec.CaptureCRD(ctx); err != nil {
		t.Fatalf("CaptureCRD: %v", err)
	}

	snap := rec.Snapshot()

	if snap.CardInfo == nil {
		t.Fatal("CardInfo is nil; CaptureCRD did not store")
	}
	if snap.CardInfo.SCPVersion != 0x03 {
		t.Errorf("CardInfo.SCPVersion = 0x%02X, want 0x03", snap.CardInfo.SCPVersion)
	}
	if snap.CardInfo.SCPParameter != 0x65 {
		t.Errorf("CardInfo.SCPParameter = 0x%02X, want 0x65", snap.CardInfo.SCPParameter)
	}

	// Probe must NOT have polluted the exchanges list.
	if len(snap.Exchanges) != 1 {
		t.Errorf("Exchanges = %d, want 1 (CaptureCRD must not record)", len(snap.Exchanges))
	}
	if len(snap.Exchanges) > 0 && snap.Exchanges[0].INS[0] != 0xA4 {
		t.Errorf("first exchange INS = 0x%02X, want 0xA4 (SELECT)", snap.Exchanges[0].INS[0])
	}

	// Verify the JSON round-trip carries CardInfo.
	var buf bytes.Buffer
	if err := rec.Flush(&buf); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"card_info"`)) {
		t.Error("flushed JSON does not contain card_info field")
	}
	if _, err := trace.NewReplayerFromBytes(buf.Bytes()); err != nil {
		t.Errorf("flushed JSON does not parse back: %v", err)
	}
}

// captureCRDTransport returns the configured CRD bytes when it sees
// GET DATA tag 0x66, and a benign 9000 for everything else.
type captureCRDTransport struct {
	crdResponse []byte
}

func (c *captureCRDTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS == 0xCA && cmd.P1 == 0x00 && cmd.P2 == 0x66 {
		return &apdu.Response{Data: c.crdResponse, SW1: 0x90, SW2: 0x00}, nil
	}
	return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
}

func (c *captureCRDTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return []byte{0x90, 0x00}, nil
}

func (c *captureCRDTransport) Close() error { return nil }
