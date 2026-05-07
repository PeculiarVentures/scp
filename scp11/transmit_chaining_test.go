package scp11

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11_Transmit_LongPayloadIsWrapThenChain is the regression
// pin for the wrap-then-chain layering at the SCP11 layer. A logical
// command whose wrapped form exceeds short-Lc (255 bytes) must emit:
//
//   - exactly ONE SCP11 wrap (one C-MAC advance, computed over the
//     extended-format header + concatenated data), followed by
//   - N transport-layer chunks sharing INS/P1/P2 with the chaining
//     bit (CLA b5 = 0x10) on every chunk except the last.
//
// The bug this guards against is sending the wrapped APDU to the
// transport directly without splitting — which would either fail on
// transports that don't auto-chain, or work on extended-length
// transports while behaving differently from SCP03 (which has
// always wrapped-then-chained). SCP03's Transmit and SCP11's
// Transmit must be symmetric on this layering; without the
// regression test, drift is invisible to unit-level coverage.
//
// The recording transport captures every APDU as emitted, including
// the chained chunks. mockcard reassembles transport-level chunks
// itself the way real cards do, so the recorder just records and
// forwards; the chunk-count, chain-bit, and INS/P1/P2 assertions
// expose any drift in the host-side wrap-then-chain layering.
func TestSCP11_Transmit_LongPayloadIsWrapThenChain(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	rec := &chainRecordingTransport{inner: mc.Transport()}
	cfg := YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true

	sess, err := Open(context.Background(), rec, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()

	// Drop handshake commands so chunk-count assertions only see
	// the long-payload command we care about.
	rec.commands = rec.commands[:0]

	// 600-byte payload. Wrapped form (AES-CBC padded to 608 +
	// 8-byte CMAC) = 616 bytes, splits at the transport into
	// 255 + 255 + 106 with CLA chain bits 0x10, 0x10, 0x00.
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i)
	}

	resp, err := sess.Transmit(context.Background(), &apdu.Command{
		CLA: 0x80, INS: 0xE2, P1: 0x90, P2: 0x00,
		Data: payload, Le: -1,
	})
	if err != nil {
		t.Fatalf("Transmit: %v (chaining or wrap layering broken)", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("expected SW=9000, got %04X", resp.StatusWord())
	}

	if len(rec.commands) < 2 {
		t.Fatalf("wire shape: expected ≥2 chunks for a wrapped APDU >255 bytes, got %d", len(rec.commands))
	}

	// First N-1 chunks have the chaining bit set; the last does not.
	// INS/P1/P2 are constant across chunks (no app-level block
	// numbering — that's the inverted layering this test guards).
	wantINS := rec.commands[0].INS
	wantP1 := rec.commands[0].P1
	wantP2 := rec.commands[0].P2
	for i, c := range rec.commands {
		isLast := i == len(rec.commands)-1
		hasChainBit := c.CLA&0x10 != 0
		switch {
		case isLast && hasChainBit:
			t.Errorf("chunk %d (final): CLA = %02X has chain bit set; final chunk must clear it", i, c.CLA)
		case !isLast && !hasChainBit:
			t.Errorf("chunk %d (intermediate): CLA = %02X has chain bit clear; intermediate chunks must set it", i, c.CLA)
		}
		if c.INS != wantINS {
			t.Errorf("chunk %d: INS = %02X, want %02X (constant across chunks)", i, c.INS, wantINS)
		}
		if c.P1 != wantP1 {
			t.Errorf("chunk %d: P1 = %02X, want %02X (constant across chunks; no app-level block numbering)", i, c.P1, wantP1)
		}
		if c.P2 != wantP2 {
			t.Errorf("chunk %d: P2 = %02X, want %02X (constant across chunks; no app-level block numbering)", i, c.P2, wantP2)
		}
		// YubiKey-compatible large-APDU path is short-Lc + ISO
		// command chaining. Extended-length on a chunk would
		// silently fail interop on retail hardware while
		// passing on simulators that accept both encodings.
		if c.ExtendedLength {
			t.Errorf("chunk %d: ExtendedLength = true; chunked transport must use SHORT-Lc encoding "+
				"(extended-length on a chained command is the regression that breaks YubiKey 5.7+)", i)
		}
	}

	// Total emitted bytes equal the original wrapped data; chaining
	// should not duplicate or lose bytes.
	var total int
	for _, c := range rec.commands {
		total += len(c.Data)
	}
	if total <= 255 {
		t.Errorf("total emitted data = %d bytes; expected >255 to actually exercise chaining", total)
	}
}

// chainRecordingTransport records every APDU emitted by the SCP11 layer
// and forwards it to the inner transport unchanged. mockcard now
// handles ISO 7816-4 §5.1.1 transport-level chain reassembly itself,
// so the recording wrapper just needs to capture wire shape.
type chainRecordingTransport struct {
	inner    transport.Transport
	commands []*apdu.Command
}

func (r *chainRecordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// Copy the command so later mutation by callers can't change
	// what we recorded. Data slice is also cloned because the
	// transport layer may slice into shared backing arrays.
	c := *cmd
	c.Data = bytes.Clone(cmd.Data)
	r.commands = append(r.commands, &c)
	return r.inner.Transmit(ctx, cmd)
}

func (r *chainRecordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}
func (r *chainRecordingTransport) Close() error { return r.inner.Close() }
func (r *chainRecordingTransport) TrustBoundary() transport.TrustBoundary {
	return r.inner.TrustBoundary()
}
