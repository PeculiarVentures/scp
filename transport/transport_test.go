package transport

import (
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// chunkingTransport is a synthetic transport that always replies with
// "still more data" (61 xx) to drive TransmitCollectAll into the
// GET RESPONSE loop. It records how many calls have been made so the
// test can verify the iteration cap fires as expected.
type chunkingTransport struct {
	calls    int
	chunkLen int
}

func (c *chunkingTransport) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	c.calls++
	data := make([]byte, c.chunkLen)
	return &apdu.Response{Data: data, SW1: 0x61, SW2: 0xFF}, nil
}

func (c *chunkingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

func (c *chunkingTransport) Close() error { return nil }

// TestTransmitCollectAll_IterationCap confirms a card that keeps signaling
// "more data" forever cannot loop the host indefinitely.
func TestTransmitCollectAll_IterationCap(t *testing.T) {
	c := &chunkingTransport{chunkLen: 0}
	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x00}

	_, err := TransmitCollectAll(context.Background(), c, cmd)
	if err == nil {
		t.Fatal("expected error when card signals more data forever")
	}
	if !strings.Contains(err.Error(), "iterations") {
		t.Errorf("expected iteration-cap error, got: %v", err)
	}
	// The cap should fire by MaxGetResponseIterations + 1 calls (1 initial
	// + iterations of GET RESPONSE).
	if c.calls > MaxGetResponseIterations+2 {
		t.Errorf("transport invoked %d times; expected ~%d", c.calls, MaxGetResponseIterations+1)
	}
}

// TestTransmitCollectAll_ByteCap confirms a card that keeps returning
// large chunks cannot exhaust host memory via accumulated response data.
func TestTransmitCollectAll_ByteCap(t *testing.T) {
	// 8 KiB chunks; 1 MiB cap means ~128 chunks should suffice to trip it.
	c := &chunkingTransport{chunkLen: 8 * 1024}
	cmd := &apdu.Command{CLA: 0x00, INS: 0xCA, P1: 0x00, P2: 0x00}

	_, err := TransmitCollectAll(context.Background(), c, cmd)
	if err == nil {
		t.Fatal("expected error when accumulated response exceeds byte cap")
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("expected byte-cap error, got: %v", err)
	}
}

func (c *chunkingTransport) TrustBoundary() TrustBoundary { return TrustBoundaryUnknown }
