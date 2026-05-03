package pcsc

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/transport"
)

// Compile-time check that *Transport satisfies the SCP transport
// interface. Hardware-free — runs in regular CI.
var _ transport.Transport = (*Transport)(nil)

// TestSentinelErrors locks in that the sentinel errors are exported
// and distinct from each other and from a generic non-pcsc error.
// Hardware-free.
func TestSentinelErrors(t *testing.T) {
	if errors.Is(ErrNoReaders, ErrNoCard) {
		t.Error("ErrNoReaders and ErrNoCard must be distinct")
	}
	other := errors.New("unrelated")
	if errors.Is(other, ErrNoReaders) || errors.Is(other, ErrNoCard) {
		t.Error("unrelated error should not match pcsc sentinels")
	}
}

// TestClose_Idempotent confirms calling Close on a Transport that
// never connected is safe (zero-value tolerance) and idempotent.
// Hardware-free.
func TestClose_Idempotent(t *testing.T) {
	tr := &Transport{closed: true}
	if err := tr.Close(); err != nil {
		t.Errorf("Close on already-closed transport should be nil, got %v", err)
	}
}

// TestTransmit_OnClosed returns a clear error rather than panicking.
// Hardware-free.
func TestTransmit_OnClosed(t *testing.T) {
	tr := &Transport{closed: true}
	_, err := tr.TransmitRaw(context.Background(), []byte{0x00, 0xA4, 0x04, 0x00, 0x00})
	if err == nil {
		t.Error("TransmitRaw on closed transport should return an error")
	}
}
