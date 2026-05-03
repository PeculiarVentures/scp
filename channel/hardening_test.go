package channel

import (
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/kdf"
)

// TestNewWithMACSize_RejectsInvalidSizes locks in that the constructor
// panics on anything other than 8 or 16. macSize=0 silently disables
// MAC verification (a security regression), and macSize > 16 panics
// inside slice arithmetic mid-protocol — both are programmer errors
// that must fail at construction, not at first use.
func TestNewWithMACSize_RejectsInvalidSizes(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:  make([]byte, 16),
		SMAC:  make([]byte, 16),
		SRMAC: make([]byte, 16),
	}
	cases := []int{0, -1, 7, 9, 15, 17, 32, 100}
	for _, sz := range cases {
		t.Run("", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("NewWithMACSize(%d) should have panicked", sz)
					return
				}
				msg, _ := r.(string)
				if !strings.Contains(msg, "macSize") {
					t.Errorf("panic message should mention macSize; got: %v", r)
				}
			}()
			_ = NewWithMACSize(keys, LevelFull, sz)
		})
	}
}

// TestNewWithMACSize_AcceptsValidSizes confirms 8 and 16 still work.
func TestNewWithMACSize_AcceptsValidSizes(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:  make([]byte, 16),
		SMAC:  make([]byte, 16),
		SRMAC: make([]byte, 16),
	}
	for _, sz := range []int{MACLen, FullMACLen} {
		ch := NewWithMACSize(keys, LevelFull, sz)
		if ch.MACSize() != sz {
			t.Errorf("MACSize() = %d, want %d", ch.MACSize(), sz)
		}
	}
}

// TestEncCounter_OverflowFailsClosed confirms the encryption counter
// is checked before wrap. Reusing IV under the same AES-CBC key is a
// key-recovery hazard; the channel must refuse to emit the wrap
// rather than reuse counter=0.
func TestEncCounter_OverflowFailsClosed(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:  make([]byte, 16),
		SMAC:  make([]byte, 16),
		SRMAC: make([]byte, 16),
	}
	ch := New(keys, LevelFull)
	ch.encCounter = 0xFFFFFFFF // force the boundary

	_, err := ch.encryptPayload([]byte("anything"))
	if err == nil {
		t.Fatal("encryptPayload should have refused at counter=MaxUint32")
	}
	if !strings.Contains(err.Error(), "counter exhausted") {
		t.Errorf("error should mention counter exhaustion; got: %v", err)
	}
}
