package pivapdu

import (
	"testing"

	"github.com/PeculiarVentures/scp/piv"
)

// TestResetRetryCounter_WireBytes locks the byte-for-byte shape of
// the PIV RESET RETRY COUNTER APDU per NIST SP 800-73-4 Part 2
// §3.2.3. The data field is the PUK followed by the new PIN, each
// right-padded to MaxPINLength with 0xFF.
//
// CLA=00, INS=2C, P1=00, P2=80 (PIN key reference). The data field
// is 16 bytes total: PUK (8 bytes 0xFF-padded) || newPIN (8 bytes
// 0xFF-padded).
func TestResetRetryCounter_WireBytes(t *testing.T) {
	cmd, err := ResetRetryCounter([]byte("12345678"), []byte("9999"))
	if err != nil {
		t.Fatalf("ResetRetryCounter: %v", err)
	}
	if cmd.CLA != 0x00 {
		t.Errorf("CLA = %02X, want 00", cmd.CLA)
	}
	if cmd.INS != 0x2C {
		t.Errorf("INS = %02X, want 2C", cmd.INS)
	}
	if cmd.P1 != 0x00 {
		t.Errorf("P1 = %02X, want 00", cmd.P1)
	}
	if cmd.P2 != PINKeyRef {
		t.Errorf("P2 = %02X, want %02X (PINKeyRef)", cmd.P2, PINKeyRef)
	}
	if cmd.Le != -1 {
		t.Errorf("Le = %d, want -1 (no Le)", cmd.Le)
	}

	wantData := []byte{
		// PUK "12345678" (already 8 bytes, no padding needed).
		'1', '2', '3', '4', '5', '6', '7', '8',
		// New PIN "9999" right-padded to 8 bytes with 0xFF.
		'9', '9', '9', '9', 0xFF, 0xFF, 0xFF, 0xFF,
	}
	if len(cmd.Data) != len(wantData) {
		t.Fatalf("Data len = %d, want %d", len(cmd.Data), len(wantData))
	}
	for i := range wantData {
		if cmd.Data[i] != wantData[i] {
			t.Errorf("Data[%d] = %02X, want %02X", i, cmd.Data[i], wantData[i])
		}
	}
}

// TestResetRetryCounter_MaxLengths verifies the boundary case of
// PUK and PIN both at MaxPINLength: the data field is exactly
// 2 * MaxPINLength bytes with no padding bytes (because nothing
// needs padding when length is already maximal).
func TestResetRetryCounter_MaxLengths(t *testing.T) {
	puk := make([]byte, piv.MaxPINLength)
	for i := range puk {
		puk[i] = 'A'
	}
	newPIN := make([]byte, piv.MaxPINLength)
	for i := range newPIN {
		newPIN[i] = 'B'
	}
	cmd, err := ResetRetryCounter(puk, newPIN)
	if err != nil {
		t.Fatalf("ResetRetryCounter: %v", err)
	}
	if len(cmd.Data) != 2*piv.MaxPINLength {
		t.Fatalf("Data len = %d, want %d", len(cmd.Data), 2*piv.MaxPINLength)
	}
	for i := 0; i < piv.MaxPINLength; i++ {
		if cmd.Data[i] != 'A' {
			t.Errorf("Data[%d] = %02X (PUK section), want %02X", i, cmd.Data[i], 'A')
		}
		if cmd.Data[piv.MaxPINLength+i] != 'B' {
			t.Errorf("Data[%d] = %02X (PIN section), want %02X",
				piv.MaxPINLength+i, cmd.Data[piv.MaxPINLength+i], 'B')
		}
	}
}

// TestResetRetryCounter_RejectsEmpty verifies the builder refuses
// empty PUK or PIN. NIST SP 800-73-4 does not define semantics for
// a zero-length credential and the card would reject the APDU
// anyway, but rejecting host-side surfaces the bug closer to the
// caller.
func TestResetRetryCounter_RejectsEmpty(t *testing.T) {
	if _, err := ResetRetryCounter(nil, []byte("9999")); err == nil {
		t.Error("expected error for empty PUK")
	}
	if _, err := ResetRetryCounter([]byte("12345678"), nil); err == nil {
		t.Error("expected error for empty new PIN")
	}
}

// TestResetRetryCounter_RejectsOverlong verifies the builder
// refuses inputs longer than MaxPINLength. A PIV card silently
// rejects oversize input but the failure mode is opaque (typically
// 6700 wrong-length); rejecting host-side gives a clear error.
func TestResetRetryCounter_RejectsOverlong(t *testing.T) {
	tooLong := make([]byte, piv.MaxPINLength+1)
	if _, err := ResetRetryCounter(tooLong, []byte("9999")); err == nil {
		t.Error("expected error for overlong PUK")
	}
	if _, err := ResetRetryCounter([]byte("12345678"), tooLong); err == nil {
		t.Error("expected error for overlong new PIN")
	}
}
