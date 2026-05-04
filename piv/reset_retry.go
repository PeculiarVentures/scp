package piv

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
)

// PUKKeyRef is the PIV key reference for the PUK
// (NIST SP 800-73-4 Part 2 Table 6).
const PUKKeyRef byte = 0x81

// PINKeyRef is the PIV key reference for the application PIN
// (NIST SP 800-73-4 Part 2 Table 6).
const PINKeyRef byte = 0x80

// ResetRetryCounter unblocks a blocked PIN by presenting the PUK
// and a new PIN. NIST SP 800-73-4 Part 2 §3.2.3: INS 0x2C, P1 0x00,
// P2 = key reference (PIN). Data is the PUK (8 bytes, 0xFF-padded)
// concatenated with the new PIN (8 bytes, 0xFF-padded).
//
// On a wrong PUK the card decrements the PUK retry counter; on
// counter exhaustion the PUK is blocked and the only way forward
// is the YubiKey-specific PIV reset (INS 0xFB), which requires
// both PIN and PUK blocked.
//
// This builder is used by piv-reset to deliberately block the PUK
// (sending wrong PUKs in a loop until 6983) as a precondition for
// the reset APDU — that's how YubiKey gates accidental wipes.
func ResetRetryCounter(puk, newPIN []byte) (*apdu.Command, error) {
	if len(puk) == 0 || len(puk) > MaxPINLength {
		return nil, fmt.Errorf("PUK length %d outside [1, %d]", len(puk), MaxPINLength)
	}
	if len(newPIN) == 0 || len(newPIN) > MaxPINLength {
		return nil, fmt.Errorf("new PIN length %d outside [1, %d]", len(newPIN), MaxPINLength)
	}
	data := make([]byte, 0, 2*MaxPINLength)
	data = append(data, padPIN(puk)...)
	data = append(data, padPIN(newPIN)...)
	return &apdu.Command{
		CLA:  0x00,
		INS:  0x2C,
		P1:   0x00,
		P2:   PINKeyRef,
		Data: data,
		Le:   -1,
	}, nil
}

// padPIN right-pads a PIN/PUK to MaxPINLength bytes with 0xFF per
// NIST SP 800-73-4 Part 2 §3.2.1. Caller guarantees len <= MaxPINLength.
func padPIN(p []byte) []byte {
	out := make([]byte, MaxPINLength)
	for i := range out {
		out[i] = 0xFF
	}
	copy(out, p)
	return out
}

// ErrPINBlocked indicates a VERIFY PIN got SW=6983 — the PIN counter
// has reached zero and further VERIFY attempts will continue to
// return 6983 until the PUK is used to unblock it (or the YubiKey
// PIV applet is reset). Used by piv-reset to detect "PIN is now
// blocked, move on to blocking the PUK."
var ErrPINBlocked = errors.New("PIN blocked (SW=6983)")

// ErrPUKBlocked indicates a RESET RETRY COUNTER got SW=6983 — the
// PUK counter has reached zero. With both PIN and PUK blocked, the
// YubiKey-specific reset INS=0xFB is now accepted.
var ErrPUKBlocked = errors.New("PUK blocked (SW=6983)")
