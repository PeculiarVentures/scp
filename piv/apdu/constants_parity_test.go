package pivapdu

// PIV/apdu constants parity test against Yubico's reference
// implementation. Pins the parallel constant block in commands.go
// against yubikit's source-of-truth bytes.
//
// The piv package has its own parity test (piv/constants_parity_test.go)
// that pins the typed Algorithm/Slot/ManagementKeyAlgorithm
// constants. This file pins the byte-typed mirrors here that
// commands.go uses for direct wire construction (Algo*, Slot*,
// PINPolicy*, TouchPolicy*).
//
// Both blocks must agree because the apdu layer is what actually
// puts bytes on the wire; the typed piv.Algorithm / piv.Slot
// values are only useful in the host code if the apdu layer
// translates them to the same bytes.
//
// Per the third external review on feat/sd-keys-cli, Section 1.

import "testing"

// TestAPDUConstants_MatchYubikit pins the apdu package's
// constants against yubikit's source-of-truth bytes. Failure means
// either yubikit changed (rare; these are NIST-derived) or the
// commands.go const block introduced drift.
//
// Cross-checked April 2026 against
// https://github.com/Yubico/yubikey-manager/blob/main/yubikit/piv.py
func TestAPDUConstants_MatchYubikit(t *testing.T) {
	t.Run("Algorithm bytes (Algo*)", func(t *testing.T) {
		// Mirrors yubikit KEY_TYPE class. These bytes are what
		// the host emits in INSERT/IMPORT/GENERATE APDUs.
		cases := []struct {
			name string
			got  byte
			want byte
		}{
			{"AlgoRSA2048", AlgoRSA2048, 0x07},
			{"AlgoECCP256", AlgoECCP256, 0x11},
			{"AlgoECCP384", AlgoECCP384, 0x14},
			{"AlgoEd25519", AlgoEd25519, 0xE0},
			{"AlgoX25519", AlgoX25519, 0xE1},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = 0x%02X, want 0x%02X", c.name, c.got, c.want)
			}
		}
	})

	t.Run("Slot bytes (Slot*)", func(t *testing.T) {
		// Mirrors yubikit SLOT class. These bytes appear as
		// P2 of INS_GENERATE_KEY and INS_AUTHENTICATE.
		cases := []struct {
			name string
			got  byte
			want byte
		}{
			{"SlotAuthentication (9A)", SlotAuthentication, 0x9A},
			{"SlotSignature (9C)", SlotSignature, 0x9C},
			{"SlotKeyManagement (9D)", SlotKeyManagement, 0x9D},
			{"SlotCardAuth (9E)", SlotCardAuth, 0x9E},
			{"SlotRetired1 (82)", SlotRetired1, 0x82},
			{"SlotRetired20 (95)", SlotRetired20, 0x95},
			{"SlotAttestation (F9, YubiKey)", SlotAttestation, 0xF9},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = 0x%02X, want 0x%02X", c.name, c.got, c.want)
			}
		}
	})

	t.Run("PIN Policy bytes", func(t *testing.T) {
		// yubikit PIN_POLICY class. Sent in the PIN policy
		// metadata field on key generation.
		cases := []struct {
			name string
			got  byte
			want byte
		}{
			{"PINPolicyDefault", PINPolicyDefault, 0x00},
			{"PINPolicyNever", PINPolicyNever, 0x01},
			{"PINPolicyOnce", PINPolicyOnce, 0x02},
			{"PINPolicyAlways", PINPolicyAlways, 0x03},
			{"PINPolicyMatch (5.7+)", PINPolicyMatch, 0x04},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = 0x%02X, want 0x%02X", c.name, c.got, c.want)
			}
		}
	})

	t.Run("Touch Policy bytes", func(t *testing.T) {
		// yubikit TOUCH_POLICY class.
		cases := []struct {
			name string
			got  byte
			want byte
		}{
			{"TouchPolicyDefault", TouchPolicyDefault, 0x00},
			{"TouchPolicyNever", TouchPolicyNever, 0x01},
			{"TouchPolicyAlways", TouchPolicyAlways, 0x02},
			{"TouchPolicyCached", TouchPolicyCached, 0x03},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = 0x%02X, want 0x%02X", c.name, c.got, c.want)
			}
		}
	})
}
