package piv

// PIV constants parity test against Yubico's reference implementation.
//
// Per the third external review on feat/sd-keys-cli, Section 1
// (PIV profile parity against yubikit/ykman). The reviewer asked
// for a single table-driven test that asserts our PIV constants
// match yubikit's numerically. The intent is regression-net: a
// future change that reorganizes our constants or duplicates a
// definition can't silently shift a wire byte without this test
// catching it.
//
// Source of truth: yubikit-python repository at github.com/Yubico/
// yubikey-manager, file yubikit/piv.py. Specifically:
//
//   - Class KEY_TYPE     (algorithm bytes: RSA2048=0x07, etc.)
//   - Class SLOT          (slot bytes: 9A/9C/9D/9E + retired 82..95
//                          + ATTESTATION=0xF9)
//   - Class MANAGEMENT_KEY_TYPE (TDES=0x03, AES128=0x08, AES192=0x0A,
//                                AES256=0x0C)
//
// Cross-checked April 2026 against the upstream source. The
// parallel definition in piv/apdu/commands.go (Algo*, Slot*, etc.)
// is pinned by the matching test in piv/apdu/constants_parity_test.go.

import "testing"

// TestPIVConstants_MatchYubikit pins every PIV byte that this
// package exposes against yubikit's source-of-truth bytes.
// Failure means either yubikit changed (rare; these are NIST-
// derived) or this library introduced a typo or accidental
// redefinition.
func TestPIVConstants_MatchYubikit(t *testing.T) {
	t.Run("Algorithm bytes", func(t *testing.T) {
		// yubikit KEY_TYPE class.
		cases := []struct {
			name  string
			alg   Algorithm
			wire  byte
			notes string
		}{
			{"RSA-2048", AlgorithmRSA2048, 0x07, "yubikit KEY_TYPE.RSA2048"},
			{"ECC P-256", AlgorithmECCP256, 0x11, "yubikit KEY_TYPE.ECCP256"},
			{"ECC P-384", AlgorithmECCP384, 0x14, "yubikit KEY_TYPE.ECCP384"},
			{"Ed25519", AlgorithmEd25519, 0xE0, "yubikit KEY_TYPE.ED25519 (YubiKey 5.7+)"},
			{"X25519", AlgorithmX25519, 0xE1, "yubikit KEY_TYPE.X25519 (YubiKey 5.7+)"},
		}
		for _, c := range cases {
			if c.alg.Byte() != c.wire {
				t.Errorf("%s: wire byte = 0x%02X, want 0x%02X (%s)",
					c.name, c.alg.Byte(), c.wire, c.notes)
			}
		}
	})

	t.Run("Slot bytes", func(t *testing.T) {
		cases := []struct {
			name string
			slot Slot
			wire byte
		}{
			// PIV-IS NIST SP 800-73-4 standard slots. yubikit
			// SLOT.AUTHENTICATION..CARD_AUTH.
			{"PIV Authentication (9A)", SlotPIVAuthentication, 0x9A},
			{"Digital Signature (9C)", SlotDigitalSignature, 0x9C},
			{"Key Management (9D)", SlotKeyMgmt, 0x9D},
			{"Card Authentication (9E)", SlotCardAuthentication, 0x9E},
			// Retired slots 1..20 (82..95). yubikit
			// SLOT.RETIRED1..SLOT.RETIRED20.
			{"Retired Key Mgmt 1 (82)", SlotRetiredKeyMgmt1, 0x82},
			{"Retired Key Mgmt 20 (95)", SlotRetiredKeyMgmt20, 0x95},
			// YubiKey-specific slot. yubikit SLOT.ATTESTATION.
			{"YubiKey Attestation (F9)", SlotYubiKeyAttestation, 0xF9},
		}
		for _, c := range cases {
			if c.slot.Byte() != c.wire {
				t.Errorf("%s: wire byte = 0x%02X, want 0x%02X",
					c.name, c.slot.Byte(), c.wire)
			}
		}

		// Boundary check: the retired range 0x82..0x95 is the
		// continuous block. If 0x82 or 0x95 ever shifted, every
		// retired-slot test in the codebase would pass on
		// constants but emit wrong wire bytes against a real
		// card. Pin both endpoints.
		if SlotRetiredKeyMgmt20-SlotRetiredKeyMgmt1 != 0x13 {
			t.Errorf("retired range Δ = 0x%02X, want 0x13 (20 slots, inclusive 82..95)",
				SlotRetiredKeyMgmt20-SlotRetiredKeyMgmt1)
		}
	})

	t.Run("Management Key Algorithm bytes", func(t *testing.T) {
		// yubikit MANAGEMENT_KEY_TYPE. NIST SP 800-78-4 §3.1
		// for 3DES (TDES) plus AES-128/192/256.
		cases := []struct {
			name string
			alg  ManagementKeyAlgorithm
			wire byte
		}{
			{"3DES (TDES)", ManagementKeyAlg3DES, 0x03},
			{"AES-128", ManagementKeyAlgAES128, 0x08},
			{"AES-192", ManagementKeyAlgAES192, 0x0A},
			{"AES-256", ManagementKeyAlgAES256, 0x0C},
		}
		for _, c := range cases {
			if c.alg.Byte() != c.wire {
				t.Errorf("%s: wire byte = 0x%02X, want 0x%02X",
					c.name, c.alg.Byte(), c.wire)
			}
		}
	})
}

// TestPIVConstants_DeferredYubikitConstants documents the yubikit
// constants we deliberately do NOT define today, alongside the wire
// bytes that any future implementation must use to stay yubikit-
// compatible. The test itself is a no-op assertion that documents
// expected bytes for future implementers — running this file
// surfaces the deferred list so a developer adding (say) RSA-3072
// support knows immediately which byte to use.
//
// Why these are deferred:
//
//   - RSA-1024 (0x06): Deprecated by NIST since 2013 (SP 800-131A).
//     Some PIV cards still accept it, but providing it would invite
//     use of a key length below the post-2030 minimum.
//
//   - RSA-3072 (0x05) and RSA-4096 (0x16): Untested against any
//     hardware in our lab harness. yubikit lists them; YubiKey
//     5.7+ supports RSA-3072. We refuse to claim parity until we
//     have a real measurement, per the same discipline that
//     deferred SCP11c-with-HostID and Allowlist on standard-sd.
//
//   - YubiKey extension instructions MOVE_KEY (0xF6),
//     GET_METADATA (0xF7), GET_SERIAL (0xF8), SET_PIN_RETRIES
//     (0xFA), GET_VERSION (0xFD): Not yet wired as named
//     constants. The bytes that ARE used (ATTEST=0xF9,
//     RESET=0xFB, IMPORT_KEY=0xFE, SET_MGMKEY=0xFF) appear as
//     hex literals in commands.go and are pinned by the
//     existing apdu/commands_test.go shape tests. GET_METADATA
//     is on the roadmap (cmd/scpctl README "Next" section) so
//     its byte will be wired when that work lands; pinning it
//     here ensures the future implementer gets the byte right.
//
// The test asserts a tautology (the documented bytes really are
// those bytes); the value is in the comment block, which a code
// review of any future "I want to add RSA-3072" change should
// land on.
func TestPIVConstants_DeferredYubikitConstants(t *testing.T) {
	deferred := map[string]byte{
		"RSA-1024 (yubikit KEY_TYPE.RSA1024, deprecated)":             0x06,
		"RSA-3072 (yubikit KEY_TYPE.RSA3072, YubiKey 5.7+, untested)": 0x05,
		"RSA-4096 (yubikit KEY_TYPE.RSA4096, untested)":               0x16,
		"INS_MOVE_KEY (yubikit, YubiKey 5.7+, not yet wired)":         0xF6,
		"INS_GET_METADATA (yubikit, on roadmap)":                      0xF7,
		"INS_GET_SERIAL (yubikit, not yet wired)":                     0xF8,
		"INS_SET_PIN_RETRIES (yubikit, not yet wired)":                0xFA,
		"INS_GET_VERSION (yubikit, not yet wired)":                    0xFD,
	}
	if len(deferred) != 8 {
		t.Errorf("deferred list length = %d, want 8 (drift in expected-future-bytes table)", len(deferred))
	}
	// Render the deferred list under -v so a developer running
	// the parity test sees the list and the rationale at the
	// same moment.
	for name, b := range deferred {
		t.Logf("deferred yubikit byte: %s = 0x%02X", name, b)
	}
}
