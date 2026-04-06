package scp03

// Test vectors extracted from the Yubico .NET SDK (Apache 2.0 licensed).
// Source: Yubico/Yubico.NET.SDK, tests/unit/Yubico/YubiKey/Scp/DerivationTests.cs
//
// These validate our NIST SP 800-108 KDF implementation against a known-good
// reference implementation that runs on real YubiKey devices.

import (
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestDeriveSCP03Key_YubicoVector tests the SCP03 CMAC-based key derivation
// against a concrete test vector from the Yubico .NET SDK.
//
// Source: DerivationTests.cs
//   Key:            FC90AA67CDC5DABFD5051663045DFA23
//   Host Challenge: 360CB43F4301B894
//   Card Challenge: CAAFA4DAC615236A
//   DDC:            HOST_CRYPTOGRAM (0x01)
//   Output length:  64 bits (8 bytes)
//   Expected:       45330AB30BB1A079
func TestDeriveSCP03Key_YubicoVector(t *testing.T) {
	key := mustHex("FC90AA67CDC5DABFD5051663045DFA23")
	hostChallenge := mustHex("360CB43F4301B894")
	cardChallenge := mustHex("CAAFA4DAC615236A")
	expected := mustHex("45330AB30BB1A079")

	context := append(hostChallenge, cardChallenge...)

	// calculateCryptogram uses derivConst, S-MAC key, context, and keyLen.
	// DDC_HOST_CRYPTOGRAM = 0x01, output = 64 bits = 8 bytes
	got, err := calculateCryptogram(key, derivConstHostCrypto, context, len(key))
	if err != nil {
		t.Fatalf("calculateCryptogram: %v", err)
	}

	if hex.EncodeToString(got) != hex.EncodeToString(expected) {
		t.Errorf("host cryptogram mismatch:\n  got:    %x\n  want:   %x", got, expected)
	}
}

// TestDeriveSCP03SessionKeys_DefaultKeys validates the full session key
// derivation with default keys and all-ones challenges.
//
// Source: Scp03StateTests.cs — uses default keys with Fill(1) challenges.
// We validate that the derivation produces deterministic, non-zero output
// and that S-MAC != S-ENC != S-RMAC.
func TestDeriveSCP03SessionKeys_DefaultKeys(t *testing.T) {
	defaultKey := mustHex("404142434445464748494A4B4C4D4E4F")
	hostChallenge := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	cardChallenge := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	context := append(hostChallenge, cardChallenge...)

	senc, err := deriveSCP03Key(defaultKey, derivConstSENC, context, 16)
	if err != nil {
		t.Fatalf("derive S-ENC: %v", err)
	}
	smac, err := deriveSCP03Key(defaultKey, derivConstSMAC, context, 16)
	if err != nil {
		t.Fatalf("derive S-MAC: %v", err)
	}
	srmac, err := deriveSCP03Key(defaultKey, derivConstSRMAC, context, 16)
	if err != nil {
		t.Fatalf("derive S-RMAC: %v", err)
	}

	// All keys should be non-zero.
	for _, k := range [][]byte{senc, smac, srmac} {
		allZero := true
		for _, b := range k {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("derived key is all zeros")
		}
	}

	// All keys should be different from each other (different DDC).
	if hex.EncodeToString(senc) == hex.EncodeToString(smac) {
		t.Error("S-ENC == S-MAC (should differ)")
	}
	if hex.EncodeToString(senc) == hex.EncodeToString(srmac) {
		t.Error("S-ENC == S-RMAC (should differ)")
	}
	if hex.EncodeToString(smac) == hex.EncodeToString(srmac) {
		t.Error("S-MAC == S-RMAC (should differ)")
	}

	// Derivation should be deterministic.
	senc2, _ := deriveSCP03Key(defaultKey, derivConstSENC, context, 16)
	if hex.EncodeToString(senc) != hex.EncodeToString(senc2) {
		t.Error("derivation not deterministic")
	}

	t.Logf("S-ENC:  %x", senc)
	t.Logf("S-MAC:  %x", smac)
	t.Logf("S-RMAC: %x", srmac)
}

// TestDeriveSCP03_CardCryptogram validates card cryptogram computation.
// The card cryptogram uses the same KDF as host cryptogram but with
// DDC_CARD_CRYPTOGRAM (0x00).
func TestDeriveSCP03_CardCryptogram(t *testing.T) {
	key := mustHex("FC90AA67CDC5DABFD5051663045DFA23")
	hostChallenge := mustHex("360CB43F4301B894")
	cardChallenge := mustHex("CAAFA4DAC615236A")

	context := append(hostChallenge, cardChallenge...)

	cardCrypto, err := calculateCryptogram(key, derivConstCardCrypto, context, len(key))
	if err != nil {
		t.Fatalf("calculateCryptogram: %v", err)
	}
	hostCrypto, err := calculateCryptogram(key, derivConstHostCrypto, context, len(key))
	if err != nil {
		t.Fatalf("calculateCryptogram: %v", err)
	}

	if len(cardCrypto) != 8 {
		t.Errorf("card cryptogram should be 8 bytes, got %d", len(cardCrypto))
	}

	// Card and host cryptograms must differ (different DDC).
	if hex.EncodeToString(cardCrypto) == hex.EncodeToString(hostCrypto) {
		t.Error("card and host cryptograms should differ")
	}
}
