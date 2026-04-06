package cmac

// Test vectors extracted from the Yubico .NET SDK (Apache 2.0 licensed).
// Source: Yubico/Yubico.NET.SDK, tests/unit/Yubico/YubiKey/Scp/ChannelMacTests.cs
//
// These validate our AES-CMAC implementation against the exact byte sequences
// used by the Yubico SDK for channel MAC computation and RMAC verification.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func yHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestAESCMAC_YubicoChannelMAC validates our CMAC against the channel MAC
// test vector from ChannelMacTests.cs.
//
// The .NET test computes MAC over: MCV || APDU_header_with_Lc
// where the APDU is INS=0xFD with no data, so Lc=8 (space for MAC).
//
// Key:    404142434445464748494A4B4C4D4E4F (default SCP03 key)
// Input:  CB85E66F9DD7C009CB85E66F9DD7C009 (MCV, 16 bytes)
//       + 00FD000008 (CLA=00, INS=FD, P1=00, P2=00, Lc=08)
// Expected MAC (first 8 bytes): 06e58094d47d8908
func TestAESCMAC_YubicoChannelMAC(t *testing.T) {
	key := yHex("404142434445464748494A4B4C4D4E4F")

	// MAC input: MCV || APDU header bytes
	var macInput []byte
	macInput = append(macInput, yHex("CB85E66F9DD7C009CB85E66F9DD7C009")...) // MCV
	macInput = append(macInput, yHex("00FD000008")...)                        // APDU header

	expectedMAC := yHex("06e58094d47d8908") // First 8 bytes of CMAC

	fullMAC, err := AESCMAC(key, macInput)
	if err != nil {
		t.Fatalf("AESCMAC: %v", err)
	}

	truncated := fullMAC[:8]
	if !bytes.Equal(truncated, expectedMAC) {
		t.Errorf("channel MAC mismatch:\n  got:  %x\n  want: %x\n  full: %x",
			truncated, expectedMAC, fullMAC)
	}
}

// TestAESCMAC_YubicoRMAC validates our CMAC against the RMAC verification
// test vector from ChannelMacTests.cs.
//
// RMAC is computed over: MCV || response_data || SW(9000)
//
// RMAC Key: 38C0C6E3D0B6AED40FBB420B51399081
// MCV:      53C2C04391250CCEC0213FF68C877EDA
// Response: 5F67E9E059DF3C52809DC9F6DDFBEF3E (16 bytes data)
//         + 4C45691B2C8CDDD8 (8 bytes RMAC)
// SW:       9000
//
// Expected: CMAC(key, MCV || data || SW)[:8] == received RMAC
func TestAESCMAC_YubicoRMAC(t *testing.T) {
	rmacKey := yHex("38C0C6E3D0B6AED40FBB420B51399081")
	mcv := yHex("53C2C04391250CCEC0213FF68C877EDA")
	fullResponse := yHex("5F67E9E059DF3C52809DC9F6DDFBEF3E4C45691B2C8CDDD8")

	// Split response: data (first 16 bytes) || received RMAC (last 8 bytes)
	respData := fullResponse[:16]
	receivedRMAC := fullResponse[16:]

	// RMAC input: MCV || response_data || SW
	var rmacInput []byte
	rmacInput = append(rmacInput, mcv...)
	rmacInput = append(rmacInput, respData...)
	rmacInput = append(rmacInput, 0x90, 0x00) // Success SW

	fullMAC, err := AESCMAC(rmacKey, rmacInput)
	if err != nil {
		t.Fatalf("AESCMAC: %v", err)
	}

	computedRMAC := fullMAC[:8]
	if !bytes.Equal(computedRMAC, receivedRMAC) {
		t.Errorf("RMAC mismatch:\n  computed: %x\n  received: %x\n  full MAC: %x",
			computedRMAC, receivedRMAC, fullMAC)
	}
}
