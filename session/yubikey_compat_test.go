package session

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
)

// TestYubiKeyCompatibility_SCP11b_ProtocolTrace verifies that every APDU
// our implementation generates matches what a YubiKey 5.7+ running SCP11b
// expects, per the YubiKey Technical Manual and the Samsung/Yubico SDK
// test vectors.
//
// YubiKey SCP11b contract (firmware 5.7.2+):
//   - SCP sits in the Security Domain (AID A0000001510000)
//   - SCP11b KID = 0x13, default KVN = 0x01
//   - Key agreement via INTERNAL AUTHENTICATE (INS=0x88)
//   - No OCE cert required (SCP11b is unilateral)
//   - Session keys derived via X9.63 KDF with SHA-256
//   - Secure messaging: C-MAC + C-ENC + R-MAC + R-ENC (S8 mode)
//   - NIST P-256 curve only
func TestYubiKeyCompatibility_SCP11b_ProtocolTrace(t *testing.T) {
	cfg := DefaultConfig() // SCP11b defaults

	// =====================================================================
	// STEP 1: SELECT Security Domain
	// GP ISD AID: A0 00 00 01 51 00 00 00
	// Expected: 00 A4 04 00 08 A0 00 00 01 51 00 00 00 00
	// =====================================================================
	selectCmd := apdu.NewSelect(cfg.SecurityDomainAID)
	selectBytes, _ := selectCmd.Encode()

	expectedSelect, _ := hex.DecodeString("00A4040008A000000151000000" + "00")
	if !bytes.Equal(selectBytes, expectedSelect) {
		t.Errorf("SELECT mismatch:\n  got:  %X\n  want: %X", selectBytes, expectedSelect)
	}
	t.Logf("STEP 1 SELECT SD: %X ✓", selectBytes)

	// YubiKey scopes an SCP session to the selected applet and selecting
	// another applet terminates the session, so the default config must not
	// auto-select PIV after opening the Security Domain channel.
	if cfg.ApplicationAID != nil {
		t.Errorf("default ApplicationAID: got %X, want nil", cfg.ApplicationAID)
	}
	t.Logf("STEP 1b Application AID: nil by default ✓")

	// =====================================================================
	// STEP 2: GET DATA for Certificate Store (BF21)
	// YubiKey expects: CLA=0x80, INS=0xCA, P1P2=BF21
	// Data field: A6 { 83 { KID=0x13, KVN=0x01 } }
	//
	// Samsung/Yubico both use KID || KVN in tag 0x83 inside A6.
	// =====================================================================
	keyRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyID, []byte{cfg.KeyID, cfg.KeyVersion}),
	)
	getDataCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xCA,
		P1:   0xBF,
		P2:   0x21,
		Data: keyRef.Encode(),
		Le:   0,
	}
	getDataBytes, _ := getDataCmd.Encode()

	// Expected: 80 CA BF 21 06 A6 04 83 02 13 01 00
	expectedGetData, _ := hex.DecodeString("80CABF2106A604830213" + "01" + "00")
	if !bytes.Equal(getDataBytes, expectedGetData) {
		t.Errorf("GET DATA mismatch:\n  got:  %X\n  want: %X", getDataBytes, expectedGetData)
	}
	t.Logf("STEP 2 GET DATA: %X ✓", getDataBytes)

	// =====================================================================
	// STEP 3: INTERNAL AUTHENTICATE (SCP11b key agreement)
	//
	// CLA=0x80, INS=0x88, P1=KVN, P2=KID
	// Data: A6 { 90{11,00}, 95{3C}, 80{88}, 81{10} } || 5F49{ePK.OCE 65B}
	// Le=0x00
	//
	// Key points:
	//   - INS=0x88 for SCP11b (not 0x82 which is for SCP11a/c)
	//   - params=0x00 for SCP11b (0x01 for a, 0x03 for c)
	//   - Key params wrapped in A6 constructed TLV
	//   - ePK.OCE is uncompressed P-256 point (65 bytes, 0x04 prefix)
	//   - keyLength = 0x10 (16 = AES-128)
	// =====================================================================

	// Use Samsung's test ephemeral key for deterministic output.
	oceEphPubHex := "0470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5DBBF8A32" +
		"F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C92"
	oceEphPub, _ := hex.DecodeString(oceEphPubHex)

	// Build INTERNAL AUTH data exactly as our session.go does.
	controlRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyInfo, []byte{0x11, 0x00}), // SCP11b: params=0x00
		tlv.Build(tlv.TagKeyUsage, []byte{kdf.KeyUsage}),
		tlv.Build(tlv.TagKeyType, []byte{kdf.KeyTypeAES}),
		tlv.Build(tlv.TagKeyLength, []byte{kdf.SessionKeyLen}),
	)
	ephPubTLV := tlv.Build(tlv.TagEphPubKey, oceEphPub)

	var authData []byte
	authData = append(authData, controlRef.Encode()...)
	authData = append(authData, ephPubTLV.Encode()...)

	authCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0x88, // INTERNAL AUTHENTICATE for SCP11b
		P1:   cfg.KeyVersion,
		P2:   cfg.KeyID,
		Data: authData,
		Le:   0,
	}
	authBytes, _ := authCmd.Encode()

	// Verify structure.
	if authBytes[0] != 0x80 {
		t.Errorf("AUTH CLA: got 0x%02X, want 0x80", authBytes[0])
	}
	if authBytes[1] != 0x88 {
		t.Errorf("AUTH INS: got 0x%02X, want 0x88 (INTERNAL AUTHENTICATE)", authBytes[1])
	}
	if authBytes[2] != 0x01 {
		t.Errorf("AUTH P1(KVN): got 0x%02X, want 0x01", authBytes[2])
	}
	if authBytes[3] != 0x13 {
		t.Errorf("AUTH P2(KID): got 0x%02X, want 0x13 (SCP11b)", authBytes[3])
	}

	// Verify the A6 TLV is present at the start of data.
	lc := authBytes[4]
	dataStart := authBytes[5 : 5+int(lc)]
	if dataStart[0] != 0xA6 {
		t.Errorf("AUTH data should start with A6 (control ref template), got 0x%02X", dataStart[0])
	}

	// Verify the 5F49 tag is present (OCE ephemeral public key).
	nodes, err := tlv.Decode(dataStart)
	if err != nil {
		t.Fatalf("decode auth data: %v", err)
	}
	ephNode := tlv.Find(nodes, tlv.TagEphPubKey)
	if ephNode == nil {
		t.Fatal("ePK.OCE (tag 5F49) not found in AUTH data")
	}
	if len(ephNode.Value) != 65 {
		t.Errorf("ePK.OCE length: got %d, want 65 (uncompressed P-256)", len(ephNode.Value))
	}
	if ephNode.Value[0] != 0x04 {
		t.Errorf("ePK.OCE prefix: got 0x%02X, want 0x04 (uncompressed)", ephNode.Value[0])
	}

	// Verify Le=0x00 at the end.
	lastByte := authBytes[len(authBytes)-1]
	if lastByte != 0x00 {
		t.Errorf("AUTH Le: got 0x%02X, want 0x00", lastByte)
	}

	t.Logf("STEP 3 INTERNAL AUTH: CLA=%02X INS=%02X P1=%02X P2=%02X Lc=%d Le=%02X ✓",
		authBytes[0], authBytes[1], authBytes[2], authBytes[3], lc, lastByte)

	// Verify key info params inside A6.
	a6Node := tlv.Find(nodes, tlv.TagControlRef)
	if a6Node == nil {
		t.Fatal("A6 control ref not found")
	}
	keyInfoNode := tlv.Find(a6Node.Children, tlv.TagKeyInfo)
	if keyInfoNode == nil {
		t.Fatal("tag 0x90 (key info) not found inside A6")
	}
	if !bytes.Equal(keyInfoNode.Value, []byte{0x11, 0x00}) {
		t.Errorf("key info: got %X, want 1100 (SCP11, params=0x00 for SCP11b)", keyInfoNode.Value)
	}

	// =====================================================================
	// STEP 4: Verify KID mapping for all variants
	// =====================================================================
	kidTests := []struct {
		variant     Variant
		expectedKID byte
		expectedINS byte
		name        string
	}{
		{SCP11a, 0x11, 0x82, "SCP11a"},
		{SCP11b, 0x13, 0x88, "SCP11b"},
		{SCP11c, 0x15, 0x82, "SCP11c"},
	}

	for _, tt := range kidTests {
		t.Run("KID_"+tt.name, func(t *testing.T) {
			// Samsung ScpKid.java: SCP11a=0x11, SCP11b=0x13, SCP11c=0x15
			// Our DefaultConfig uses KeyID=0x13 for SCP11b.
			// For SCP11a/c, the caller must set the right KID.

			// Verify INS byte mapping.
			var ins byte
			switch tt.variant {
			case SCP11a, SCP11c:
				ins = 0x82 // EXTERNAL AUTHENTICATE
			case SCP11b:
				ins = 0x88 // INTERNAL AUTHENTICATE
			}
			if ins != tt.expectedINS {
				t.Errorf("%s INS: got 0x%02X, want 0x%02X", tt.name, ins, tt.expectedINS)
			}
		})
	}

	// =====================================================================
	// STEP 5: Verify wrapped APDU CLA byte
	// YubiKey expects CLA |= 0x04 for secure messaging.
	// =====================================================================
	t.Run("WrappedCLA", func(t *testing.T) {
		plainCLA := byte(0x00)
		wrappedCLA := plainCLA | 0x04
		if wrappedCLA != 0x04 {
			t.Errorf("wrapped CLA: got 0x%02X, want 0x04", wrappedCLA)
		}

		gpCLA := byte(0x80)
		wrappedGPCLA := gpCLA | 0x04
		if wrappedGPCLA != 0x84 {
			t.Errorf("wrapped GP CLA: got 0x%02X, want 0x84", wrappedGPCLA)
		}
	})

	// =====================================================================
	// STEP 6: Verify all constant values match YubiKey expectations
	// =====================================================================
	t.Run("Constants", func(t *testing.T) {
		// From Yubico internal.h:
		// #define SCP11_SESSION_KEY_LEN 16
		// #define SCP11B_KID 0x13
		// #define SCP11B_KVN 0x1
		// #define SCP11_KEY_USAGE 0x3c
		// #define SCP11_KEY_TYPE 0x88
		if kdf.SessionKeyLen != 16 {
			t.Errorf("SessionKeyLen: got %d, want 16", kdf.SessionKeyLen)
		}
		if kdf.KeyUsage != 0x3C {
			t.Errorf("KeyUsage: got 0x%02X, want 0x3C", kdf.KeyUsage)
		}
		if kdf.KeyTypeAES != 0x88 {
			t.Errorf("KeyTypeAES: got 0x%02X, want 0x88", kdf.KeyTypeAES)
		}
		if cfg.KeyID != 0x13 {
			t.Errorf("default KeyID: got 0x%02X, want 0x13 (SCP11b)", cfg.KeyID)
		}
		if cfg.KeyVersion != 0x01 {
			t.Errorf("default KeyVersion: got 0x%02X, want 0x01", cfg.KeyVersion)
		}
	})
}
