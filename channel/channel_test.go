package channel

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
)

// ============================================================
// REVIEW FINDING 1: IV derivation polarity is swapped.
//
// GP §5.3.2 command encryption:
//   IV for COMMAND encryption = AES-ECB(SENC, 0x00..00 || counter)
//   (12 zero bytes + 4-byte counter, NO 0x80 prefix)
//
// GP §5.3.2 response decryption:
//   IV for RESPONSE decryption = AES-ECB(SENC, 0x80 || 0x00..00 || counter)
//   (0x80 prefix + 11 zero bytes + 4-byte counter)
//
// Our channel.go has these BACKWARDS:
//   deriveIV()         sets counterBlock[0] = 0x80  (WRONG: should be 0x00)
//   deriveResponseIV() leaves counterBlock[0] = 0x00 (WRONG: should be 0x80)
//
// This test will fail until we fix the polarity.
// ============================================================

func TestEncryptIV_Polarity(t *testing.T) {
	senc := bytes.Repeat([]byte{0xAA}, 16)
	keys := &kdf.SessionKeys{
		SENC:     senc,
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}

	sc := New(keys, LevelFull)

	// The IV for command encryption (counter=1) should be:
	// AES-ECB(SENC, 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01)
	// NOT: AES-ECB(SENC, 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01)
	block, _ := aes.NewCipher(senc)

	var correctCounterBlock [16]byte
	// No 0x80 prefix for command encryption
	binary.BigEndian.PutUint32(correctCounterBlock[12:], 1)
	var expectedIV [16]byte
	block.Encrypt(expectedIV[:], correctCounterBlock[:])

	iv, err := sc.deriveIV()
	if err != nil {
		t.Fatalf("deriveIV: %v", err)
	}

	if !bytes.Equal(iv, expectedIV[:]) {
		t.Errorf("command IV wrong polarity (0x80 prefix should NOT be set for commands)\n"+
			"  got:  %X\n  want: %X", iv, expectedIV[:])
	}
}

// ============================================================
// REVIEW FINDING 2: MAC computation doesn't match reference implementation.
//
// reference implementation's ScpProcessor.sendApdu():
//   1. Builds the full APDU with placeholder MAC bytes
//   2. Calls state.mac() with APDU minus the trailing MAC bytes
//
// GP §5.3.2 command MAC:
//   mac.update(macChain)
//   macChain = mac.doFinal(data)
//   return macChain[:macSize]
//
// This means the CMAC input is: macChain || apdu_without_mac_bytes
// The CMAC is computed as a single call with macChain prepended.
//
// Our channel.go Wrap():
//   - Builds macInput = macChain || CLA' || INS || P1 || P2 || Lc || payload
//   - Pads the macInput
//   - Computes AESCMAC(SMAC, padded_macInput)
//
// PROBLEM: reference implementation uses CMAC's natural chaining (mac.update(chain); mac.doFinal(data)),
// which means chain is part of the message, NOT padded separately. Our code
// concatenates macChain to the data then pads the whole thing — but CMAC with
// update/doFinal is equivalent to CMAC(key, chain || data) which is what
// our code does. So actually the MAC computation is equivalent.
//
// BUT: reference implementation formats the APDU bytes using processor.formatApdu() which
// produces the full serialized APDU (CLA INS P1 P2 Lc data) without Le.
// Our code manually builds the header, which should produce the same result.
//
// Let's verify with reference implementation's known wrapped APDU.
// ============================================================

func TestWrapListPackages_MatchesReferenceVectors(t *testing.T) {
	// reference implementation's SCP11a P-256 AES-128 S8 test vectors.
	// Session keys derived from TestECDHWithreference implementationKeys.
	senc, _ := hex.DecodeString("4C6B3E83965B676F0A52B42FCEB3B2D3")
	smac, _ := hex.DecodeString("4CBBF2F343596805B47D8DFBEF766C43")
	srmac, _ := hex.DecodeString("7922CCFB7DED0806B53D81EEA29A01D8")
	dek, _ := hex.DecodeString("6D659C4AD557C2CE400EB38BF7FD1725")

	// reference implementation initializes macChain to the receipt value after SCP11 handshake.
	receipt, _ := hex.DecodeString("0B63C42C2D5138936FF5894F10C1234F")

	keys := &kdf.SessionKeys{
		SENC:     senc,
		SMAC:     smac,
		SRMAC:    srmac,
		DEK:      dek,
		MACChain: receipt,
	}

	sc := New(keys, LevelFull)

	// reference implementation's GET STATUS (list packages):
	// CLA=0x80, INS=0xF2, P1=0x20, P2=0x00, Data=4F00
	// Le is NOT included in the wrapped APDU per reference implementation's ScpProcessor
	// (formatApdu with forceAddLe=false on the MAC computation means
	// the final APDU also excludes Le).
	cmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xF2,
		P1:   0x20,
		P2:   0x00,
		Data: []byte{0x4F, 0x00},
		Le:   -1, // No Le byte in wrapped commands
	}

	wrapped, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// reference implementation's expected wrapped CAPDU:
	// 84 F2 20 00 18 E1EE3A92EF45551E 8464A252F997230D C4E84F41BA692405
	// Lc=0x18 = 24 bytes: 16 encrypted + 8 MAC
	expectedHex := "84F2200018E1EE3A92EF45551E8464A252F997230DC4E84F41BA692405"
	expected, _ := hex.DecodeString(expectedHex)

	encoded, err := wrapped.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("wrapped LIST_PACKAGES mismatch:\n  got:  %X\n  want: %X", encoded, expected)
		// Decode both to help debug.
		if len(encoded) > 5 && len(expected) > 5 {
			gotLc := encoded[4]
			wantLc := expected[4]
			t.Logf("  Lc: got=%d want=%d", gotLc, wantLc)
			if len(encoded) > 5+int(gotLc) {
				gotData := encoded[5 : 5+int(gotLc)]
				t.Logf("  got data:  %X", gotData)
			}
		}
	}
}

// ============================================================
// REVIEW FINDING 3: Empty data handling during encryption.
//
// reference implementation's encrypt() has a critical special case:
//   if (data.length == 0) { encCounter++; return data; }
//
// This means commands with no data field SKIP encryption but
// still increment the counter. Our code checks
// `len(payload) > 0` before encrypting, which is correct,
// but we DON'T increment encCounter for empty payloads.
// ============================================================

func TestEmptyPayload_CounterIncrement(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}

	sc := New(keys, LevelFull)
	initialCounter := sc.encCounter

	// Wrap a command with no data field.
	cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Data: nil, Le: -1}
	_, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// reference implementation's encrypt(): empty data → counter++ and return empty.
	if sc.encCounter != initialCounter+1 {
		t.Errorf("encCounter: got %d, want %d", sc.encCounter, initialCounter+1)
	}
}

// ============================================================
// REVIEW FINDING 4: R-MAC uses macChain not a separate chain.
//
// reference implementation's unmac():
//   mac.init(keys.srmac)
//   mac.update(macChain)    <-- uses the COMMAND mac chain value
//   rmac = mac.doFinal(msg)
//
// This is correct behavior: the R-MAC chains from the same
// macChain that was updated during the C-MAC computation.
// Our code does the same (uses sc.macChain). Good.
//
// But reference implementation does NOT update macChain after R-MAC computation.
// The macChain only updates during C-MAC (mac()). Verify this.
// ============================================================

func TestRMACDoesNotUpdateChain(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}

	sc := New(keys, LevelCMAC|LevelRMAC)

	// Wrap a command (updates macChain via C-MAC).
	cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Le: 0}
	_, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	chainAfterCMAC := make([]byte, 16)
	copy(chainAfterCMAC, sc.macChain)

	// Build a fake response with a valid R-MAC.
	// The R-MAC input is: macChain || response_data || SW1 || SW2
	responseData := []byte{0x01, 0x02, 0x03}
	var macInput []byte
	macInput = append(macInput, sc.macChain...)
	macInput = append(macInput, responseData...)
	macInput = append(macInput, 0x90, 0x00)

	mac, _ := cmac.AESCMAC(keys.SRMAC, macInput)

	var respData []byte
	respData = append(respData, responseData...)
	respData = append(respData, mac[:MACLen]...)

	resp := &apdu.Response{Data: respData, SW1: 0x90, SW2: 0x00}
	_, err = sc.Unwrap(resp)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	// macChain should NOT have changed during R-MAC verification.
	if !bytes.Equal(sc.macChain, chainAfterCMAC) {
		t.Errorf("macChain changed during R-MAC unwrap:\n  before: %X\n  after:  %X",
			chainAfterCMAC, sc.macChain)
	}
}

// ============================================================
// REVIEW FINDING 5: reference implementation's APDU format processor excludes Le
// from MAC computation.
//
// reference implementation's ScpProcessor.sendApdu():
//   apduData = processor.formatApdu(cla, ins, p1, p2, macedData,
//       0, macedData.length, 0, false /* no Le */);
//
// The comment says: "Mandatory for correct MAC calculation over
// whole APDU blob without Le byte"
//
// This means the MAC is computed over: CLA INS P1 P2 Lc DATA
// but NOT over Le. Our Wrap() doesn't include Le in the MAC
// computation either (we only include CLA INS P1 P2 Lc payload),
// so this is correct.
// ============================================================

// ============================================================
// REVIEW FINDING 6: reference implementation uses ScpMode S8 (8-byte MAC) and
// S16 (16-byte MAC). Our MACLen is hardcoded to 8.
// We should verify the S8 mode matches, and flag S16 as unsupported.
// ============================================================

func TestMACTruncation_S8Mode(t *testing.T) {
	// Verify MAC is truncated to 8 bytes (S8 mode).
	key := bytes.Repeat([]byte{0xAA}, 16)
	data := []byte{0x01, 0x02, 0x03}

	fullMAC, err := cmac.AESCMAC(key, data)
	if err != nil {
		t.Fatalf("CMAC: %v", err)
	}

	if len(fullMAC) != 16 {
		t.Fatalf("full MAC should be 16 bytes")
	}

	truncated := fullMAC[:MACLen]
	if len(truncated) != 8 {
		t.Errorf("truncated MAC should be 8 bytes (S8 mode), got %d", len(truncated))
	}
}

// ============================================================
// End-to-end: unwrap reference implementation's LIST_PACKAGES response and verify
// it decrypts to the known plaintext.
// ============================================================

func TestUnwrapListPackagesResponse_MatchesReferenceVectors(t *testing.T) {
	senc, _ := hex.DecodeString("4C6B3E83965B676F0A52B42FCEB3B2D3")
	smac, _ := hex.DecodeString("4CBBF2F343596805B47D8DFBEF766C43")
	srmac, _ := hex.DecodeString("7922CCFB7DED0806B53D81EEA29A01D8")
	dek, _ := hex.DecodeString("6D659C4AD557C2CE400EB38BF7FD1725")
	receipt, _ := hex.DecodeString("0B63C42C2D5138936FF5894F10C1234F")

	keys := &kdf.SessionKeys{
		SENC:     senc,
		SMAC:     smac,
		SRMAC:    srmac,
		DEK:      dek,
		MACChain: receipt,
	}

	sc := New(keys, LevelFull)

	// First wrap the LIST_PACKAGES command so macChain advances correctly.
	cmd := &apdu.Command{
		CLA: 0x80, INS: 0xF2, P1: 0x20, P2: 0x00,
		Data: []byte{0x4F, 0x00}, Le: -1,
	}
	_, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// reference implementation's LIST_PACKAGES response (encrypted + MACed + SW).
	respHex := "DC8D7D92F77BB20F4AEA2C2EB70A7D93C5F0EA0F27D193679C3D1C970BED8F73C394C63A201C8D367A9F0990146D1FF5CEC2" +
		"E5F90F6956EF241D2CC899BA25B964FFFB799F4C42469000"
	respRaw, _ := hex.DecodeString(respHex)

	resp, err := apdu.ParseResponse(respRaw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	// Unwrap: verify R-MAC, then decrypt.
	plainResp, err := sc.Unwrap(resp)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	// reference implementation's expected plaintext data from OutputTestData.LIST_PACKAGES_RSP_PLAIN_DATA.
	expectedPlainHex := "08A00000015141434C010010A00000022020030101010000000000060100" +
		"10A0000002202003010101000000000011010005A0000002480100"
	expectedPlain, _ := hex.DecodeString(expectedPlainHex)

	if !bytes.Equal(plainResp.Data, expectedPlain) {
		t.Errorf("decrypted LIST_PACKAGES mismatch:\n  got:  %X\n  want: %X",
			plainResp.Data, expectedPlain)
	}
}

// ============================================================
// Wrap-then-unwrap round trip with synthetic data.
// ============================================================

func TestWrapUnwrapRoundTrip(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0x11}, 16),
		SMAC:     bytes.Repeat([]byte{0x22}, 16),
		SRMAC:    bytes.Repeat([]byte{0x33}, 16),
		DEK:      bytes.Repeat([]byte{0x44}, 16),
		MACChain: make([]byte, 16),
	}

	// Use two separate SecureChannel instances to simulate card and host
	// sharing the same key material.
	scHost := New(keys, LevelFull)

	// Make a copy for the "card" side.
	cardKeys := &kdf.SessionKeys{
		SENC:     append([]byte{}, keys.SENC...),
		SMAC:     append([]byte{}, keys.SMAC...),
		SRMAC:    append([]byte{}, keys.SRMAC...),
		DEK:      append([]byte{}, keys.DEK...),
		MACChain: make([]byte, 16),
	}
	scCard := New(cardKeys, LevelFull)

	// Wrap a command on the host side.
	plainData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	cmd := &apdu.Command{CLA: 0x80, INS: 0xDA, P1: 0x01, P2: 0x02, Data: plainData, Le: -1}
	wrapped, err := scHost.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// The card side should be able to:
	// 1. Verify the C-MAC (same SMAC key, same macChain)
	// 2. Decrypt the payload
	// For this we manually simulate what the card would do.

	// Verify CLA has secure messaging bit.
	if wrapped.CLA&0x04 == 0 {
		t.Error("secure messaging bit not set in CLA")
	}

	// Verify data is longer than original (encrypted + MAC).
	if len(wrapped.Data) <= len(plainData) {
		t.Error("wrapped data should be longer than plaintext")
	}

	// Extract MAC (last 8 bytes).
	mac := wrapped.Data[len(wrapped.Data)-MACLen:]
	encData := wrapped.Data[:len(wrapped.Data)-MACLen]

	// Verify MAC using the card's key state.
	var macInput []byte
	macInput = append(macInput, scCard.macChain...)
	macInput = append(macInput, wrapped.CLA, wrapped.INS, wrapped.P1, wrapped.P2)
	macInput = append(macInput, byte(len(wrapped.Data))) // Lc
	macInput = append(macInput, encData...)
	expectedMAC, _ := cmac.AESCMAC(keys.SMAC, macInput)
	if !bytes.Equal(mac, expectedMAC[:MACLen]) {
		t.Errorf("C-MAC verification failed on card side")
	}

	t.Logf("Wrap round-trip: %d bytes plaintext -> %d bytes wrapped",
		len(plainData), len(wrapped.Data))
}

// ============================================================
// Regression: S16 mode (16-byte MAC) wrap/unwrap round trip.
//
// Before the fix, Unwrap compared expectedMAC[:MACLen] (8 bytes)
// against receivedMAC (16 bytes), which always failed because
// constantTimeEqual rejects mismatched lengths. This test verifies
// S16 mode works end-to-end after the fix.
// ============================================================

func TestWrapUnwrapRoundTrip_S16(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0x11}, 16),
		SMAC:     bytes.Repeat([]byte{0x22}, 16),
		SRMAC:    bytes.Repeat([]byte{0x33}, 16),
		DEK:      bytes.Repeat([]byte{0x44}, 16),
		MACChain: make([]byte, 16),
	}

	scHost := NewS16(keys, LevelFull)

	cardKeys := &kdf.SessionKeys{
		SENC:     append([]byte{}, keys.SENC...),
		SMAC:     append([]byte{}, keys.SMAC...),
		SRMAC:    append([]byte{}, keys.SRMAC...),
		DEK:      append([]byte{}, keys.DEK...),
		MACChain: make([]byte, 16),
	}
	scCard := NewS16(cardKeys, LevelFull)

	// Wrap a command on the host side.
	plainData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	cmd := &apdu.Command{CLA: 0x80, INS: 0xDA, P1: 0x01, P2: 0x02, Data: plainData, Le: -1}
	wrapped, err := scHost.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Verify the wrapped data contains a 16-byte MAC (not 8).
	// Encrypted payload is 16 bytes (6 data + 0x80 padding = 16),
	// plus 16-byte MAC = 32 total.
	if len(wrapped.Data) != 32 {
		t.Errorf("S16 wrapped data length: got %d, want 32 (16 enc + 16 mac)", len(wrapped.Data))
	}

	// Simulate card side: verify C-MAC, build encrypted response, add R-MAC.
	// First verify the C-MAC using the card channel.
	receivedMAC := wrapped.Data[len(wrapped.Data)-FullMACLen:]
	encData := wrapped.Data[:len(wrapped.Data)-FullMACLen]

	var macInput []byte
	macInput = append(macInput, scCard.macChain...)
	macInput = append(macInput, wrapped.CLA, wrapped.INS, wrapped.P1, wrapped.P2)
	macInput = append(macInput, byte(len(wrapped.Data)))
	macInput = append(macInput, encData...)
	expectedCMAC, _ := cmac.AESCMAC(cardKeys.SMAC, macInput)

	if !bytes.Equal(receivedMAC, expectedCMAC[:FullMACLen]) {
		t.Fatalf("S16 C-MAC verification failed on card side")
	}

	// Update card's MAC chain.
	scCard.SetMACChain(expectedCMAC)

	// Card decrypts command data.
	decrypted, err := scCard.DecryptCommand(encData)
	if err != nil {
		t.Fatalf("card decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plainData) {
		t.Errorf("decrypted data mismatch: got %X, want %X", decrypted, plainData)
	}

	// Card builds and wraps a response.
	cardResp := &apdu.Response{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}
	wrappedResp, err := scCard.WrapResponse(cardResp)
	if err != nil {
		t.Fatalf("card WrapResponse: %v", err)
	}

	// Host unwraps the response — this is the critical test.
	// Before the fix, this would ALWAYS fail in S16 mode.
	unwrappedResp, err := scHost.Unwrap(wrappedResp)
	if err != nil {
		t.Fatalf("S16 Unwrap failed (this was the bug): %v", err)
	}

	if !bytes.Equal(unwrappedResp.Data, cardResp.Data) {
		t.Errorf("unwrapped response data mismatch: got %X, want %X",
			unwrappedResp.Data, cardResp.Data)
	}

	t.Logf("S16 round-trip passed: %d bytes plaintext, %d bytes wrapped command",
		len(plainData), len(wrapped.Data))
}

// ============================================================
// Regression: S16 Unwrap must compare full 16-byte MAC, not 8.
//
// Construct a response with a correct first-8-bytes but wrong
// last-8-bytes of the MAC. Before the fix this would have been
// accepted (only first 8 compared). After the fix it must reject.
// ============================================================

func TestS16_RejectsPartialMACMatch(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0x11}, 16),
		SMAC:     bytes.Repeat([]byte{0x22}, 16),
		SRMAC:    bytes.Repeat([]byte{0x33}, 16),
		DEK:      bytes.Repeat([]byte{0x44}, 16),
		MACChain: make([]byte, 16),
	}

	sc := NewS16(keys, LevelRMAC) // R-MAC only, no encryption

	// Build a valid R-MAC for known data.
	responseData := []byte{0xAA, 0xBB, 0xCC}
	var macInput []byte
	macInput = append(macInput, sc.macChain...)
	macInput = append(macInput, responseData...)
	macInput = append(macInput, 0x90, 0x00)

	validMAC, _ := cmac.AESCMAC(keys.SRMAC, macInput)

	// Corrupt the last 8 bytes of the MAC, keeping the first 8 intact.
	corruptMAC := make([]byte, 16)
	copy(corruptMAC, validMAC)
	for i := 8; i < 16; i++ {
		corruptMAC[i] ^= 0xFF
	}

	var respData []byte
	respData = append(respData, responseData...)
	respData = append(respData, corruptMAC...)

	resp := &apdu.Response{Data: respData, SW1: 0x90, SW2: 0x00}
	_, err := sc.Unwrap(resp)
	if err == nil {
		t.Fatal("S16 Unwrap should have rejected response with corrupted last 8 MAC bytes")
	}
}

// TestEmptyData_PadAndEncrypt_Default confirms the default empty-data
// encryption behavior pads with 0x80||0x00*15 and encrypts as one
// AES block. Matches yubikit's ScpState.encrypt:
//
//	msg = data + b"\x80" + 0-padding to 16 bytes; encrypt.
//
// Earlier the code skipped encryption entirely for empty data, which
// is what GP §6.2.4 literally says, but YubiKey rejects that. We now
// default to EmptyDataPadAndEncrypt and have a fallback
// (EmptyDataNoOp) for cards that follow the literal spec.
func TestEmptyData_PadAndEncrypt_Default(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}
	sc := New(keys, LevelFull)
	// Default policy is EmptyDataPadAndEncrypt; verify.
	if sc.EmptyDataEncryption != EmptyDataPadAndEncrypt {
		t.Errorf("default EmptyDataEncryption = %v, want EmptyDataPadAndEncrypt", sc.EmptyDataEncryption)
	}

	cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Data: nil, Le: -1}
	wrapped, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Encrypted block (16 bytes) + truncated MAC (8 bytes) = 24 bytes.
	// If we had skipped encryption, the data field would be just the
	// 8-byte MAC.
	if len(wrapped.Data) != 24 {
		t.Errorf("wrapped data length = %d, want 24 (16 encrypted + 8 MAC) under EmptyDataPadAndEncrypt",
			len(wrapped.Data))
	}
}

func TestEmptyData_NoOp_SkipsEncryption(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}
	sc := New(keys, LevelFull)
	sc.EmptyDataEncryption = EmptyDataNoOp

	cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Data: nil, Le: -1}
	wrapped, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// NoOp path skips encryption: data field is just the 8-byte MAC.
	if len(wrapped.Data) != 8 {
		t.Errorf("wrapped data length = %d, want 8 (MAC only) under EmptyDataNoOp",
			len(wrapped.Data))
	}
}

// TestEmptyData_BothModes_AdvanceCounter confirms both empty-data
// policies still advance the encryption counter, including NoOp,
// which advances the counter without producing ciphertext.
func TestEmptyData_BothModes_AdvanceCounter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy EmptyDataPolicy
	}{
		{"PadAndEncrypt", EmptyDataPadAndEncrypt},
		{"NoOp", EmptyDataNoOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := &kdf.SessionKeys{
				SENC:     bytes.Repeat([]byte{0xAA}, 16),
				SMAC:     bytes.Repeat([]byte{0xBB}, 16),
				SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
				DEK:      bytes.Repeat([]byte{0xDD}, 16),
				MACChain: make([]byte, 16),
			}
			sc := New(keys, LevelFull)
			sc.EmptyDataEncryption = tc.policy

			before := sc.encCounter
			cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, Data: nil, Le: -1}
			if _, err := sc.Wrap(cmd); err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if sc.encCounter != before+1 {
				t.Errorf("counter not advanced under %s: before=%d after=%d", tc.name, before, sc.encCounter)
			}
		})
	}
}

// TestEmptyDataPolicy_ZeroValueIsPadAndEncrypt pins the default
// behavior of an unset EmptyDataEncryption field. Callers rely on
// the zero value matching the verified card profile; if a future
// change reorders the iota the default flips silently and every
// empty-data command goes out wrong.
func TestEmptyDataPolicy_ZeroValueIsPadAndEncrypt(t *testing.T) {
	var p EmptyDataPolicy
	if p != EmptyDataPadAndEncrypt {
		t.Errorf("zero-value EmptyDataPolicy = %v, want EmptyDataPadAndEncrypt = %v",
			p, EmptyDataPadAndEncrypt)
	}
}

// TestWrap_LogicalChannelEncoding confirms Wrap sets the right
// secure-messaging bit per the CLA's class encoding. The naive
// "cmd.CLA | 0x04" treatment that the helper replaces would silently
// re-route logical channel 4 (CLA 0x40) to logical channel 8 (CLA
// 0x44), turning a "missing channel" failure on the card into a
// "wrong channel" failure that's far harder to diagnose.
//
// This test asserts the wire CLA round-trips through Wrap and
// re-decoding back to the original logical channel.
func TestWrap_LogicalChannelEncoding(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0x11}, 16),
		SMAC:     bytes.Repeat([]byte{0x22}, 16),
		SRMAC:    bytes.Repeat([]byte{0x33}, 16),
		DEK:      bytes.Repeat([]byte{0x44}, 16),
		MACChain: make([]byte, 16),
	}

	tests := []struct {
		name        string
		cla         byte
		wantChannel int
		wantSMSet   bool
	}{
		{"basic channel 0 first interindustry", 0x00, 0, true},
		{"basic channel 0 proprietary", 0x80, 0, true},
		{"basic channel 1 first interindustry", 0x01, 1, true},
		{"basic channel 3 proprietary", 0x83, 3, true},
		{"further channel 4", 0x40, 4, true},
		{"further channel 8", 0x44, 8, true},
		{"further channel 19", 0x4F, 19, true},
		// Chaining preserved
		{"basic channel 0 chained", 0x10, 0, true},
		{"further channel 4 chained", 0x50, 4, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := New(keys, LevelFull)
			cmd := &apdu.Command{
				CLA: tt.cla, INS: 0xCA, P1: 0x00, P2: 0x00,
				Data: []byte{0x01, 0x02}, Le: -1,
			}
			wrapped, err := sc.Wrap(cmd)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if got := LogicalChannel(wrapped.CLA); got != tt.wantChannel {
				t.Errorf("wrapped CLA %#02x decoded channel %d, want %d (original CLA %#02x)",
					wrapped.CLA, got, tt.wantChannel, tt.cla)
			}
			if got := IsSecureMessaging(wrapped.CLA); got != tt.wantSMSet {
				t.Errorf("wrapped CLA %#02x SM flag %v, want %v", wrapped.CLA, got, tt.wantSMSet)
			}
			// Chaining bit preserved
			if IsCommandChaining(tt.cla) != IsCommandChaining(wrapped.CLA) {
				t.Errorf("chaining bit not preserved: original %#02x -> wrapped %#02x",
					tt.cla, wrapped.CLA)
			}
		})
	}
}

// TestResponseIsSecureMessagingProtected covers the GP SCP03 §6.2.4
// classification of which response status words carry secure-
// messaging protection. The helper feeds Transmit's gating decision:
// 9000 and warning 62XX/63XX go through Unwrap (R-MAC verified);
// error status words (6Axx, 6Bxx, 6Cxx, 6Dxx, 6Exx, 6Fxx) pass
// through unprotected.
func TestResponseIsSecureMessagingProtected(t *testing.T) {
	tests := []struct {
		sw1, sw2 byte
		want     bool
		note     string
	}{
		// Success and warnings — protected
		{0x90, 0x00, true, "SW=9000"},
		{0x62, 0x00, true, "SW=6200 warning, NV memory unchanged"},
		{0x62, 0x82, true, "SW=6282 warning, end of file before Le"},
		{0x62, 0xFF, true, "SW=62FF arbitrary 62xx warning"},
		{0x63, 0x00, true, "SW=6300 warning, NV memory changed"},
		{0x63, 0xC0, true, "SW=63C0 warning"},
		{0x63, 0xCF, true, "SW=63CF warning, last verification"},

		// Errors — unprotected
		{0x67, 0x00, false, "SW=6700 wrong length"},
		{0x69, 0x82, false, "SW=6982 security status not satisfied"},
		{0x69, 0x85, false, "SW=6985 conditions of use not satisfied"},
		{0x6A, 0x80, false, "SW=6A80 incorrect data"},
		{0x6A, 0x88, false, "SW=6A88 referenced data not found"},
		{0x6B, 0x00, false, "SW=6B00 wrong P1/P2"},
		{0x6C, 0x10, false, "SW=6C10 Le too small"},
		{0x6D, 0x00, false, "SW=6D00 INS not supported"},
		{0x6E, 0x00, false, "SW=6E00 CLA not supported"},
		{0x6F, 0x00, false, "SW=6F00 no precise diagnosis"},
		// SW1 < 0x62 also unprotected (proprietary procedure bytes)
		{0x61, 0x00, false, "SW=6100 GET RESPONSE indicator"},
	}
	for _, tt := range tests {
		got := ResponseIsSecureMessagingProtected(tt.sw1, tt.sw2)
		if got != tt.want {
			t.Errorf("ResponseIsSecureMessagingProtected(%#02x, %#02x) = %v, want %v (%s)",
				tt.sw1, tt.sw2, got, tt.want, tt.note)
		}
	}
}

// TestUnwrap_WarningSW_IsRMACVerified composes a card response with
// SW=6282 (warning, end of file before Le) carrying a correctly-
// computed R-MAC, and confirms Unwrap accepts it and surfaces the
// warning to the caller without tearing down the channel.
//
// This is the positive companion to the error-status-word test in
// session/error_status_word_test.go: the R-MAC gate must not be too
// permissive (errors must pass through) but it also must not be too
// restrictive (warnings must be MAC-verified per spec). Without
// this test, a regression that excluded 62XX/63XX from the
// "protected" set would be invisible — the 9000 path covers
// success, the error tests cover errors, but warnings sit between.
func TestUnwrap_WarningSW_IsRMACVerified(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}

	sc := New(keys, LevelCMAC|LevelRMAC)

	// Establish a non-zero MAC chain by wrapping a command first.
	// Without this, the R-MAC input includes an all-zero chain,
	// which is technically valid but doesn't exercise the chained
	// case.
	if _, err := sc.Wrap(&apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Le: 0}); err != nil {
		t.Fatalf("Wrap (priming): %v", err)
	}

	// Compose a 6282 response with a valid R-MAC.
	responseData := []byte{0x55, 0x66, 0x77}
	const sw1, sw2 byte = 0x62, 0x82

	var macInput []byte
	macInput = append(macInput, sc.macChain...)
	macInput = append(macInput, responseData...)
	macInput = append(macInput, sw1, sw2)
	mac, err := cmac.AESCMAC(keys.SRMAC, macInput)
	if err != nil {
		t.Fatalf("AESCMAC: %v", err)
	}

	var respData []byte
	respData = append(respData, responseData...)
	respData = append(respData, mac[:MACLen]...)

	resp := &apdu.Response{Data: respData, SW1: sw1, SW2: sw2}

	// Gating helper says this is protected.
	if !ResponseIsSecureMessagingProtected(sw1, sw2) {
		t.Fatalf("warning SW %02X%02X must be classified as protected", sw1, sw2)
	}

	// Unwrap accepts the response.
	out, err := sc.Unwrap(resp)
	if err != nil {
		t.Fatalf("Unwrap rejected a correctly-MAC'd warning response: %v", err)
	}
	if out.SW1 != sw1 || out.SW2 != sw2 {
		t.Errorf("Unwrap returned SW=%02X%02X, want %02X%02X", out.SW1, out.SW2, sw1, sw2)
	}
	if !bytes.Equal(out.Data, responseData) {
		t.Errorf("Unwrap returned data %x, want %x", out.Data, responseData)
	}
}

// TestUnwrap_WarningSW_TamperedMAC_Rejected confirms that the
// warning-protected path also catches tampering: a 62XX response
// whose R-MAC fails verification must be rejected by Unwrap, not
// passed through as if it were an unprotected error SW. Without
// this, a regression that broadened "unprotected" to include
// warnings would silently downgrade MITM detection.
func TestUnwrap_WarningSW_TamperedMAC_Rejected(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}

	sc := New(keys, LevelCMAC|LevelRMAC)

	// Compose a 6300 response with a deliberately-wrong MAC.
	responseData := []byte{0x11, 0x22, 0x33}
	bogusMAC := bytes.Repeat([]byte{0xEE}, MACLen)

	var respData []byte
	respData = append(respData, responseData...)
	respData = append(respData, bogusMAC...)

	resp := &apdu.Response{Data: respData, SW1: 0x63, SW2: 0x00}
	if _, err := sc.Unwrap(resp); err == nil {
		t.Fatal("Unwrap accepted a 6300 response with an invalid R-MAC; warning SWs must be MAC-verified per GP SCP03 §6.2.4")
	}
}

// TestWrap_LogicalChannel_FullRoundTrip exercises wrap → card-side
// MAC verification → response wrap → host-side unwrap across the
// logical channels real cards use. The existing
// TestWrapUnwrapRoundTrip covers basic channel 0 only because the
// in-tree mocks live there; this fills the gap the README's
// "expansion targets" section names.
//
// Each sub-test:
//
//  1. Host wraps a command on the named logical channel.
//  2. The wrapped CLA is asserted to encode the expected channel and
//     to have the spec-correct SM bit position (0x04 for
//     first-interindustry/proprietary, 0x20 for further-interindustry).
//  3. The MAC chain after the host's wrap is captured.
//  4. A "card" SecureChannel re-derives the same MAC chain by
//     verifying the host's MAC with proper Lc encoding (matches the
//     extended-length form used by Wrap when wrapped data > 255 bytes).
//  5. The card builds a response, wraps it, the host unwraps it.
//  6. Both sides' MAC chains advance in lockstep.
//
// A regression in Wrap that miscoded SM-bit position for further-
// interindustry CLAs (the naive |= 0x04 fallback) would surface as
// either an SM-bit-not-set assertion or a MAC verification failure
// because the wrapped CLA would no longer match what Wrap MAC'd.
func TestWrap_LogicalChannel_FullRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		cla       byte
		wantChan  int
		wantSMBit byte // 0x04 or 0x20
	}{
		{"basic-channel 1", 0x01, 1, 0x04},
		{"basic-channel 3 proprietary", 0x83, 3, 0x04},
		{"further-channel 4", 0x40, 4, 0x20},
		{"further-channel 8", 0x44, 8, 0x20},
		{"further-channel 19", 0x4F, 19, 0x20},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostKeys := freshSessionKeys(0xAA)
			cardKeys := freshSessionKeys(0xAA) // same material, separate state
			scHost := New(hostKeys, LevelFull)
			scCard := New(cardKeys, LevelFull)

			// Host wraps a small command on the chosen logical channel.
			plain := []byte{0x01, 0x02, 0x03, 0x04}
			cmd := &apdu.Command{
				CLA: tc.cla, INS: 0xCA, P1: 0x00, P2: 0x00,
				Data: plain, Le: -1,
			}
			wrapped, err := scHost.Wrap(cmd)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}

			// CLA encoding assertions.
			if got := LogicalChannel(wrapped.CLA); got != tc.wantChan {
				t.Errorf("wrapped CLA %#02x → channel %d, want %d", wrapped.CLA, got, tc.wantChan)
			}
			if wrapped.CLA&tc.wantSMBit == 0 {
				t.Errorf("wrapped CLA %#02x missing SM bit %#02x", wrapped.CLA, tc.wantSMBit)
			}

			// Card verifies the MAC and decrypts.
			plainOnCard, err := simulateCardUnwrap(t, scCard, wrapped, hostKeys.SMAC)
			if err != nil {
				t.Fatalf("card-side unwrap: %v", err)
			}
			if !bytes.Equal(plainOnCard, plain) {
				t.Errorf("plaintext mismatch on card: got %X want %X", plainOnCard, plain)
			}

			// Card crafts a small response, wraps it, host unwraps.
			respPlain := []byte{0x10, 0x20, 0x30}
			respIn := &apdu.Response{Data: respPlain, SW1: 0x90, SW2: 0x00}
			respWrapped, err := scCard.WrapResponse(respIn)
			if err != nil {
				t.Fatalf("card WrapResponse: %v", err)
			}
			respOut, err := scHost.Unwrap(respWrapped)
			if err != nil {
				t.Fatalf("host Unwrap: %v", err)
			}
			if !bytes.Equal(respOut.Data, respPlain) {
				t.Errorf("response plaintext mismatch: got %X want %X", respOut.Data, respPlain)
			}

			// Both MAC chains must have advanced identically.
			if !bytes.Equal(scHost.macChain, scCard.macChain) {
				t.Errorf("MAC chains diverged: host=%X card=%X", scHost.macChain, scCard.macChain)
			}
		})
	}
}

// TestWrap_CommandChaining_PreservedOnLogicalChannel confirms the
// command-chaining bit (CLA |= 0x10) survives Wrap on non-zero
// logical channels. A naive implementation that masked CLA before
// re-applying the SM bit would lose chaining on logical channel 4+
// silently.
func TestWrap_CommandChaining_PreservedOnLogicalChannel(t *testing.T) {
	cases := []struct {
		name      string
		cla       byte
		wantSMBit byte
	}{
		{"basic-channel 0 chained", 0x10, 0x04},
		{"basic-channel 2 chained", 0x12, 0x04},
		{"further-channel 4 chained", 0x50, 0x20},
		{"further-channel 19 chained", 0x5F, 0x20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := New(freshSessionKeys(0xBB), LevelFull)
			cmd := &apdu.Command{
				CLA: tc.cla, INS: 0xDB, P1: 0x00, P2: 0x00,
				Data: []byte{0xAA}, Le: -1,
			}
			wrapped, err := sc.Wrap(cmd)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if !IsCommandChaining(wrapped.CLA) {
				t.Errorf("chaining bit lost: original CLA %#02x → wrapped %#02x", tc.cla, wrapped.CLA)
			}
			if wrapped.CLA&tc.wantSMBit == 0 {
				t.Errorf("SM bit %#02x not set on wrapped CLA %#02x", tc.wantSMBit, wrapped.CLA)
			}
			// Original logical channel preserved.
			if LogicalChannel(wrapped.CLA) != LogicalChannel(tc.cla) {
				t.Errorf("logical channel changed: %d → %d", LogicalChannel(tc.cla), LogicalChannel(wrapped.CLA))
			}
		})
	}
}

// TestWrap_ExtendedLength_OnFurtherChannel exercises a >255-byte
// payload wrapped on logical channel 4 (further-interindustry).
// This is the path that exposed a MAC-input encoding bug in
// mockcard during PR #54 — the host's Lc encoding switches to the
// extended form (0x00 || hi || lo) at the 255-byte threshold and
// any verifier that doesn't track that produces a MAC mismatch.
//
// At the channel layer (no mock involved), the test verifies
// Wrap sets the apdu.Command.ExtendedLength flag so downstream
// transports use the 7-byte header form, and that the wrap/unwrap
// round-trip works when both sides use the same SecureChannel logic.
func TestWrap_ExtendedLength_OnFurtherChannel(t *testing.T) {
	hostKeys := freshSessionKeys(0xCC)
	cardKeys := freshSessionKeys(0xCC)
	scHost := New(hostKeys, LevelFull)
	scCard := New(cardKeys, LevelFull)

	// 300 bytes plaintext → after pad+encrypt+MAC, well over 255
	// bytes wrapped; Wrap must select the extended-length form.
	plain := bytes.Repeat([]byte{0x42}, 300)
	cmd := &apdu.Command{
		CLA: 0x40, // logical channel 4
		INS: 0xDA, P1: 0x00, P2: 0x00,
		Data: plain, Le: -1,
	}
	wrapped, err := scHost.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !wrapped.ExtendedLength {
		t.Errorf("Wrap did not set ExtendedLength on a %d-byte payload (wrapped data %d bytes)",
			len(plain), len(wrapped.Data))
	}
	if got := LogicalChannel(wrapped.CLA); got != 4 {
		t.Errorf("logical channel changed: want 4 got %d", got)
	}

	// Card-side verification using the same Lc encoding rules.
	plainOnCard, err := simulateCardUnwrap(t, scCard, wrapped, hostKeys.SMAC)
	if err != nil {
		t.Fatalf("card unwrap: %v", err)
	}
	if !bytes.Equal(plainOnCard, plain) {
		t.Errorf("decrypted payload mismatch (lengths got=%d want=%d)", len(plainOnCard), len(plain))
	}
}

// freshSessionKeys returns SessionKeys with all five 16-byte keys
// filled with the given byte. Two calls with the same fill produce
// independent state structs that share key material — the standard
// pattern for simulating host-vs-card halves of the channel.
func freshSessionKeys(fill byte) *kdf.SessionKeys {
	return &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{fill}, 16),
		SMAC:     bytes.Repeat([]byte{fill}, 16),
		SRMAC:    bytes.Repeat([]byte{fill}, 16),
		DEK:      bytes.Repeat([]byte{fill}, 16),
		MACChain: make([]byte, 16),
	}
}

// simulateCardUnwrap reproduces the card-side processing of a wrapped
// command: verify the C-MAC using the same Lc encoding the host
// used (extended form when wrapped data > 255 bytes), advance the
// MAC chain, and decrypt the payload. Returns the plaintext.
//
// This is a test helper, not a piece of production code; the mock
// card's processSecure is the production-shaped equivalent.
func simulateCardUnwrap(t *testing.T, scCard *SecureChannel, wrapped *apdu.Command, smacKey []byte) ([]byte, error) {
	t.Helper()
	macSize := scCard.MACSize()
	if len(wrapped.Data) < macSize {
		return nil, fmt.Errorf("wrapped data too short for MAC")
	}
	receivedMAC := wrapped.Data[len(wrapped.Data)-macSize:]
	encData := wrapped.Data[:len(wrapped.Data)-macSize]

	var macInput []byte
	macInput = append(macInput, scCard.macChain...)
	macInput = append(macInput, wrapped.CLA, wrapped.INS, wrapped.P1, wrapped.P2)
	if len(wrapped.Data) > 0xFF {
		macInput = append(macInput, 0x00, byte(len(wrapped.Data)>>8), byte(len(wrapped.Data)))
	} else {
		macInput = append(macInput, byte(len(wrapped.Data)))
	}
	macInput = append(macInput, encData...)

	expectedMAC, err := cmac.AESCMAC(smacKey, macInput)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expectedMAC[:macSize], receivedMAC) {
		return nil, fmt.Errorf("MAC mismatch")
	}
	scCard.macChain = expectedMAC

	if len(encData) == 0 {
		_, _ = scCard.DecryptCommand(nil)
		return nil, nil
	}
	return scCard.DecryptCommand(encData)
}
