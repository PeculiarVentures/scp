package channel

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
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

// TestEmptyData_YubicoDefault confirms the default empty-data
// encryption behavior pads with 0x80||0x00*15 and encrypts as one
// AES block. Matches yubikit's ScpState.encrypt:
//
//   msg = data + b"\x80" + 0-padding to 16 bytes; encrypt.
//
// Earlier the code skipped encryption entirely for empty data, which
// is what GP §6.2.4 literally says, but YubiKey rejects that. We now
// default to Yubico's interpretation (EmptyDataYubico) and have a
// fallback (EmptyDataGPLiteral) for cards that follow the literal
// spec.
func TestEmptyData_YubicoDefault_PadsAndEncrypts(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}
	sc := New(keys, LevelFull)
	// Default policy is EmptyDataYubico — verify.
	if sc.EmptyDataEncryption != EmptyDataYubico {
		t.Errorf("default EmptyDataEncryption = %v, want EmptyDataYubico", sc.EmptyDataEncryption)
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
		t.Errorf("wrapped data length = %d, want 24 (16 encrypted + 8 MAC) under EmptyDataYubico",
			len(wrapped.Data))
	}
}

func TestEmptyData_GPLiteral_SkipsEncryption(t *testing.T) {
	keys := &kdf.SessionKeys{
		SENC:     bytes.Repeat([]byte{0xAA}, 16),
		SMAC:     bytes.Repeat([]byte{0xBB}, 16),
		SRMAC:    bytes.Repeat([]byte{0xCC}, 16),
		DEK:      bytes.Repeat([]byte{0xDD}, 16),
		MACChain: make([]byte, 16),
	}
	sc := New(keys, LevelFull)
	sc.EmptyDataEncryption = EmptyDataGPLiteral

	cmd := &apdu.Command{CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x00, Data: nil, Le: -1}
	wrapped, err := sc.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// GP-literal path skips encryption: data field is just the 8-byte MAC.
	if len(wrapped.Data) != 8 {
		t.Errorf("wrapped data length = %d, want 8 (MAC only) under EmptyDataGPLiteral",
			len(wrapped.Data))
	}
}

// TestEmptyData_BothModes_AdvanceCounter confirms both empty-data
// policies still advance the encryption counter — even GP-literal,
// which advances the counter without producing ciphertext.
func TestEmptyData_BothModes_AdvanceCounter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy EmptyDataPolicy
	}{
		{"Yubico", EmptyDataYubico},
		{"GPLiteral", EmptyDataGPLiteral},
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
