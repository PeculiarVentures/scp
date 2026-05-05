package scp11

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
)

// TestSCP11c_SamsungTranscript_ByteExact is the SCP11c companion to
// the SCP11a Samsung byte-exact test. It drives scp11.Open against
// Samsung OpenSCP-Java's published SCP11c P-256/AES-128/S8 vectors
// and asserts that every CAPDU we put on the wire matches Samsung's
// reference byte-for-byte where it should.
//
// SCP11c diverges from SCP11a in two visible places at the wire level:
//
//   - The session KID is 0x15 (vs SCP11a's 0x11), so the GET_DATA
//     control reference embeds 0x15 and the MUTUAL_AUTHENTICATE
//     control reference uses 0x15 with the OCE KVN.
//
//   - The MUTUAL_AUTHENTICATE P1 byte is 0x03 (vs SCP11a's 0x01).
//     P1 in SCP11 mutual-auth selects the variant flavor; SCP11c is
//     "mutual auth with offline scripting allowed" and the P1 bit
//     pattern reflects that.
//
// The card-side OCE-ECKA certificate, OCE static keys, and OCE
// ephemeral keys are identical to the SCP11a test fixture by
// design — Samsung exercises both variants against the same card
// state, isolating the protocol differences from the certificate
// chain. The wrapped LIST_PACKAGES bytes differ because the session
// keys are derived through the variant-dependent handshake.
//
// Vector source:
//
//	github.com/Samsung/OpenSCP-Java
//	verified at SHA b9876fc36a5b18fb90ce03d0894f39edb08a905b (2026-05-03)
//	license: Apache-2.0
//	src/test/java/com/samsung/openscp/testdata/
//	  - SmartCardScp11cP256Aes128S8ModeEmulation.java   (SCP11c-specific)
//	  - Scp11Nist256TestData.java                       (shared GET DATA)
//	  - Scp11TestData.java                              (shared OCE keys)
//
// Provenance and refresh procedure: see testvectors/README.md.
//
// Coverage scope:
//
//   - GET DATA + GET RESPONSE chain — byte-exact, drives the
//     production cert-fetch path through Samsung's chunked response.
//     The CAPDU differs from SCP11a only in the embedded KID byte
//     (0x15 vs 0x11).
//
//   - PSO certificate upload — accepted in any spec-valid encoding;
//     the mock just returns 9000 (same posture as the SCP11a test).
//
//   - MUTUAL_AUTHENTICATE — byte-exact, with the ephemeral key
//     pinned to Samsung's published eSK.OCE.ECKA.P256 so the
//     comparison is deterministic. A match proves P1=0x03 SCP11c
//     framing, the KID=0x15 control reference, and the rest of the
//     mutual-auth template.
//
//   - Wrapped LIST_PACKAGES — byte-exact. Strongest proof point:
//     confirms that our X9.63 KDF, dual-ECDH, AES-CBC encryption with
//     derived IV, ISO 9797-1 method-2 padding, AES-CMAC chaining, and
//     counter/IV derivation all match Samsung's reference for the
//     SCP11c variant.
func TestSCP11c_SamsungTranscript_ByteExact(t *testing.T) {
	// --- Samsung published vectors -----------------------------------
	//
	// GET DATA chunks are shared with the SCP11a transcript (the
	// card's BF21 certificate store is the same across SCP11a and
	// SCP11c emulations in Samsung's reference). They're inlined
	// here for self-containment rather than imported from the
	// SCP11a test, so refreshing one doesn't silently affect the
	// other.

	getDataChunk0 := mustHex(t, ""+
		"BF2182021430820210308201B5A00302010202146A994C23ECC7F71C16325F2CF93878D1B4327086300A06082A8648CE3D040302"+
		"3051310B3009060355040613024B52310B300906035504080C0253553110300E060355040A0C0753616D73756E67312330210603"+
		"5504030C1A43412D4B4C434320436572746966696361746520285445535429301E170D3235303230363130343634305A170D3236"+
		"303530393130343634305A304C310B3009060355040613024B52310B300906035504080C0253553110300E060355040A0C075361"+
		"6D73756E67311E301C06035504030C155344204365727469666963617465202854455354293059301306072A8648CE3D6100")
	getDataChunk1 := mustHex(t, ""+
		"020106082A8648CE3D030107034200044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5E6CD1F4D"+
		"D11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1EA370306E301D0603551D0E04160414CD7B897E3C1BC6FFAC"+
		"7F9595FB55AE66C3CE84AB301F0603551D230418301680149E216D9AEF4531670A5B83ADE5DED7FF6CD97B0F300E0603551D0F01"+
		"01FF040403020308301C0603551D200101FF04123010300E060C2A864886FC6B64000A02010A300A06082A8648CE3D0403020349"+
		"003046022100AE0814C3B4C715BFCF4DA365944DA532B241C98227184C99364DE3DD2563E803022100D46AB8C79B47526100")
	getDataChunk2 := mustHex(t, ""+
		"62B10487F0065CA8D720E3E275D87E516879DBE5CACDDE13559000")

	// SCP11c-specific MUTUAL_AUTHENTICATE: P1=0x03, KID=0x15 in the A6 control reference.
	mutualAuthExpectedCAPDU := mustHex(t, ""+
		"8082031553A60D9002110395013C8001888101105F49410470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5"+
		"DBBF8A32F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C9200")
	mutualAuthRAPDU := mustHex(t, ""+
		"5F4941044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5E6CD1F4DD11609E2100C033BBD723BE7"+
		"8B71477E64883EB41EC366713E44AF1E86100B9394B90AEC0BC62F1F024E6D748ADD9000")

	// SCP11c-derived session keys → SCP11c-specific wrapped LIST_PACKAGES bytes.
	listPackagesExpectedCAPDU := mustHex(t, "84F2200018D2AAA03B2F7B80150EEB1A62CE525FA9B98055B95E2E35A4")
	listPackagesRAPDU := mustHex(t, ""+
		"A05ADFADAF85CD3E9FCBBC05597FFA61B6328C799934B35A92AA3ABC3B7596FD6E77F30C5A7D6758A2636A26FF81C1A9643C189D"+
		"834565C153D34A1901B1D706411CE2DC076B51779000")

	// Samsung's OCE leaf certificate (X509_CERT_OCE_ECKA_P256), identical to the SCP11a fixture.
	oceLeafDER := mustHex(t, ""+
		"30820211308201B6A00302010202146DBC19AFE3782C7C0053F19E86DF2F0F00B559EA300A06082A8648CE3D0403023051310B30"+
		"09060355040613024B52310B300906035504080C0253553110300E060355040A0C0753616D73756E673123302106035504030C1A"+
		"43412D4B4C4F4320436572746966696361746520285445535429301E170D3235303230363130323135365A170D32363035303931"+
		"30323135365A304D310B3009060355040613024B52310B300906035504080C0253553110300E060355040A0C0753616D73756E67"+
		"311F301D06035504030C164F4345204365727469666963617465202854455354293059301306072A8648CE3D020106082A8648CE"+
		"3D03010703420004B5C2598092609EFEFBA7A2FBED2F6E9142CA3882E7DE69D47D29476E7F0CE85077480CAC6AD5C156CE459F25"+
		"92DA0EECDCB0DE2E8F112C9E49C4655A11C59620A370306E301D0603551D0E04160414E225C62F5E33CA02D23D9D83D0685B4EB2"+
		"FEBC11301F0603551D23041830168014851A6F60A6B45534647260877A357F3676C35686300E0603551D0F0101FF040403020308"+
		"301C0603551D200101FF04123010300E060C2A864886FC6B64000A020100300A06082A8648CE3D0403020349003046022100A0D2"+
		"76B639EE863758B5568ADFA9D3B7F3D906A557C4C7675607FC82A9596EC6022100D7044BDE4CB536055CF93D5C7FCF5C7C5298EB"+
		"1D4646357CE6515BC0CD9E10FF")
	oceSKDER := mustHex(t, ""+
		"308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B0201010420A5116B848D41BD93737F187ABC03886B"+
		"F7A80422D150025109C6749F45BB9B6DA14403420004B5C2598092609EFEFBA7A2FBED2F6E9142CA3882E7DE69D47D29476E7F0C"+
		"E85077480CAC6AD5C156CE459F2592DA0EECDCB0DE2E8F112C9E49C4655A11C59620")
	oceESKScalarHex := "B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5"

	// --- Parse keys and certificate ----------------------------------

	leaf, err := x509.ParseCertificate(oceLeafDER)
	if err != nil {
		t.Fatalf("parse OCE leaf: %v", err)
	}
	skAny, err := x509.ParsePKCS8PrivateKey(oceSKDER)
	if err != nil {
		t.Fatalf("parse OCE SK: %v", err)
	}
	oceSK, ok := skAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("OCE SK is not ECDSA: %T", skAny)
	}
	scalar, _ := hex.DecodeString(oceESKScalarHex)
	oceESK, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("parse OCE ESK: %v", err)
	}

	// --- Build the scripted transport --------------------------------

	sx := newScriptedTransport(t, []scriptedExchange{
		{name: "GET_DATA", matchINS: 0xCA, response: getDataChunk0},
		{name: "GET_RESPONSE_1", matchINS: 0xC0, response: getDataChunk1},
		{name: "GET_RESPONSE_2", matchINS: 0xC0, response: getDataChunk2},
		// Cert chained into 3 short APDUs; see SCP11a transcript
		// test for context on why the wire shape is chunked.
		{name: "PSO_chunk_1", matchCLA: 0x90, matchINS: 0x2A, response: mustHex(t, "9000")},
		{name: "PSO_chunk_2", matchCLA: 0x90, matchINS: 0x2A, response: mustHex(t, "9000")},
		{name: "PSO_chunk_final", matchCLA: 0x80, matchINS: 0x2A, response: mustHex(t, "9000")},
		{name: "MUTUAL_AUTH", matchINS: 0x82, expectExact: mutualAuthExpectedCAPDU, response: mutualAuthRAPDU},
		{name: "LIST_PACKAGES", matchCLA: 0x84, matchINS: 0xF2, expectExact: listPackagesExpectedCAPDU, response: listPackagesRAPDU},
	})

	// --- Drive scp11.Open ------------------------------------------

	cfg := &Config{
		Variant:                        SCP11c,
		SelectAID:                      nil,  // Samsung transcript starts at GET DATA
		KeyID:                          0x15, // SCP11c session KID per Samsung
		KeyVersion:                     0x03,
		OCECertificates:                []*x509.Certificate{leaf},
		OCEKeyReference:                KeyRef{KID: 0x10, KVN: 0x03},
		OCEPrivateKey:                  oceSK,
		InsecureTestOnlyEphemeralKey:   oceESK,
		InsecureSkipCardAuthentication: true, // not testing trust here
	}
	sess, err := Open(context.Background(), sx, cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v\n\nCAPDUs sent:\n%s",
			err, formatCAPDUs(sx.captured))
	}
	defer sess.Close()

	// --- Drive a wrapped Transmit ------------------------------------

	listPackagesCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xF2,
		P1:   0x20,
		P2:   0x00,
		Data: []byte{0x4F, 0x00}, // GP empty-AID search criterion
		Le:   -1,
	}
	if _, err := sess.Transmit(context.Background(), listPackagesCmd); err != nil {
		t.Fatalf("sess.Transmit(LIST_PACKAGES): %v", err)
	}

	if sx.idx != len(sx.exchanges) {
		t.Errorf("only %d/%d scripted exchanges consumed", sx.idx, len(sx.exchanges))
	}
}
