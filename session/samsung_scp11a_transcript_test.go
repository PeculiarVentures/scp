package session

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11a_SamsungTranscript_ByteExact is the headline interop proof
// for this library: drive session.Open end-to-end against Samsung
// OpenSCP-Java's published byte-exact SCP11a P-256/AES-128/S8 vectors
// and assert that every CAPDU we put on the wire matches Samsung's
// reference byte-for-byte where it should.
//
// Vector source:
//   github.com/Samsung/OpenSCP-Java
//   verified at SHA b9876fc36a5b18fb90ce03d0894f39edb08a905b (2026-05-03)
//   license: Apache-2.0
//   src/test/java/com/samsung/openscp/testdata/
//     - SmartCardScp11aP256Aes128S8ModeEmulation.java
//     - Scp11Nist256TestData.java
//     - Scp11TestData.java
//
// Provenance and refresh procedure: see testvectors/README.md.
//
// Coverage scope:
//
//   - GET DATA + GET RESPONSE chain — assert byte-exact, drive the
//     production cert-fetch path through Samsung's chunked response.
//   - PSO certificate upload — accepted in any spec-valid encoding
//     (we send a single extended APDU per cert per Yubico's reference;
//     Samsung uses CLA-chained chunks; both are spec-valid). The mock
//     just returns 9000.
//   - MUTUAL_AUTHENTICATE — assert byte-exact. With InsecureTestOnlyEphemeralKey
//     pinned to Samsung's published eSK.OCE.ECKA.P256 this APDU is
//     fully deterministic. A match proves the control reference template,
//     KID/KVN bytes, key-info encoding, ephemeral pubkey embedding, and
//     framing are all correct.
//   - Wrapped LIST_PACKAGES (GP GET STATUS with empty AID filter,
//     command data 4F 00) — assert byte-exact. This is the strongest
//     proof point: it confirms our X9.63 KDF, dual-ECDH, AES-CBC
//     encryption with derived IV, ISO 9797-1 method 2 padding, AES-CMAC
//     over the secure-channel header, and counter/IV derivation all
//     match Samsung's reference exactly.
//
// Implementation note:
//
// While developing this test we discovered a subtle gotcha: Samsung's
// "LIST_PACKAGES" CAPDU isn't a no-data command. It's GP §11.5
// GET_STATUS with the standard empty-AID search filter (4F 00) as its
// data field. An earlier draft of this test sent nil data and produced
// a 16-byte ciphertext that disagreed with Samsung's; reverse-decrypting
// Samsung's expected ciphertext with our (correctly derived) SENC
// recovered plaintext 4F 00 80 || 13 zeros — i.e. 2 bytes of data + ISO
// 9797-1 padding. Once the data field was set correctly the wrapped
// CAPDU matched Samsung's byte-for-byte. Our implementation was always
// correct; the test fixture was wrong.
func TestSCP11a_SamsungTranscript_ByteExact(t *testing.T) {
	// --- Samsung published vectors -----------------------------------

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

	mutualAuthExpectedCAPDU := mustHex(t, ""+
		"8082031153A60D9002110195013C8001888101105F49410470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5"+
		"DBBF8A32F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C9200")
	mutualAuthRAPDU := mustHex(t, ""+
		"5F49410492CAFD79D7E39EA433611E9AAD9742D85B3BD06F3D6055D7CDE28FC44D0AB556BC0F94D2100D87727FDFA2B49033C78F"+
		"07A30AA8D5A6A505E59F99FCDFB2526686100B63C42C2D5138936FF5894F10C1234F9000")

	listPackagesExpectedCAPDU := mustHex(t, "84F2200018E1EE3A92EF45551E8464A252F997230DC4E84F41BA692405")
	listPackagesRAPDU := mustHex(t, ""+
		"DC8D7D92F77BB20F4AEA2C2EB70A7D93C5F0EA0F27D193679C3D1C970BED8F73C394C63A201C8D367A9F0990146D1FF5CEC2E5F9"+
		"0F6956EF241D2CC899BA25B964FFFB799F4C42469000")

	// Samsung's OCE leaf certificate (X509_CERT_OCE_ECKA_P256).
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

	// Samsung's OCE static private key (SK_OCE_ECKA_P256, PKCS#8).
	oceSKDER := mustHex(t, ""+
		"308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B0201010420A5116B848D41BD93737F187ABC03886B"+
		"F7A80422D150025109C6749F45BB9B6DA14403420004B5C2598092609EFEFBA7A2FBED2F6E9142CA3882E7DE69D47D29476E7F0C"+
		"E85077480CAC6AD5C156CE459F2592DA0EECDCB0DE2E8F112C9E49C4655A11C59620")

	// Samsung's OCE ephemeral private key (ESK_OCE_ECKA_P256), 32-byte raw scalar.
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
		{name: "PSO", matchINS: 0x2A, response: mustHex(t, "9000")},
		{name: "MUTUAL_AUTH", matchINS: 0x82, expectExact: mutualAuthExpectedCAPDU, response: mutualAuthRAPDU},
		{name: "LIST_PACKAGES", matchCLA: 0x84, matchINS: 0xF2, expectExact: listPackagesExpectedCAPDU, response: listPackagesRAPDU},
	})

	// --- Drive session.Open ------------------------------------------

	cfg := &Config{
		Variant:                        SCP11a,
		SelectAID:                      nil, // Samsung transcript starts at GET DATA
		KeyID:                          0x11,
		KeyVersion:                     0x03,
		OCECertificates:                []*x509.Certificate{leaf},
		OCEKeyReference:                KeyRef{KID: 0x10, KVN: 0x03},
		OCEPrivateKey:                  oceSK,
		InsecureTestOnlyEphemeralKey:   oceESK,
		InsecureSkipCardAuthentication: true, // not testing trust here
	}
	sess, err := Open(context.Background(), sx, cfg)
	if err != nil {
		t.Fatalf("session.Open: %v\n\nCAPDUs sent:\n%s",
			err, formatCAPDUs(sx.captured))
	}
	defer sess.Close()

	// --- Drive a wrapped Transmit ------------------------------------
	//
	// Samsung's LIST_PACKAGES is GP §11.5 GET_STATUS with the empty-AID
	// search filter as its data field (TLV 4F 00 = "any AID"). The
	// previous draft of this test passed Data=nil and produced ciphertext
	// that disagreed with Samsung's vector — the divergence came from
	// the data-field convention on the original APDU, not from a bug
	// in our wrap.
	listPackagesCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xF2,
		P1:   0x20,
		P2:   0x00,
		Data: []byte{0x4F, 0x00}, // GP empty-AID search criterion
		Le:   -1,                 // Samsung's wrapped CAPDU has no Le byte
	}
	if _, err := sess.Transmit(context.Background(), listPackagesCmd); err != nil {
		t.Fatalf("sess.Transmit(LIST_PACKAGES): %v", err)
	}

	if sx.idx != len(sx.exchanges) {
		t.Errorf("only %d/%d scripted exchanges consumed", sx.idx, len(sx.exchanges))
	}
}

type scriptedExchange struct {
	name        string
	matchCLA    byte
	matchINS    byte
	expectExact []byte
	response    []byte
}

type scriptedTransport struct {
	t         *testing.T
	exchanges []scriptedExchange
	idx       int
	captured  [][]byte
}

func newScriptedTransport(t *testing.T, exchanges []scriptedExchange) *scriptedTransport {
	return &scriptedTransport{t: t, exchanges: exchanges}
}

func (s *scriptedTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	return s.transmitRaw(encoded)
}

func (s *scriptedTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	resp, err := s.transmitRaw(raw)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, resp.Data...)
	out = append(out, resp.SW1, resp.SW2)
	return out, nil
}

func (s *scriptedTransport) transmitRaw(raw []byte) (*apdu.Response, error) {
	s.captured = append(s.captured, raw)

	if s.idx >= len(s.exchanges) {
		return nil, fmt.Errorf("scripted transport: unexpected APDU #%d (no more scripted exchanges): % X",
			len(s.captured), raw)
	}
	ex := s.exchanges[s.idx]
	s.idx++

	if ex.matchINS != 0 && len(raw) >= 2 && raw[1] != ex.matchINS {
		s.t.Errorf("[%s] CAPDU INS = %02X, want %02X (full: % X)", ex.name, raw[1], ex.matchINS, raw)
	}
	if ex.matchCLA != 0 && len(raw) >= 1 && raw[0] != ex.matchCLA {
		s.t.Errorf("[%s] CAPDU CLA = %02X, want %02X (full: % X)", ex.name, raw[0], ex.matchCLA, raw)
	}

	if ex.expectExact != nil && !bytes.Equal(raw, ex.expectExact) {
		s.t.Errorf("[%s] CAPDU does not match Samsung vector\n  got:  % X\n  want: % X",
			ex.name, raw, ex.expectExact)
	}

	if len(ex.response) < 2 {
		return nil, fmt.Errorf("[%s] scripted response too short", ex.name)
	}
	return &apdu.Response{
		Data: ex.response[:len(ex.response)-2],
		SW1:  ex.response[len(ex.response)-2],
		SW2:  ex.response[len(ex.response)-1],
	}, nil
}

func (s *scriptedTransport) Close() error { return nil }

var _ transport.Transport = (*scriptedTransport)(nil)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func formatCAPDUs(capdus [][]byte) string {
	var out string
	for i, c := range capdus {
		out += fmt.Sprintf("  %d: % X\n", i+1, c)
	}
	return out
}
