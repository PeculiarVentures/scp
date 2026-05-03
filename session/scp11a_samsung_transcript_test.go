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
	"github.com/PeculiarVentures/scp/tlv"
)

// Samsung's published OCE static private key (PKCS#8, P-256).
// Source: SamsungElectronicsCo/OpenSCP-Java
//
//	src/test/java/com/samsung/openscp/testdata/Scp11TestData.java
//	  SK_OCE_ECKA_P256
var refOCEStaticPrivP256, _ = hex.DecodeString(
	"308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B0201010420" +
		"A5116B848D41BD93737F187ABC03886BF7A80422D150025109C6749F45BB9B6DA1440342" +
		"0004B5C2598092609EFEFBA7A2FBED2F6E9142CA3882E7DE69D47D29476E7F0CE8507748" +
		"0CAC6AD5C156CE459F2592DA0EECDCB0DE2E8F112C9E49C4655A11C59620")

// Samsung's published OCE ephemeral scalar (raw 32-byte private key).
// Source: same file, ESK_OCE_ECKA_P256 PKCS#8 inner key.
var refOCEEphemPrivP256Scalar, _ = hex.DecodeString(
	"B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5")

// Samsung's expected MUTUAL_AUTHENTICATE CAPDU bytes.
// Source: SmartCardScp11aP256Aes128S8ModeEmulation.java
var refMutualAuthCAPDU_Samsung_11a, _ = hex.DecodeString(
	"8082031153A60D9002110195013C8001888101105F49410470B0BD7863E90E32DA5401188354D1F4" +
		"1999442FDFDCBA7472B7F1E5DBBF8A32F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9" +
		"CCAC8239C9200")

// Samsung's expected first wrapped LIST_PACKAGES (GET STATUS) CAPDU.
// Source: same file. Plaintext command is CLA=0x80 INS=0xF2 P1=0x20 P2=0x00,
// no data; channel wraps with derived session keys + verified-receipt-seeded
// MAC chain.
var refWrappedListPackagesCAPDU_Samsung, _ = hex.DecodeString(
	"84F2200018E1EE3A92EF45551E8464A252F997230DC4E84F41BA692405")

// Samsung's wrapped LIST_PACKAGES RAPDU (encrypted response + R-MAC + 9000).
var refWrappedListPackagesRAPDU_Samsung, _ = hex.DecodeString(
	"DC8D7D92F77BB20F4AEA2C2EB70A7D93C5F0EA0F27D193679C3D1C970BED8F73C394C63A201C8D367A9F0990146" +
		"D1FF5CEC2E5F90F6956EF241D2CC899BA25B964FFFB799F4C42469000")

// scriptedTransport drives session.Open by responding to each command
// based on its INS byte rather than position. Captures every CAPDU
// for byte-exact assertions on specific cryptographic-diagnostic
// commands (MUTUAL AUTHENTICATE; first wrapped command).
type scriptedTransport struct {
	getData []byte // BF21 cert store payload for INS=0xCA
	psoSW   []byte // RAPDU for INS=0x2A (typically 9000)
	mutAuth []byte // RAPDU for INS=0x82
	wrapped []byte // RAPDU for any post-handshake command
	sent    [][]byte
}

func (s *scriptedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	s.sent = append(s.sent, encoded)

	switch cmd.INS {
	case 0xCA:
		return &apdu.Response{Data: s.getData, SW1: 0x90, SW2: 0x00}, nil
	case 0x2A:
		return apdu.ParseResponse(s.psoSW)
	case 0x82, 0x88:
		return apdu.ParseResponse(s.mutAuth)
	default:
		return apdu.ParseResponse(s.wrapped)
	}
}

func (s *scriptedTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	s.sent = append(s.sent, raw)
	return nil, fmt.Errorf("scriptedTransport: TransmitRaw unsupported")
}
func (s *scriptedTransport) Close() error { return nil }

// TestSCP11a_SamsungTranscript_EndToEnd is the byte-exact integration
// proof of correctness for SCP11a end-to-end: drives session.Open
// against Samsung OpenSCP-Java's published P-256 / AES-128 / S8
// vectors, then sends a wrapped LIST_PACKAGES through the secure
// channel.
//
// The two byte-exact assertions:
//
//  1. The MUTUAL AUTHENTICATE CAPDU we send matches Samsung's
//     published expected bytes. This proves: TLV layout (5F49 EPK,
//     A6 control reference, 90/95/80/81 sub-tags), fixed-ephemeral
//     injection through the InsecureTestOnlyEphemeralKey seam, and
//     KID/KVN encoding all align.
//
//  2. The wrapped LIST_PACKAGES CAPDU matches Samsung's expected
//     bytes. This proves: KDF-derived session keys, receipt
//     verification, MAC-chain seeding from the verified receipt,
//     S8 truncation, AES-CBC ICV derivation, and channel.Wrap all
//     align with Samsung end-to-end.
//
// What is NOT byte-checked: GET DATA and PERFORM SECURITY OPERATION
// wire encoding. Both have multiple spec-valid encodings (extended
// APDU vs CLA-chained chunks); a byte-exact check there would force
// a wire format choice rather than testing protocol correctness.
//
// Vector source: SamsungElectronicsCo/OpenSCP-Java
//
//	src/test/java/com/samsung/openscp/SmartCardScp11aP256Aes128S8ModeEmulation.java
//	src/test/java/com/samsung/openscp/testdata/Scp11Nist256TestData.java
//	src/test/java/com/samsung/openscp/testdata/Scp11TestData.java
func TestSCP11a_SamsungTranscript_EndToEnd(t *testing.T) {
	oceCert, err := x509.ParseCertificate(refOCECertP256)
	if err != nil {
		t.Fatalf("parse OCE cert: %v", err)
	}
	oceSKAny, err := x509.ParsePKCS8PrivateKey(refOCEStaticPrivP256)
	if err != nil {
		t.Fatalf("parse OCE static key: %v", err)
	}
	oceSK, ok := oceSKAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("OCE static key type %T, want *ecdsa.PrivateKey", oceSKAny)
	}
	eskKey, err := ecdh.P256().NewPrivateKey(refOCEEphemPrivP256Scalar)
	if err != nil {
		t.Fatalf("parse OCE ephemeral key: %v", err)
	}

	// Wrap Samsung's SD cert in the BF21 cert-store TLV that our
	// getCardCertificate parses.
	bf21 := tlv.BuildConstructed(tlv.TagCertStore, tlv.Build(tlv.TagCertificate, refSDCertP256))
	xport := &scriptedTransport{
		getData: bf21.Encode(),
		psoSW:   []byte{0x90, 0x00},
		mutAuth: refMutualAuthRAPDU_11a,
		wrapped: refWrappedListPackagesRAPDU_Samsung,
	}

	sess, err := Open(context.Background(), xport, &Config{
		Variant:                        SCP11a,
		SelectAID:                      nil, // Samsung transcript starts at GET DATA
		KeyID:                          0x11,
		KeyVersion:                     0x03,
		OCECertificates:                []*x509.Certificate{oceCert},
		OCEKeyReference:                KeyRef{KID: 0x10, KVN: 0x03},
		OCEPrivateKey:                  oceSK,
		InsecureTestOnlyEphemeralKey:   eskKey,
		InsecureSkipCardAuthentication: true,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	// Find and assert the MUTUAL_AUTHENTICATE CAPDU.
	var gotMutAuth []byte
	for _, c := range xport.sent {
		if len(c) >= 2 && c[1] == 0x82 {
			gotMutAuth = c
			break
		}
	}
	if gotMutAuth == nil {
		t.Fatal("did not capture a MUTUAL AUTHENTICATE CAPDU in transcript")
	}
	if !bytes.Equal(gotMutAuth, refMutualAuthCAPDU_Samsung_11a) {
		t.Errorf("MUTUAL AUTHENTICATE CAPDU mismatch:\n  got:  %X\n  want: %X",
			gotMutAuth, refMutualAuthCAPDU_Samsung_11a)
	}

	// Now wrap LIST_PACKAGES through the established channel.
	// Now wrap LIST_PACKAGES through the established channel.
	//
	// The plaintext GP GET STATUS (INS=0xF2) command takes a TLV
	// search criteria in its data field: tag 0x4F (AID) with empty
	// length means "match any AID". This is the standard GP §11.4
	// form and what Samsung's test fixture uses; the AES-CBC
	// ciphertext + S8 MAC are computed over this 2-byte plaintext.
	sentBefore := len(xport.sent)
	_, transmitErr := sess.Transmit(context.Background(), &apdu.Command{
		CLA:  0x80,
		INS:  0xF2,
		P1:   0x20, // applications + supplementary security domains
		P2:   0x00,
		Data: []byte{0x4F, 0x00},
		Le:   -1,
	})
	// We may fail to UNWRAP Samsung's RAPDU if our session state
	// diverges from theirs (R-MAC won't verify). That's diagnostic in
	// itself. Either way, the wrapped CAPDU we put on the wire was
	// captured before unwrap was attempted, so we can still check it.
	if len(xport.sent) != sentBefore+1 {
		t.Fatalf("expected exactly 1 wrapped CAPDU, got %d new (transmit err: %v)",
			len(xport.sent)-sentBefore, transmitErr)
	}
	if !bytes.Equal(xport.sent[sentBefore], refWrappedListPackagesCAPDU_Samsung) {
		t.Errorf("wrapped LIST_PACKAGES CAPDU mismatch:\n  got:  %X\n  want: %X",
			xport.sent[sentBefore], refWrappedListPackagesCAPDU_Samsung)
	} else if transmitErr != nil {
		t.Errorf("wrapped CAPDU matched Samsung byte-exact, but unwrap of canned RAPDU failed: %v",
			transmitErr)
	}
}
