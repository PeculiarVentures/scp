package scp11

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/trust"
)

// TestSCP11a_SamsungTranscript_GPProprietary_CustomValidator drives
// scp11.Open against Samsung OpenSCP-Java's published SCP11a P-256
// / AES-128 / S8 transcript where the card's certificate store uses
// the GlobalPlatform proprietary cert format (7F21 wrapper containing
// a 7F49 SubjectPublicKey TLV) instead of standard X.509.
//
// This is the proof point for the trust.Policy.CustomValidator
// extension. The built-in X.509 chain validator cannot parse this
// store; only a caller-supplied validator that understands the
// GP-proprietary layout can extract the card's static public key.
// If a regression broke the CustomValidator dispatch path, or the
// post-validator P-256 / ECDH-convertibility checks, this test would
// fail end-to-end rather than at a synthetic assertion.
//
// Invariant being tested: against the same card state (same OCE
// keys, same card static key, same ephemeral key), the SCP11a
// handshake produces byte-identical output regardless of whether
// the cert store is X.509 or GP-proprietary. Samsung's two
// emulations confirm this — their MUTUAL_AUTHENTICATE and wrapped
// LIST_PACKAGES bytes match between SmartCardScp11aP256Aes128S8 and
// SmartCardScp11aGpP256Aes128S8. That isolates the cert-format
// difference from the protocol behavior, which is what makes this a
// clean test of the CustomValidator path: if our CustomValidator
// returns the right public key, the session will derive the same
// session keys as the X.509 path would, and the wrapped command
// bytes will match Samsung's reference.
//
// Vector source:
//
//	github.com/Samsung/OpenSCP-Java
//	verified at SHA b9876fc36a5b18fb90ce03d0894f39edb08a905b (2026-05-03)
//	license: Apache-2.0
//	src/test/java/com/samsung/openscp/testdata/
//	  - SmartCardScp11aGpP256Aes128S8ModeEmulation.java   (GP-proprietary)
//	  - Scp11Nist256TestData.java                         (shared GET DATA CAPDU)
//	  - Scp11TestData.java                                (shared OCE keys)
//
// Provenance and refresh procedure: see testvectors/README.md.
func TestSCP11a_SamsungTranscript_GPProprietary_CustomValidator(t *testing.T) {
	// --- Samsung published vectors -----------------------------------
	//
	// The GP-proprietary GET DATA response is a single chunk (no GET
	// RESPONSE chaining) because the proprietary cert is much smaller
	// than an X.509 cert. Inside the BF21 envelope is a 7F21 wrapper
	// containing GP-proprietary fields rather than a DER-encoded
	// X.509 certificate.

	getDataProprietaryRAPDU := mustHex(t, ""+
		"BF2181E57F2181E193146A994C23ECC7F71C16325F2CF93878D1B432708642149E216D9AEF4531670A5B83ADE5DED7FF6CD97B0F"+
		"5F2014CD7B897E3C1BC6FFAC7F9595FB55AE66C3CE84AB950200805F2404141C0C1F7F4946B041044F92A07D168C309959EED99E"+
		"288381DD192979CD452D8FBE1F163447979207C5E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"+
		"F001005F3747304502210084BD2834015556ACF7920BF4D599578133AE55118894B0DCDC3EAB45BA0D3DE8022065025536025DE2"+
		"A98D99758FA7A9E352A02AE3CF9B041BA90A0CE948F3FA60749000")

	// SCP11a MUTUAL_AUTHENTICATE bytes — identical to the X.509 SCP11a
	// transcript because the handshake derives from the same OCE static
	// key, same card static key, and same ephemeral key. The only thing
	// that differs between the X.509 and GP-proprietary emulations is
	// how the card publishes its static public key for retrieval; the
	// public key value itself is the same, and so is everything that
	// follows.
	mutualAuthExpectedCAPDU := mustHex(t, ""+
		"8082031153A60D9002110195013C8001888101105F49410470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5"+
		"DBBF8A32F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C9200")
	mutualAuthRAPDU := mustHex(t, ""+
		"5F49410492CAFD79D7E39EA433611E9AAD9742D85B3BD06F3D6055D7CDE28FC44D0AB556BC0F94D2100D87727FDFA2B49033C78F"+
		"07A30AA8D5A6A505E59F99FCDFB2526686100B63C42C2D5138936FF5894F10C1234F9000")

	listPackagesExpectedCAPDU := mustHex(t, "84F2200018E1EE3A92EF45551E8464A252F997230DC4E84F41BA692405")
	listPackagesRAPDU := mustHex(t, ""+
		"DC8D7D92F77BB20F4AEA2C2EB70A7D93C5F0EA0F27D193679C3D1C970BED8F73C394C63A201C8D367A9F0990146D1FF5CEC2"+
		"E5F90F6956EF241D2CC899BA25B964FFFB799F4C42469000")

	// Same OCE leaf and OCE static SK as the X.509 SCP11a fixture.
	// The OCE side is identical between Samsung's emulations; only
	// the card-side cert store differs.
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

	// --- Parse keys --------------------------------------------------

	leaf, err := x509.ParseCertificate(oceLeafDER)
	if err != nil {
		t.Fatalf("parse OCE leaf: %v", err)
	}
	skAny, err := x509.ParsePKCS8PrivateKey(oceSKDER)
	if err != nil {
		t.Fatalf("parse OCE SK: %v", err)
	}
	oceSK := skAny.(*ecdsa.PrivateKey)
	scalar, _ := hex.DecodeString(oceESKScalarHex)
	oceESK, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("parse OCE ESK: %v", err)
	}

	// --- Build the scripted transport --------------------------------
	//
	// Sequence (per Samsung's SmartCardScp11aGpP256Aes128S8ModeEmulation):
	//
	//   1. GET DATA  → BF21/7F21 GP-proprietary cert store (single chunk).
	//   2. PSO       → upload OCE cert (any spec-valid framing accepted;
	//                  Samsung uses GP CLA-chained chunks, we send one
	//                  extended-length APDU per cert per Yubico's
	//                  reference. Both are valid.)
	//   3. MUTUAL_AUTH → byte-exact match against the same handshake
	//                    bytes as the X.509 SCP11a fixture.
	//   4. LIST_PACKAGES → byte-exact match against the same wrapped
	//                      command as the X.509 SCP11a fixture.

	sx := newScriptedTransport(t, []scriptedExchange{
		{name: "GET_DATA", matchINS: 0xCA, response: getDataProprietaryRAPDU},
		{name: "PSO", matchINS: 0x2A, response: mustHex(t, "9000")},
		{name: "MUTUAL_AUTH", matchINS: 0x82, expectExact: mutualAuthExpectedCAPDU, response: mutualAuthRAPDU},
		{name: "LIST_PACKAGES", matchCLA: 0x84, matchINS: 0xF2, expectExact: listPackagesExpectedCAPDU, response: listPackagesRAPDU},
	})

	// --- The CustomValidator -----------------------------------------
	//
	// Parses Samsung's GP-proprietary cert format, extracts the card's
	// static public key, and returns it. This is the kind of validator
	// a real GP-proprietary integration would write.
	//
	// Trust model in this test: the validator pins the expected card
	// static-key tag positions and parses out the SEC1 uncompressed
	// point. A production validator would also verify the GP signature
	// over the cert against a known issuer key (the 5F37 TLV is the
	// signature; we don't verify it here because that requires the
	// issuer's public key, which is outside the scope of the byte-
	// exact test).
	//
	// Validator-call counter so the test asserts the dispatch path
	// actually fired. Without this assertion, a regression that
	// silently fell through to the X.509 path would produce a
	// confusing parse-error diagnostic instead of an obvious
	// "validator never ran" signal.
	var validatorCalled int

	gpProprietaryValidator := func(rawBF21 []byte) (*trust.Result, error) {
		validatorCalled++

		nodes, err := tlv.Decode(rawBF21)
		if err != nil {
			return nil, fmt.Errorf("decode BF21 envelope: %w", err)
		}

		// The 7F49 SubjectPublicKey is nested inside BF21 → 7F21 → 7F49.
		// tlv.Find searches recursively through all constructed tags.
		pubKey7F49 := tlv.Find(nodes, 0x7F49)
		if pubKey7F49 == nil {
			return nil, errors.New("BF21 store does not contain 7F49 SubjectPublicKey")
		}

		// Inside 7F49 (constructed) the SEC1 uncompressed point lives
		// in tag B0. The 7F49 envelope also contains a tag F0
		// configuration byte that we do not need.
		pointB0 := tlv.Find(pubKey7F49.Children, 0xB0)
		if pointB0 == nil {
			return nil, errors.New("7F49 does not contain B0 (uncompressed P-256 point)")
		}
		if len(pointB0.Value) != 65 || pointB0.Value[0] != 0x04 {
			return nil, fmt.Errorf(
				"B0 value is not a SEC1 uncompressed P-256 point: %d bytes, prefix %#02x",
				len(pointB0.Value), pointB0.Value[0])
		}

		x := new(big.Int).SetBytes(pointB0.Value[1:33])
		y := new(big.Int).SetBytes(pointB0.Value[33:65])

		return &trust.Result{
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		}, nil
	}

	// --- Drive scp11.Open ------------------------------------------

	cfg := &Config{
		Variant:                      SCP11a,
		SelectAID:                    nil,
		KeyID:                        0x11,
		KeyVersion:                   0x03,
		OCECertificates:              []*x509.Certificate{leaf},
		OCEKeyReference:              KeyRef{KID: 0x10, KVN: 0x03},
		OCEPrivateKey:                oceSK,
		InsecureTestOnlyEphemeralKey: oceESK,
		// Trust path: NOT InsecureSkipCardAuthentication. The
		// CustomValidator owns the trust decision. This is the
		// production-shaped configuration for GP-proprietary cards.
		CardTrustPolicy: &trust.Policy{
			CustomValidator: gpProprietaryValidator,
		},
	}
	sess, err := Open(context.Background(), sx, cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v\n\nCAPDUs sent:\n%s",
			err, formatCAPDUs(sx.captured))
	}
	defer sess.Close()

	// Validator must have run exactly once.
	if validatorCalled != 1 {
		t.Errorf("CustomValidator called %d times, want exactly 1", validatorCalled)
	}

	// --- Drive a wrapped Transmit ------------------------------------

	listPackagesCmd := &apdu.Command{
		CLA:  0x80,
		INS:  0xF2,
		P1:   0x20,
		P2:   0x00,
		Data: []byte{0x4F, 0x00},
		Le:   -1,
	}
	if _, err := sess.Transmit(context.Background(), listPackagesCmd); err != nil {
		t.Fatalf("sess.Transmit(LIST_PACKAGES): %v", err)
	}

	if sx.idx != len(sx.exchanges) {
		t.Errorf("only %d/%d scripted exchanges consumed", sx.idx, len(sx.exchanges))
	}
}

// TestSCP11a_GPProprietary_NonP256Key_Rejected confirms the post-
// validator P-256 invariant. A custom validator that returns a
// non-P-256 key (e.g. P-384) must be rejected by the session layer
// regardless of whether the validator itself thought the key was
// trustworthy. SCP11 ECDH cannot function on a non-P-256 key, so this
// is a protocol precondition, not a policy choice.
func TestSCP11a_GPProprietary_NonP256Key_Rejected(t *testing.T) {
	// Same GET DATA bytes as the positive test — content doesn't
	// matter because the validator we install ignores them and
	// returns a P-384 key.
	getDataProprietaryRAPDU := mustHex(t, ""+
		"BF2181E57F2181E193146A994C23ECC7F71C16325F2CF93878D1B432708642149E216D9AEF4531670A5B83ADE5DED7FF6CD97B0F"+
		"5F2014CD7B897E3C1BC6FFAC7F9595FB55AE66C3CE84AB950200805F2404141C0C1F7F4946B041044F92A07D168C309959EED99E"+
		"288381DD192979CD452D8FBE1F163447979207C5E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"+
		"F001005F3747304502210084BD2834015556ACF7920BF4D599578133AE55118894B0DCDC3EAB45BA0D3DE8022065025536025DE2"+
		"A98D99758FA7A9E352A02AE3CF9B041BA90A0CE948F3FA60749000")

	// Synthesize a P-384 ECDSA public key. The key bytes themselves
	// don't need to be valid — the post-validator gate inspects
	// PublicKey.Curve before doing ECDH.
	curve := elliptic.P384()
	wrongCurveKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}

	cfg := &Config{
		Variant:                      SCP11a,
		KeyID:                        0x11,
		KeyVersion:                   0x03,
		InsecureTestOnlyEphemeralKey: nil,
		CardTrustPolicy: &trust.Policy{
			CustomValidator: func(_ []byte) (*trust.Result, error) {
				return &trust.Result{PublicKey: wrongCurveKey}, nil
			},
		},
		// Need OCE state set so config validation passes;
		// we won't reach the handshake.
		OCEKeyReference: KeyRef{KID: 0x10, KVN: 0x03},
	}

	sx := newScriptedTransport(t, []scriptedExchange{
		{name: "GET_DATA", matchINS: 0xCA, response: getDataProprietaryRAPDU},
	})

	_, err := Open(context.Background(), sx, cfg)
	if err == nil {
		t.Fatal("scp11.Open accepted a non-P-256 custom-validated key; the post-validator P-256 invariant was bypassed")
	}
	// The error message should reference P-256 rejection, not a
	// downstream parsing failure that happens to occur first.
	if !containsCaseFold(err.Error(), "P-256") {
		t.Errorf("expected P-256 rejection in error, got: %v", err)
	}
}

// TestSCP11a_GPProprietary_NilResultRejected confirms a CustomValidator
// returning a nil Result is rejected (rather than being treated as a
// successful no-op trust decision).
func TestSCP11a_GPProprietary_NilResultRejected(t *testing.T) {
	getDataProprietaryRAPDU := mustHex(t, ""+
		"BF2181E57F2181E193146A994C23ECC7F71C16325F2CF93878D1B432708642149E216D9AEF4531670A5B83ADE5DED7FF6CD97B0F"+
		"5F2014CD7B897E3C1BC6FFAC7F9595FB55AE66C3CE84AB950200805F2404141C0C1F7F4946B041044F92A07D168C309959EED99E"+
		"288381DD192979CD452D8FBE1F163447979207C5E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"+
		"F001005F3747304502210084BD2834015556ACF7920BF4D599578133AE55118894B0DCDC3EAB45BA0D3DE8022065025536025DE2"+
		"A98D99758FA7A9E352A02AE3CF9B041BA90A0CE948F3FA60749000")

	cfg := &Config{
		Variant:         SCP11a,
		KeyID:           0x11,
		KeyVersion:      0x03,
		OCEKeyReference: KeyRef{KID: 0x10, KVN: 0x03},
		CardTrustPolicy: &trust.Policy{
			CustomValidator: func(_ []byte) (*trust.Result, error) {
				return nil, nil
			},
		},
	}

	sx := newScriptedTransport(t, []scriptedExchange{
		{name: "GET_DATA", matchINS: 0xCA, response: getDataProprietaryRAPDU},
	})

	if _, err := Open(context.Background(), sx, cfg); err == nil {
		t.Fatal("scp11.Open accepted a nil Result from CustomValidator; should fail closed")
	}
}

// containsCaseFold checks whether s contains substr ignoring case.
// Local helper to avoid importing strings just for one site.
func containsCaseFold(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			a := s[i+j]
			b := substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
