package session

// Test vectors from publicly available SCP11 reference implementations.
// reference manually calculated these because GlobalPlatform does not
// publish official SCP11 test vectors. See:
// // Test vectors derived from publicly available SCP11 reference implementations.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/kdf"
	"github.com/PeculiarVentures/scp/tlv"
)

// --- reference P-256 Key Material ---
// From Scp11TestData.java and Scp11Nist256TestData.java

// X.509 OCE certificate (P-256), DER encoded.
var refOCECertP256, _ = hex.DecodeString(
	"30820211308201B6A00302010202146DBC19AFE3782C7C0053F19E86DF2F0F00B559EA300A06082A8648CE3D040302" +
		"3051310B3009060355040613024B52310B300906035504080C0253553110300E060355040A0C0753616D73756E67" +
		"3123302106035504030C1A43412D4B4C4F4320436572746966696361746520285445535429301E170D3235303230" +
		"363130323135365A170D3236303530393130323135365A304D310B3009060355040613024B52310B300906035504" +
		"080C0253553110300E060355040A0C0753616D73756E67311F301D06035504030C164F434520436572746966696361" +
		"7465202854455354293059301306072A8648CE3D020106082A8648CE3D03010703420004B5C2598092609EFEFBA7A2" +
		"FBED2F6E9142CA3882E7DE69D47D29476E7F0CE85077480CAC6AD5C156CE459F2592DA0EECDCB0DE2E8F112C9E49C4" +
		"655A11C59620A370306E301D0603551D0E04160414E225C62F5E33CA02D23D9D83D0685B4EB2FEBC11301F0603551D" +
		"23041830168014851A6F60A6B45534647260877A357F3676C35686300E0603551D0F0101FF040403020308301C0603" +
		"551D200101FF04123010300E060C2A864886FC6B64000A020100300A06082A8648CE3D0403020349003046022100A0D2" +
		"76B639EE863758B5568ADFA9D3B7F3D906A557C4C7675607FC82A9596EC6022100D7044BDE4CB536055CF93D5C7FCF" +
		"5C7C5298EB1D4646357CE6515BC0CD9E10FF")

// --- reference GET DATA Command/Response Vectors ---

// Expected GET DATA CAPDU for SCP11a (KID=0x11, KVN=0x03).
var refGetDataCAPDU, _ = hex.DecodeString("00CABF2106A6048302110300")

// SD certificate (X.509 DER) — the card's certificate containing PK.SD.ECKA.
var refSDCertP256, _ = hex.DecodeString(
	"30820210308201B5A00302010202146A994C23ECC7F71C16325F2CF93878D1B4327086300A06082A8648CE3D040302" +
		"3051310B3009060355040613024B52310B300906035504080C0253553110300E060355040A0C0753616D73756E6731" +
		"23302106035504030C1A43412D4B4C434320436572746966696361746520285445535429301E170D32353032303631" +
		"30343634305A170D3236303530393130343634305A304C310B3009060355040613024B52310B300906035504080C02" +
		"53553110300E060355040A0C0753616D73756E67311E301C06035504030C15534420436572746966696361746520" +
		"28544553542930593013" +
		"06072A8648CE3D020106082A8648CE3D030107034200044F92A07D168C309959EED99E288381DD192979CD452D8FBE" +
		"1F163447979207C5E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1EA370306E301D06" +
		"03551D0E04160414CD7B897E3C1BC6FFAC7F9595FB55AE66C3CE84AB301F0603551D230418301680149E216D9AEF45" +
		"31670A5B83ADE5DED7FF6CD97B0F300E0603551D0F0101FF040403020308301C0603551D200101FF04123010300E06" +
		"0C2A864886FC6B64000A02010A300A06082A8648CE3D0403020349003046022100AE0814C3B4C715BFCF4DA365944D" +
		"A532B241C98227184C99364DE3DD2563E803022100D46AB8C79B475262B10487F0065CA8D720E3E275D87E516879DB" +
		"E5CACDDE1355")

// SCP11a MUTUAL AUTHENTICATE response: card ephemeral pubkey + receipt.
var refMutualAuthRAPDU_11a, _ = hex.DecodeString(
	"5F49410492CAFD79D7E39EA433611E9AAD9742D85B3BD06F3D6055D7CDE28FC44D0AB556BC0F94D2100D87727FDFA2" +
		"B49033C78F07A30AA8D5A6A505E59F99FCDFB2526686100B63C42C2D5138936FF5894F10C1234F9000")

// SCP11c MUTUAL AUTHENTICATE response: card static pubkey (as ephemeral) + receipt.
var refMutualAuthRAPDU_11c, _ = hex.DecodeString(
	"5F4941044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5E6CD1F4DD11609E2100C03" +
		"3BBD723BE78B71477E64883EB41EC366713E44AF1E86100B9394B90AEC0BC62F1F024E6D748ADD9000")

// Wrapped LIST_PACKAGES command (SCP11a P-256 AES-128 S8).
var refListPkgCAPDU_11a, _ = hex.DecodeString(
	"84F2200018E1EE3A92EF45551E8464A252F997230DC4E84F41BA692405")

// ============================================================
// Tests
// ============================================================

func TestParseOCECertificate(t *testing.T) {
	cert, err := x509.ParseCertificate(refOCECertP256)
	if err != nil {
		t.Fatalf("parse OCE cert: %v", err)
	}
	if cert.Subject.CommonName != "OCE Certificate (TEST)" {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, "OCE Certificate (TEST)")
	}
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	if ecPub.Curve != elliptic.P256() {
		t.Errorf("curve: got %v, want P-256", ecPub.Curve.Params().Name)
	}
}

func TestParseSDCertificate(t *testing.T) {
	cert, err := x509.ParseCertificate(refSDCertP256)
	if err != nil {
		t.Fatalf("parse SD cert: %v", err)
	}
	if cert.Subject.CommonName != "SD Certificate (TEST)" {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, "SD Certificate (TEST)")
	}
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	// Verify the public key matches the expected uncompressed point.
	ecdhPub, err := ecPub.ECDH()
	if err != nil {
		t.Fatalf("ECDH conversion: %v", err)
	}
	point := ecdhPub.Bytes()
	expectedPubHex := "044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5" +
		"E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"
	expectedPub, _ := hex.DecodeString(expectedPubHex)
	if !bytes.Equal(point, expectedPub) {
		t.Errorf("SD public key mismatch:\n  got:  %X\n  want: %X", point, expectedPub)
	}
}

func TestParseGetDataResponse_CertificateChain(t *testing.T) {
	// Test that extractCardPublicKey works with a BF21-wrapped X.509 cert.
	// Use the known-good full SD certificate wrapped in BF21.
	certNode := tlv.Build(tlv.TagCertificate, refSDCertP256)
	storeNode := tlv.BuildConstructed(tlv.TagCertStore, certNode)
	wrapped := storeNode.Encode()

	pubKey, err := extractCardPublicKey(wrapped, nil)
	if err != nil {
		t.Fatalf("extractCardPublicKey: %v", err)
	}
	if pubKey == nil {
		t.Fatal("no public key extracted")
	}

	pubBytes := pubKey.Bytes()
	if len(pubBytes) != 65 {
		t.Errorf("public key length: got %d, want 65", len(pubBytes))
	}

	expectedHex := "044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5" +
		"E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"
	expectedPub, _ := hex.DecodeString(expectedHex)
	if !bytes.Equal(pubBytes, expectedPub) {
		t.Errorf("extracted public key mismatch:\n  got:  %X\n  want: %X", pubBytes, expectedPub)
	}

	// Also test with raw DER (no BF21 wrapper) — some cards return this.
	pubKey2, err := extractCardPublicKey(refSDCertP256, nil)
	if err != nil {
		t.Fatalf("extractCardPublicKey (raw DER): %v", err)
	}
	if !bytes.Equal(pubKey2.Bytes(), expectedPub) {
		t.Error("raw DER extraction failed")
	}
}

func TestParseMutualAuthResponse_SCP11a(t *testing.T) {
	// Strip the 9000 SW.
	data := refMutualAuthRAPDU_11a[:len(refMutualAuthRAPDU_11a)-2]

	ephPub, receipt, err := parseKeyAgreementResponse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// SCP11a response should have both ephemeral key and receipt.
	if len(ephPub) != 65 {
		t.Errorf("ephemeral key length: got %d, want 65", len(ephPub))
	}
	if ephPub[0] != 0x04 {
		t.Errorf("ephemeral key prefix: got 0x%02X, want 0x04", ephPub[0])
	}

	// Receipt should be 16 bytes (tag 0x86, length 0x10).
	if len(receipt) != 16 {
		t.Errorf("receipt length: got %d, want 16", len(receipt))
	}

	// Verify the receipt matches the expected value from the reference vectors.
	expectedReceipt, _ := hex.DecodeString("0B63C42C2D5138936FF5894F10C1234F")
	if !bytes.Equal(receipt, expectedReceipt) {
		t.Errorf("receipt mismatch:\n  got:  %X\n  want: %X", receipt, expectedReceipt)
	}

	// Verify the ephemeral key is parseable.
	_, err = ecdh.P256().NewPublicKey(ephPub)
	if err != nil {
		t.Errorf("invalid ephemeral key: %v", err)
	}
}

func TestParseMutualAuthResponse_SCP11c(t *testing.T) {
	data := refMutualAuthRAPDU_11c[:len(refMutualAuthRAPDU_11c)-2]

	ephPub, receipt, err := parseKeyAgreementResponse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(ephPub) != 65 {
		t.Errorf("ephemeral key length: got %d, want 65", len(ephPub))
	}

	// SCP11c returns the SD static key as "ephemeral" and a receipt.
	expectedReceipt, _ := hex.DecodeString("0B9394B90AEC0BC62F1F024E6D748ADD")
	if !bytes.Equal(receipt, expectedReceipt) {
		t.Errorf("receipt mismatch:\n  got:  %X\n  want: %X", receipt, expectedReceipt)
	}
}

func TestGetDataAPDUConstruction(t *testing.T) {
	// Verify our GET DATA command matches the reference expected CAPDU.
	// the reference expected: 00 CA BF 21 06 A6 04 83 02 11 03 00
	// That's: CLA=00, INS=CA, P1=BF, P2=21, Lc=06, data=A6048302110300, Le=00
	//
	// The data is: A6 { 83 { 11, 03 } } — control ref template with KID=0x11, KVN=0x03.
	keyRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyID, []byte{0x11, 0x03}),
	)

	cmd := &apdu.Command{
		CLA:  0x00,
		INS:  0xCA,
		P1:   0xBF,
		P2:   0x21,
		Data: keyRef.Encode(),
		Le:   0,
	}

	encoded, err := cmd.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if !bytes.Equal(encoded, refGetDataCAPDU) {
		t.Errorf("GET DATA CAPDU mismatch:\n  got:  %X\n  want: %X", encoded, refGetDataCAPDU)
	}
}

func TestECDHWithReferenceKeys(t *testing.T) {
	// Parse the OCE ephemeral private key from the reference PKCS#8 DER.
	eskRaw, _ := hex.DecodeString("B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5")

	oceEphPriv, err := ecdh.P256().NewPrivateKey(eskRaw)
	if err != nil {
		t.Fatalf("parse OCE ephemeral private key: %v", err)
	}

	// Verify the public key matches the reference expected EPK.
	epkExpectedHex := "0470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5DBBF8A32" +
		"F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C92"
	epkExpected, _ := hex.DecodeString(epkExpectedHex)
	if !bytes.Equal(oceEphPriv.PublicKey().Bytes(), epkExpected) {
		t.Fatalf("derived public key doesn't match reference EPK")
	}

	// Parse the SD static public key from the reference certificate.
	sdPubHex := "044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5" +
		"E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"
	sdPubBytes, _ := hex.DecodeString(sdPubHex)
	sdPub, err := ecdh.P256().NewPublicKey(sdPubBytes)
	if err != nil {
		t.Fatalf("parse SD public key: %v", err)
	}

	// Parse the SCP11a card ephemeral key from the MUTUAL AUTH response.
	cardEphPubHex := "0492CAFD79D7E39EA433611E9AAD9742D85B3BD06F3D6055D7CDE28FC44D0AB556" +
		"BC0F94D2100D87727FDFA2B49033C78F07A30AA8D5A6A505E59F99FCDFB25266"
	cardEphPubBytes, _ := hex.DecodeString(cardEphPubHex)
	cardEphPub, err := ecdh.P256().NewPublicKey(cardEphPubBytes)
	if err != nil {
		t.Fatalf("parse card ephemeral key: %v", err)
	}

	// For SCP11a, the second ECDH uses the OCE *static* private key against SD static pub.
	// the reference code: skOceEcka = keyParams.skOceEcka (the static key)
	oceStaticRaw, _ := hex.DecodeString("A5116B848D41BD93737F187ABC03886BF7A80422D150025109C6749F45BB9B6D")
	oceStaticPriv, err := ecdh.P256().NewPrivateKey(oceStaticRaw)
	if err != nil {
		t.Fatalf("parse OCE static private key: %v", err)
	}

	// Compute ShSee = ECDH(eSK.OCE, ePK.SD) — ephemeral-ephemeral
	shSee, err := oceEphPriv.ECDH(cardEphPub)
	if err != nil {
		t.Fatalf("ECDH (eph-eph): %v", err)
	}

	// Compute ShSes = ECDH(SK.OCE, PK.SD) — static-static for SCP11a
	shSes, err := oceStaticPriv.ECDH(sdPub)
	if err != nil {
		t.Fatalf("ECDH (static-static): %v", err)
	}

	// Derive session keys.
	keys, err := kdf.DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, nil)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	// Build keyAgreementData exactly as reference does:
	// command_data = A6 { 90{11, 01}, 95{3C}, 80{88}, 81{10} } || 5F49{ePK.OCE}
	// reference SCP11a params=0x01, keyUsage=0x3C, keyType=0x88, keyLen=0x10
	commandData := buildMutualAuthData(0x01, oceEphPriv.PublicKey().Bytes())

	// Concatenate with card's ePK.SD TLV (the full TLV bytes from the response).
	cardEphPubTLV := tlv.Build(tlv.TagEphPubKey, cardEphPubBytes)
	var keyAgreementData []byte
	keyAgreementData = append(keyAgreementData, commandData...)
	keyAgreementData = append(keyAgreementData, cardEphPubTLV.Encode()...)

	// Verify the receipt matches the reference expected value.
	receipt, err := kdf.ComputeReceipt(keys.Receipt, keyAgreementData)
	if err != nil {
		t.Fatalf("compute receipt: %v", err)
	}

	expectedReceipt, _ := hex.DecodeString("0B63C42C2D5138936FF5894F10C1234F")
	if !bytes.Equal(receipt, expectedReceipt) {
		t.Errorf("receipt mismatch:\n  got:  %X\n  want: %X", receipt, expectedReceipt)
	}

	t.Logf("Session keys derived successfully from reference vectors test vectors:")
	t.Logf("  S-ENC:  %X", keys.SENC)
	t.Logf("  S-MAC:  %X", keys.SMAC)
	t.Logf("  S-RMAC: %X", keys.SRMAC)
	t.Logf("  DEK:    %X", keys.DEK)
}

// buildMutualAuthData constructs the MUTUAL AUTHENTICATE data field
// exactly as reference does: A6 { 90{11,params}, 95{3C}, 80{88}, 81{10} } || 5F49{ePK.OCE}
func buildMutualAuthData(params byte, oceEphPubBytes []byte) []byte {
	controlRef := tlv.BuildConstructed(tlv.TagControlRef,
		tlv.Build(tlv.TagKeyInfo, []byte{0x11, params}),
		tlv.Build(tlv.TagKeyUsage, []byte{kdf.KeyUsage}),
		tlv.Build(tlv.TagKeyType, []byte{kdf.KeyTypeAES}),
		tlv.Build(tlv.TagKeyLength, []byte{kdf.SessionKeyLen}),
	)
	ephPubTLV := tlv.Build(tlv.TagEphPubKey, oceEphPubBytes)

	var data []byte
	data = append(data, controlRef.Encode()...)
	data = append(data, ephPubTLV.Encode()...)
	return data
}

func TestWrappedListPackagesAPDU_ReferenceFormat(t *testing.T) {
	// The reference wrapped LIST_PACKAGES CAPDU is:
	// 84 F2 20 00 18 E1EE3A92EF45551E 8464A252F997230D C4E84F41BA692405
	// CLA=0x84 (secure messaging), INS=0xF2, P1=0x20, P2=0x00
	// Lc=0x18 (24 bytes) = 16 bytes encrypted data + 8 bytes MAC
	wrapped := refListPkgCAPDU_11a

	if wrapped[0] != 0x84 {
		t.Errorf("CLA: got 0x%02X, want 0x84 (secure messaging)", wrapped[0])
	}
	if wrapped[1] != 0xF2 {
		t.Errorf("INS: got 0x%02X, want 0xF2 (LIST)", wrapped[1])
	}

	// Lc = 0x18 = 24 bytes: 16 encrypted + 8 MAC
	lc := wrapped[4]
	if lc != 0x18 {
		t.Errorf("Lc: got 0x%02X, want 0x18", lc)
	}

	dataField := wrapped[5:]
	if len(dataField) != 24 {
		t.Errorf("data field length: got %d, want 24", len(dataField))
	}

	// The last 8 bytes are the truncated C-MAC.
	mac := dataField[16:]
	t.Logf("Encrypted data: %X", dataField[:16])
	t.Logf("C-MAC (8B):     %X", mac)
}

// Verify ecdsaToECDH round-trips correctly with the reference test key.
func TestEcdsaToECDH_SDKey(t *testing.T) {
	cert, err := x509.ParseCertificate(refSDCertP256)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ecdhKey, err := ecdsaToECDH(cert.PublicKey)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	expectedHex := "044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5" +
		"E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"
	expected, _ := hex.DecodeString(expectedHex)

	if !bytes.Equal(ecdhKey.Bytes(), expected) {
		t.Errorf("ECDH key mismatch:\n  got:  %X\n  want: %X", ecdhKey.Bytes(), expected)
	}
}

func TestMutualAuthCAPDU_MatchesReferenceVectors(t *testing.T) {
	// the reference expected SCP11a MUTUAL AUTHENTICATE CAPDU:
	// 80 82 03 11 53 A6{0D 90{02 11 01} 95{01 3C} 80{01 88} 81{01 10}}
	//               5F49{41 04 70B0BD...} 00
	// CLA=80, INS=82, P1=03(KVN), P2=11(KID=SCP11a)
	expectedHex := "8082031153A60D9002110195013C8001888101105F49410470B0BD7863E90E32DA5401188354D1F41999" +
		"442FDFDCBA7472B7F1E5DBBF8A32F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C9200"
	expected, _ := hex.DecodeString(expectedHex)

	oceEphPubHex := "0470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5DBBF8A32" +
		"F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C92"
	oceEphPub, _ := hex.DecodeString(oceEphPubHex)

	data := buildMutualAuthData(0x01, oceEphPub) // SCP11a params=0x01

	cmd := &apdu.Command{
		CLA:  0x80,
		INS:  0x82, // MUTUAL AUTHENTICATE
		P1:   0x03, // KVN
		P2:   0x11, // KID (SCP11a)
		Data: data,
		Le:   0,
	}

	encoded, err := cmd.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("MUTUAL AUTH CAPDU mismatch:\n  got:  %X\n  want: %X", encoded, expected)
	}
}

func TestECDHWithReferenceKeys_SCP11c(t *testing.T) {
	// SCP11c uses the SD static public key in the response (not an ephemeral key).
	eskRaw, _ := hex.DecodeString("B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5")
	oceEphPriv, err := ecdh.P256().NewPrivateKey(eskRaw)
	if err != nil {
		t.Fatalf("parse OCE ephemeral key: %v", err)
	}

	sdPubHex := "044F92A07D168C309959EED99E288381DD192979CD452D8FBE1F163447979207C5" +
		"E6CD1F4DD11609E2100C033BBD723BE78B71477E64883EB41EC366713E44AF1E"
	sdPubBytes, _ := hex.DecodeString(sdPubHex)
	sdPub, err := ecdh.P256().NewPublicKey(sdPubBytes)
	if err != nil {
		t.Fatalf("parse SD pub: %v", err)
	}

	oceStaticRaw, _ := hex.DecodeString("A5116B848D41BD93737F187ABC03886BF7A80422D150025109C6749F45BB9B6D")
	oceStaticPriv, err := ecdh.P256().NewPrivateKey(oceStaticRaw)
	if err != nil {
		t.Fatalf("parse OCE static key: %v", err)
	}

	// For SCP11c, ePK.SD in the response IS the SD static key.
	// ShSee = ECDH(eSK.OCE, PK.SD)
	shSee, err := oceEphPriv.ECDH(sdPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	// ShSes = ECDH(SK.OCE, PK.SD)
	shSes, err := oceStaticPriv.ECDH(sdPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	keys, err := kdf.DeriveSessionKeysFromSharedSecrets(shSee, shSes, nil, nil)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	// Build keyAgreementData for SCP11c (params=0x03).
	commandData := buildMutualAuthData(0x03, oceEphPriv.PublicKey().Bytes())
	cardPubTLV := tlv.Build(tlv.TagEphPubKey, sdPubBytes)
	var keyAgreementData []byte
	keyAgreementData = append(keyAgreementData, commandData...)
	keyAgreementData = append(keyAgreementData, cardPubTLV.Encode()...)

	receipt, err := kdf.ComputeReceipt(keys.Receipt, keyAgreementData)
	if err != nil {
		t.Fatalf("compute receipt: %v", err)
	}

	expectedReceipt, _ := hex.DecodeString("0B9394B90AEC0BC62F1F024E6D748ADD")
	if !bytes.Equal(receipt, expectedReceipt) {
		t.Errorf("SCP11c receipt mismatch:\n  got:  %X\n  want: %X", receipt, expectedReceipt)
	}
	t.Logf("SCP11c receipt verified against reference vectors")
}
