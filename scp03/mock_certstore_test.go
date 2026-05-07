package scp03

// Tests for the SCP03 mock card's cert-store persistence.
//
// Wire round-trip tested here: STORE DATA tag 0xBF21 with a
// key-reference and cert chain body writes to the mock's certStore
// map; GET DATA tag 0xBF21 with the same key reference reads it
// back and returns BF21{stored} for parseCertificates to round-trip.
//
// The mock previously had no cert-store persistence (STORE DATA was
// record-and-9000, GET DATA tag BF21 returned 6A88), so the
// bootstrap-scp11a-sd chain-validation flow couldn't be exercised
// against the mock. These tests pin the new behavior at the unit
// level so any future regression in the storage round-trip lands
// an obvious failure here regardless of higher-level callers.

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// TestMock_CertStore_RoundTrip verifies the basic write-then-read
// round-trip: STORE DATA writes a chain at one key reference; GET
// DATA at the same reference reads it back, BF21-wrapped for the
// caller to parse.
func TestMock_CertStore_RoundTrip(t *testing.T) {
	mock := NewMockCard(DefaultKeys)

	// Build a STORE DATA body for ref (KID=0x11, KVN=0x01) holding
	// a deterministic "cert chain" — we use 0x30-prefixed sequences
	// so any future caller using splitDERCertificates would parse
	// these as if they were certs.
	storeBody := buildCertStoreSTOREDATABody(t, 0x11, 0x01,
		mockCert(0x01, 0x02, 0x03),
		mockCert(0x04, 0x05, 0x06),
	)
	if !mock.tryStoreCertChain(storeBody) {
		t.Fatalf("tryStoreCertChain returned false on a valid cert-chain body")
	}

	// Read back via lookupCertChain with the matching key ref.
	reqBody := buildKeyRefRequestBody(0x11, 0x01)
	resp, ok := mock.lookupCertChain(reqBody)
	if !ok {
		t.Fatalf("lookupCertChain returned false; chain should be stored at ref 0x11/0x01")
	}
	// Response is BF21{concat-of-DER}; verify that wrapping is
	// present and the inner content matches what we stored.
	wantInner := append(mockCert(0x01, 0x02, 0x03), mockCert(0x04, 0x05, 0x06)...)
	nodes, err := tlv.Decode(resp)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	store := tlv.Find(nodes, tlv.Tag(0xBF21))
	if store == nil {
		t.Fatalf("response missing BF21 wrapper; resp=%X", resp)
	}
	if !bytes.Equal(store.Value, wantInner) {
		t.Errorf("BF21 inner content mismatch:\n  got:  %X\n  want: %X", store.Value, wantInner)
	}
}

// TestMock_CertStore_DifferentRef_NotFound confirms refs are
// distinct: a chain stored at one ref isn't returned for a different
// ref.
func TestMock_CertStore_DifferentRef_NotFound(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	storeBody := buildCertStoreSTOREDATABody(t, 0x11, 0x01, mockCert(0xFF))
	if !mock.tryStoreCertChain(storeBody) {
		t.Fatalf("tryStoreCertChain returned false")
	}
	// Same KID, different KVN.
	reqBody := buildKeyRefRequestBody(0x11, 0x02)
	if _, ok := mock.lookupCertChain(reqBody); ok {
		t.Errorf("lookupCertChain returned a chain for the wrong ref")
	}
	// Different KID, same KVN.
	reqBody = buildKeyRefRequestBody(0x13, 0x01)
	if _, ok := mock.lookupCertChain(reqBody); ok {
		t.Errorf("lookupCertChain returned a chain for the wrong KID")
	}
}

// TestMock_CertStore_Overwrite confirms the store overwrites on
// re-write at the same ref. This is the rotation case — replacing a
// chain at an existing key reference.
func TestMock_CertStore_Overwrite(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.tryStoreCertChain(buildCertStoreSTOREDATABody(t, 0x11, 0x01,
		mockCert(0xAA),
	))
	mock.tryStoreCertChain(buildCertStoreSTOREDATABody(t, 0x11, 0x01,
		mockCert(0xBB), mockCert(0xCC),
	))

	resp, ok := mock.lookupCertChain(buildKeyRefRequestBody(0x11, 0x01))
	if !ok {
		t.Fatalf("lookupCertChain returned false after overwrite")
	}
	wantInner := append(mockCert(0xBB), mockCert(0xCC)...)
	nodes, _ := tlv.Decode(resp)
	store := tlv.Find(nodes, tlv.Tag(0xBF21))
	if !bytes.Equal(store.Value, wantInner) {
		t.Errorf("overwrite did not replace; store value=%X want=%X", store.Value, wantInner)
	}
}

// TestMock_CertStore_NotCertChainShape_FallsThrough checks that
// other STORE DATA shapes (allowlist, CA-issuer SKI) don't
// accidentally hit the cert store. tryStoreCertChain must return
// false for them.
func TestMock_CertStore_NotCertChainShape_FallsThrough(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	cases := []struct {
		name string
		body []byte
	}{
		{
			name: "allowlist (A6 + 70)",
			body: append(
				tlv.BuildConstructed(tlv.Tag(0xA6),
					tlv.Build(tlv.Tag(0x83), []byte{0x11, 0x01}),
				).Encode(),
				tlv.Build(tlv.Tag(0x70), []byte{0x93, 0x01, 0x42}).Encode()...,
			),
		},
		{
			name: "ca-issuer SKI (A6 + nested)",
			body: tlv.BuildConstructed(tlv.Tag(0xA6),
				tlv.Build(tlv.Tag(0x80), []byte{0x01}),
				tlv.Build(tlv.Tag(0x42), []byte{0xCA, 0xFE, 0x00, 0x01}),
				tlv.Build(tlv.Tag(0x83), []byte{0x10, 0x01}),
			).Encode(),
		},
		{
			name: "empty",
			body: nil,
		},
		{
			name: "non-TLV garbage",
			body: []byte{0xFF, 0xFE, 0xFD},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if mock.tryStoreCertChain(tc.body) {
				t.Errorf("tryStoreCertChain accepted non-cert body; should fall through")
			}
		})
	}
}

// TestMock_CertStore_LookupNotFoundReturnsFalse: a fresh mock with
// no chains stored returns ok=false for any ref. The mock's GET
// DATA case translates this to 6A88, matching real cards.
func TestMock_CertStore_LookupNotFoundReturnsFalse(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	if _, ok := mock.lookupCertChain(buildKeyRefRequestBody(0x11, 0x01)); ok {
		t.Errorf("lookupCertChain returned a chain on a fresh mock")
	}
}

// TestMock_CertStore_GetDataTagBF21_RealAPDUPath drives the full
// dispatch path: insert a chain via tryStoreCertChain (proxying for
// what STORE DATA would do), then issue a GET DATA tag BF21 APDU
// through processSecure-style entry and verify the response.
//
// This test pins that the doGetData refactor — adding requestBody
// — wires through correctly to the BF21 case.
func TestMock_CertStore_GetDataTagBF21_RealAPDUPath(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.tryStoreCertChain(buildCertStoreSTOREDATABody(t, 0x13, 0x05, mockCert(0x99)))

	// Hit doGetData directly with tag BF21 (P1=0xBF, P2=0x21) and
	// the key-ref request body.
	resp, err := mock.doGetData(0xBF, 0x21, buildKeyRefRequestBody(0x13, 0x05))
	if err != nil {
		t.Fatalf("doGetData: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("doGetData returned SW=%04X, want 9000", resp.StatusWord())
	}
	nodes, err := tlv.Decode(resp.Data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tlv.Find(nodes, tlv.Tag(0xBF21)) == nil {
		t.Errorf("response missing BF21 wrapper; data=%X", resp.Data)
	}

	// Lookup miss → 6A88.
	resp, err = mock.doGetData(0xBF, 0x21, buildKeyRefRequestBody(0x99, 0x99))
	if err != nil {
		t.Fatalf("doGetData (miss): %v", err)
	}
	if resp.StatusWord() != 0x6A88 {
		t.Errorf("miss SW = %04X, want 6A88", resp.StatusWord())
	}
}

// TestMock_CertStore_OtherTagsUnchanged: the doGetData refactor
// must not change behavior for tags 0x0066 (CRD) and 0x00E0
// (KeyInfo). They keep returning their synthetic blobs regardless
// of the new requestBody parameter.
func TestMock_CertStore_OtherTagsUnchanged(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	for _, tc := range []struct {
		name string
		p1   byte
		p2   byte
		want []byte
	}{
		{"CRD", 0x00, 0x66, syntheticCRD},
		{"KeyInfo", 0x00, 0xE0, syntheticKeyInfo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Pass arbitrary body; existing tags ignore it.
			resp, err := mock.doGetData(tc.p1, tc.p2, []byte{0x01, 0x02, 0x03})
			if err != nil {
				t.Fatalf("doGetData: %v", err)
			}
			if !resp.IsSuccess() {
				t.Fatalf("SW=%04X, want 9000", resp.StatusWord())
			}
			if !bytes.Equal(resp.Data, tc.want) {
				t.Errorf("data mismatch:\n  got:  %X\n  want: %X", resp.Data, tc.want)
			}
		})
	}
}

// TestMock_CertStore_RefKeyClassifier pins the (KID,KVN) → uint16
// packing. MSB=KID, LSB=KVN; collisions across distinct refs would
// cause cross-talk in the storage map.
func TestMock_CertStore_RefKeyClassifier(t *testing.T) {
	cases := []struct {
		ref  keyRef
		want uint16
	}{
		{keyRef{0x00, 0x00}, 0x0000},
		{keyRef{0x11, 0x01}, 0x1101},
		{keyRef{0x10, 0x10}, 0x1010},
		{keyRef{0xFF, 0xFF}, 0xFFFF},
		{keyRef{0x11, 0x10}, 0x1110}, // distinct from {0x10, 0x11}
		{keyRef{0x10, 0x11}, 0x1011},
	}
	for _, tc := range cases {
		if got := refKey(tc.ref); got != tc.want {
			t.Errorf("refKey(%+v) = 0x%04X, want 0x%04X", tc.ref, got, tc.want)
		}
	}
}

// --- helpers ---

// mockCert builds a minimal "DER-ish" cert blob starting with the
// 0x30 SEQUENCE tag so splitDERCertificates would treat each as a
// distinct cert. Length encoding follows BER short-form.
//
// We don't use real x509.CreateCertificate here because these tests
// validate the storage shell — not certificate parsing — and a
// stable opaque blob is easier to assert byte-equality on.
func mockCert(payload ...byte) []byte {
	// 0x30 LL <payload>
	out := []byte{0x30, byte(len(payload))}
	out = append(out, payload...)
	return out
}

// buildCertStoreSTOREDATABody assembles a STORE DATA body matching
// what storeCertificatesData would produce: A6{83{KID,KVN}} ||
// BF21{concat-of-DER}. We don't import securitydomain (it imports
// scp03 — cycle), so we build the bytes directly via the TLV package.
func buildCertStoreSTOREDATABody(t *testing.T, kid, kvn byte, certs ...[]byte) []byte {
	t.Helper()
	keyRefTLV := tlv.BuildConstructed(tlv.Tag(0xA6),
		tlv.Build(tlv.Tag(0x83), []byte{kid, kvn}),
	).Encode()
	var concat []byte
	for _, c := range certs {
		concat = append(concat, c...)
	}
	certStoreTLV := tlv.Build(tlv.Tag(0xBF21), concat).Encode()
	return append(keyRefTLV, certStoreTLV...)
}

// buildKeyRefRequestBody assembles the GET DATA tag BF21 request
// body: A6{83{KID,KVN}}, matching securitydomain.buildKeyRefTLV.
func buildKeyRefRequestBody(kid, kvn byte) []byte {
	return tlv.BuildConstructed(tlv.Tag(0xA6),
		tlv.Build(tlv.Tag(0x83), []byte{kid, kvn}),
	).Encode()
}

// silence unused-import warning on context/apdu when only some
// tests in the file use them.
var _ = context.Background
var _ = apdu.Response{}
