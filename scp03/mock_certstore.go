package scp03

// Cert store behavioral surface for MockCard.
//
// The mock persists certificate chains posted via STORE DATA
// (A6{83{KID,KVN}} || BF21{cert_DER_concat}) and serves them
// back via GET DATA tag BF21. Two functions live here: a write
// path (tryStoreCertChain, called from processSecure / processPlain
// on STORE DATA) and a read path (lookupCertChain, called from
// doGetData on tag BF21).
//
// Split from mock.go because cert-chain handling is the smallest
// stateful surface (one map keyed by KID/KVN) and is referenced
// from both the dispatch layer (STORE DATA) and the GET DATA
// layer. Keeping it in its own file makes the storage shape
// auditable in isolation: anyone tracing a cert-store bug only
// has to read this file plus the small slice of mock_inventory.go
// that defines refKey.

import (
	"github.com/PeculiarVentures/scp/tlv"
)

// tryStoreCertChain inspects a STORE DATA body for the cert-chain
// shape (A6{83{KID,KVN}} || BF21{cert_DER_concat}) and persists it
// to the cert store on hit. Returns true on hit, false on any other
// shape (allowlist, CA-issuer SKI, etc.) — the caller falls back to
// the plain record-and-9000 behavior for non-cert STORE DATA.
//
// We don't enforce the exact tag order or insist on no other tags
// being present; the parser walks top-level nodes and pairs the
// first A6 (control reference) with the first BF21 (cert store) it
// sees. This matches storeCertificatesData's emission order
// (A6 first, BF21 second) without breaking on potential future
// shapes that interleave additional tags.
//
// Persisting the BF21 *value* (the concatenated DER bytes) — not
// the wrapper — keeps the storage canonical. On read we re-wrap
// in BF21 so the response matches the on-the-wire shape that
// parseCertificates round-trips cleanly.
func (c *MockCard) tryStoreCertChain(body []byte) bool {
	nodes, err := tlv.Decode(body)
	if err != nil {
		return false
	}
	ref, refOK := extractKeyRefFromControlRef(nodes)
	if !refOK {
		return false
	}
	store := tlv.Find(nodes, tlv.Tag(0xBF21))
	if store == nil || len(store.Value) == 0 {
		return false
	}
	if c.certStore == nil {
		c.certStore = make(map[uint16][]byte)
	}
	c.certStore[refKey(ref)] = append([]byte(nil), store.Value...)
	return true
}

// lookupCertChain parses a key reference from a GET DATA tag BF21
// request body and returns the BF21-wrapped stored chain bytes if
// present. Returns (nil, false) if no chain is stored at that ref or
// the request body is malformed; caller surfaces this as 6A88, the
// same status real cards return when no cert is stored at the
// requested reference.
//
// We re-wrap the stored bytes in BF21 on read because that's what
// storeCertificatesData put on the wire originally and what the
// library's parseCertificates expects to round-trip. Keeping the
// store canonical (DER concat, no wrapper) and re-wrapping on read
// avoids redundant wrap/unwrap state in the storage map.
func (c *MockCard) lookupCertChain(reqBody []byte) ([]byte, bool) {
	if len(c.certStore) == 0 {
		return nil, false
	}
	nodes, err := tlv.Decode(reqBody)
	if err != nil {
		return nil, false
	}
	ref, ok := extractKeyRefFromControlRef(nodes)
	if !ok {
		return nil, false
	}
	stored, ok := c.certStore[refKey(ref)]
	if !ok {
		return nil, false
	}
	return tlv.Build(tlv.Tag(0xBF21), stored).Encode(), true
}
