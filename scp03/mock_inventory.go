package scp03

// Key inventory model for MockCard.
//
// This file holds the in-memory map that tracks which (KID, KVN)
// pairs the card believes are populated, plus the helpers that
// mutate that map in response to PUT KEY, GENERATE EC KEY, and
// DELETE KEY commands. The map exists so that
// buildKeyInfoResponse (the GET DATA tag E0 builder in
// mock_getdata.go) can render an accurate Key Information
// Template after the test fixture has issued provisioning
// commands — without it, post-install state always looks like
// the factory default.
//
// Split from mock.go because the inventory is the largest
// stateful surface (six update methods plus a serializer) and
// is referenced from both the dispatch layer (processSecure
// applies PUT KEY / DELETE KEY effects to the inventory) and
// the GET DATA layer (E0 builder reads the inventory). Keeping
// it in its own file makes the state-shape contract auditable:
// anyone tracing "why does sd keys list show stale entries?"
// only has to read this file.

import (
	"github.com/PeculiarVentures/scp/tlv"
)

// keyRef holds (KID, KVN) in a small fixed-size struct usable as a
// map key. Unlike securitydomain.KeyReference this is package-local
// to avoid pulling securitydomain into scp03 (would create an import
// cycle: securitydomain imports scp03 already).
type keyRef struct {
	KID byte
	KVN byte
}

// refKey packs (KID, KVN) into a uint16 for use as a map key.
// MSB = KID, LSB = KVN. The compact form keeps the certStore map
// small even with many keys.
func refKey(r keyRef) uint16 {
	return uint16(r.KID)<<8 | uint16(r.KVN)
}

// extractKeyRefFromControlRef walks a TLV node list looking for
// A6 { 83 { KID, KVN } } and returns the parsed key reference.
// Returns (zero, false) if the shape doesn't match or 83's value
// isn't exactly two bytes.
//
// The control-reference tag (A6) wraps key-management TLVs
// throughout SCP11: storeCertificatesData, storeCaIssuerData, and
// buildKeyRefTLV all emit A6{83{KID,KVN}} as the address field.
// Centralizing the parser here means all three paths (store certs,
// store CA issuer, get certs) extract the ref the same way.
func extractKeyRefFromControlRef(nodes []*tlv.Node) (keyRef, bool) {
	ctrl := tlv.Find(nodes, tlv.Tag(0xA6))
	if ctrl == nil {
		return keyRef{}, false
	}
	keyID := tlv.Find(ctrl.Children, tlv.Tag(0x83))
	if keyID == nil || len(keyID.Value) != 2 {
		return keyRef{}, false
	}
	return keyRef{KID: keyID.Value[0], KVN: keyID.Value[1]}, true
}

// --- Inventory model: PUT KEY / DELETE KEY / GENERATE EC KEY
//     register and unregister entries; GET DATA tag 0x00E0 reads
//     them out as the Key Information Template the library expects.

// registerKey adds or replaces an entry in the inventory. Idempotent
// at the (KID, KVN) tuple level — re-registering an existing entry
// updates its components in place.
func (c *MockCard) registerKey(kid, kvn byte, components []byte) {
	if c.inventory == nil {
		c.inventory = make(map[uint16]mockKeyEntry)
	}
	c.inventory[uint16(kid)<<8|uint16(kvn)] = mockKeyEntry{
		KID:        kid,
		KVN:        kvn,
		Components: append([]byte(nil), components...),
	}
}

// unregisterKey removes a single (KID, KVN) entry. Idempotent —
// removing a non-existent entry is a no-op, matching real-card
// DELETE KEY semantics where deleting a key that isn't installed
// returns 9000 (success, no-op).
func (c *MockCard) unregisterKey(kid, kvn byte) {
	if c.inventory == nil {
		return
	}
	delete(c.inventory, uint16(kid)<<8|uint16(kvn))
}

// unregisterAllAtKVN removes every entry with the given KVN,
// regardless of KID. Used by DELETE KEY when only a KVN is
// specified — the real-card semantic for "delete the keyset at
// this version" affects all keys at that version (e.g. an SCP03
// keyset comprises ENC, MAC, DEK with the same KVN; deleting "the
// keyset" deletes all three).
func (c *MockCard) unregisterAllAtKVN(kvn byte) {
	for k, e := range c.inventory {
		if e.KVN == kvn {
			delete(c.inventory, k)
		}
	}
}

// unregisterAllAtKID removes every entry with the given KID,
// regardless of KVN. Used by DELETE KEY when only a KID is
// specified — semantic is "delete all versions of this key" which
// is rarer in practice but supported by the GP DELETE KEY surface.
func (c *MockCard) unregisterAllAtKID(kid byte) {
	for k, e := range c.inventory {
		if e.KID == kid {
			delete(c.inventory, k)
		}
	}
}

// SetInventory replaces the entire inventory. Useful for tests that
// want to start from a non-default state — e.g. simulating a card
// where the factory keys have been rotated and additional keys
// installed.
//
// Pass an empty slice to clear the inventory entirely. The mock
// will then advertise zero installed keys until something gets
// registered.
func (c *MockCard) SetInventory(entries []mockKeyEntry) {
	c.inventory = make(map[uint16]mockKeyEntry, len(entries))
	for _, e := range entries {
		c.inventory[uint16(e.KID)<<8|uint16(e.KVN)] = mockKeyEntry{
			KID:        e.KID,
			KVN:        e.KVN,
			Components: append([]byte(nil), e.Components...),
		}
	}
}

// applyPutKeyToInventory updates the inventory after a PUT KEY
// command lands. Three flavors:
//
//   - SCP03 AES key set (body starts with KVN, then tag 0x88):
//     register at (0x01, body[0]) with AES-128 components. If
//     P1 is non-zero, the existing keyset at (0x01, P1) is
//     unregistered first — that's the GP "replace" semantic.
//   - EC private (body starts with KVN, then tag 0xA1 or 0xB1):
//     register at (P2 & 0x7F, body[0]) with EC components.
//   - EC public / trust anchor (body starts with KVN, then tag 0xB0):
//     same registration as EC private.
//
// The inventory mutation is best-effort. A malformed body that
// can't be classified just leaves the inventory untouched; the
// APDU still records and the response still goes out. Tests that
// want to verify post-install inventory state should drive PUT
// KEY through the library's typed API, which produces well-formed
// bodies.
//
// The 0x80 bit on P2 is the "multiple keys in this command" flag
// per GP §11.8.2.2. We mask it off because the inventory tracks
// the KID itself, not the wire flag.
func (c *MockCard) applyPutKeyToInventory(p1, p2 byte, body []byte) {
	if len(body) < 2 {
		return
	}
	newKVN := body[0]
	firstTag := body[1]
	kid := p2 & 0x7F

	var components []byte
	switch firstTag {
	case 0x88: // AES key set (SCP03)
		// SCP03 always installs at KID=0x01 logically (the keyset
		// is one entry from the host's KIT view, regardless of
		// the three sub-KIDs ENC/MAC/DEK that the card creates
		// internally). We register at 0x01 ignoring the P2 KID
		// because for SCP03 the wire P2 also carries 0x01 with
		// the multi-key flag set.
		kid = 0x01
		// AES-128 only (16-byte key). The mock's
		// synthesizeSCP03KeySetPutKeyResponse already requires
		// the body length match an AES-128 keyset shape, so
		// bodies that get this far have been validated.
		components = []byte{0x88, 0x10}
	case 0xA1, 0xB1: // EC private (SCP11 SD slot installation)
		components = []byte{0x88, 0x88}
	case 0xB0: // EC public (CA/OCE trust anchor)
		components = []byte{0x88, 0x88}
	default:
		// Unknown PUT KEY shape: don't touch inventory, but don't
		// reject the APDU either (the response side already
		// handles the EC-keyless / SCP03-keyless fallback case
		// correctly).
		return
	}

	// Replace semantic: if P1 is non-zero, the new key replaces
	// an existing keyset at version P1. Unregister the old entry
	// before adding the new one. For additive installs (P1=0x00)
	// we just add.
	if p1 != 0 {
		c.unregisterKey(kid, p1)
	}
	c.registerKey(kid, newKVN, components)
}

// applyGenerateKeyToInventory registers an entry for a key just
// generated on-card via GENERATE EC KEY (INS=0xF1). The library's
// generateECKeyCmd places:
//
//   - the REPLACE KVN in P1 (0x00 = additive install)
//   - the KID in P2
//   - the NEW KVN as body[0]
//   - F0 TLV (curve params) following body[0]
//
// On a non-zero P1 we also remove the old entry at (KID, P1) — the
// GP "replace" semantic — before registering the new one.
func (c *MockCard) applyGenerateKeyToInventory(p1, p2 byte, body []byte) {
	if len(body) < 1 {
		return
	}
	kid := p2 & 0x7F
	newKVN := body[0]
	if p1 != 0 {
		c.unregisterKey(kid, p1)
	}
	c.registerKey(kid, newKVN, []byte{0x88, 0x88})
}

// applyDeleteKeyToInventory parses a DELETE KEY body and removes
// matching entries. Body shape per GP §11.5:
//
//   - D0 LL KID  (delete all keys with this KID)
//   - D2 LL KVN  (delete all keys with this KVN)
//   - both       (delete the specific (KID, KVN) entry)
//
// At least one of D0 or D2 must be present per the library's
// deleteKeyCmd validation; we mirror that precondition by simply
// doing nothing if neither parses out (the APDU still records and
// returns 9000, matching idempotent real-card behavior).
//
// The p2 byte (0x00 = "more deletes pending", 0x01 = "final
// delete operation") is informational here; the inventory mutation
// applies to whatever the body specifies regardless of pending-
// state framing.
func (c *MockCard) applyDeleteKeyToInventory(_ byte, body []byte) {
	var kid, kvn byte
	hasKID, hasKVN := false, false

	// Walk D0/D2 TLVs out of the body. We don't use tlv.Decode
	// here because these are raw single-byte length encodings
	// without the BER context (D0/D2 are not BER-TLV constructed
	// tags in this body shape — they're application-defined
	// 1-byte tag + 1-byte length + 1-byte value units).
	off := 0
	for off+2 < len(body) {
		tag := body[off]
		length := body[off+1]
		if off+2+int(length) > len(body) {
			break
		}
		value := body[off+2 : off+2+int(length)]
		switch tag {
		case 0xD0:
			if len(value) == 1 {
				kid = value[0]
				hasKID = true
			}
		case 0xD2:
			if len(value) == 1 {
				kvn = value[0]
				hasKVN = true
			}
		}
		off += 2 + int(length)
	}

	switch {
	case hasKID && hasKVN:
		c.unregisterKey(kid, kvn)
	case hasKID:
		c.unregisterAllAtKID(kid)
	case hasKVN:
		c.unregisterAllAtKVN(kvn)
	default:
		// No D0/D2 in the body — nothing to delete from the
		// inventory. Real cards would reject with 6A80; we leave
		// the response side unchanged (still returns 9000) for
		// backward compat with tests that didn't model deletion
		// pre-conditions.
	}
}

// buildKeyInfoResponse marshals the current inventory into the
// Key Information Template wire shape per GP §11.3.3.1:
//
//	E0 LL
//	  C0 LL <KID> <KVN> <component_pairs...>
//	  C0 LL <KID> <KVN> <component_pairs...>
//	  ...
//
// Entries are sorted by (KID, KVN) so the response is deterministic
// across runs and across map iteration order. The library's
// parseKeyInformation walks C0 children in order; sd keys list
// further sorts on the host side, so the wire order doesn't affect
// CLI output, but a deterministic mock simplifies snapshot tests
// and trace comparisons.
//
// An empty inventory marshals to E0 00 (zero-length container).
// The library's parseKeyInformation handles that as "no keys
// installed" — sd keys list reports "no key entries" and exits
// successfully, mirroring what a freshly-erased card would show.
func (c *MockCard) buildKeyInfoResponse() []byte {
	if len(c.inventory) == 0 {
		return []byte{0xE0, 0x00}
	}
	// Sort keys deterministically.
	keys := make([]uint16, 0, len(c.inventory))
	for k := range c.inventory {
		keys = append(keys, k)
	}
	sortUint16s(keys)

	var inner []byte
	for _, k := range keys {
		e := c.inventory[k]
		body := append([]byte{e.KID, e.KVN}, e.Components...)
		inner = append(inner, tlv.Build(tlv.Tag(0xC0), body).Encode()...)
	}
	return tlv.Build(tlv.Tag(0xE0), inner).Encode()
}

// sortUint16s is a small uint16 sort. We don't import sort because
// the mock is on the hot path of every test that uses SCP03 and
// adding a stdlib package for one call site is wasteful; the inner
// loop here is O(n log n) on a list that's typically 1-5 entries
// long.
func sortUint16s(a []uint16) {
	// Insertion sort — fine for the small N we deal with here.
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}
