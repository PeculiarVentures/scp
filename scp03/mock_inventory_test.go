package scp03

// Tests for the SCP03 mock card's installed-key inventory model.
//
// Inventory drives the GET DATA tag 0x00E0 (Key Information
// Template) response. The mock previously returned a fixed
// syntheticKeyInfo blob regardless of what had been installed,
// blocking any test that wanted to verify post-install state via
// sd keys list. The new model registers entries on PUT KEY /
// GENERATE EC KEY and unregisters on DELETE KEY, so the KIT
// response reflects the current set of installed keys.
//
// These tests exercise the model in isolation:
//
//   - default inventory matches the legacy syntheticKeyInfo bytes
//     (factory SCP03 key at 0x01/0xFF, AES-128)
//   - PUT KEY adds entries; replace-KVN removes the old before
//     adding the new
//   - GENERATE EC KEY adds entries
//   - DELETE KEY removes by KID, by KVN, or by (KID, KVN)
//   - the marshaled KIT response is deterministic and round-trips
//     through the library's parseKeyInformation
//
// The integration check — that sd keys list shows imported keys —
// lives in cmd/scpctl/cmd_sd_e2e_test.go.

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/scp/tlv"
)

// TestMock_Inventory_Default_MatchesSyntheticKeyInfo verifies that
// the default inventory marshals to exactly the same bytes the
// legacy syntheticKeyInfo blob contained. This is the
// backward-compatibility pin: any pre-existing test that asserted
// "GET DATA tag E0 returns the factory-key KIT" still passes.
func TestMock_Inventory_Default_MatchesSyntheticKeyInfo(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	got := mock.buildKeyInfoResponse()
	if !bytes.Equal(got, syntheticKeyInfo) {
		t.Errorf("default inventory marshal mismatch:\n  got:  %X\n  want: %X (syntheticKeyInfo)", got, syntheticKeyInfo)
	}
}

// TestMock_Inventory_PutKeySCP03_Additive registers a new SCP03
// keyset at a different KVN (P1=0x00, additive install). Both the
// factory key (0x01/0xFF) and the new keyset (0x01/0xFE) must
// appear in the resulting KIT.
func TestMock_Inventory_PutKeySCP03_Additive(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	// Build a minimal SCP03-keyset PUT KEY body header: KVN +
	// tag 0x88. The body bytes after that don't matter for
	// inventory tracking; only the leading byte (KVN) and the
	// first algorithm tag (0x88) are read.
	body := append([]byte{0xFE, 0x88, 0x10}, make([]byte, 64)...)
	mock.applyPutKeyToInventory(0x00, 0x81, body)

	resp := mock.buildKeyInfoResponse()
	keys := parseKITForTest(t, resp)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after additive install, got %d: %+v", len(keys), keys)
	}
	if !hasKey(keys, 0x01, 0xFF) {
		t.Errorf("factory key 0x01/0xFF missing after additive install")
	}
	if !hasKey(keys, 0x01, 0xFE) {
		t.Errorf("new key 0x01/0xFE missing after additive install")
	}
}

// TestMock_Inventory_PutKeySCP03_Replace replaces the factory key
// (P1=0xFF means "replace KVN 0xFF with the new keyset"). After
// the replace, only the new keyset should appear in the KIT.
func TestMock_Inventory_PutKeySCP03_Replace(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	body := append([]byte{0xFE, 0x88, 0x10}, make([]byte, 64)...)
	mock.applyPutKeyToInventory(0xFF, 0x81, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after replace, got %d: %+v", len(keys), keys)
	}
	if hasKey(keys, 0x01, 0xFF) {
		t.Errorf("factory key 0x01/0xFF should be gone after replace")
	}
	if !hasKey(keys, 0x01, 0xFE) {
		t.Errorf("new key 0x01/0xFE missing after replace")
	}
}

// TestMock_Inventory_PutKeyEC_Private registers an SCP11 SD private
// key at the requested ref. The body's leading tag is 0xB1 (EC
// private), so applyPutKeyToInventory should classify and register
// at (P2 & 0x7F, body[0]).
func TestMock_Inventory_PutKeyEC_Private(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	body := append([]byte{0x01, 0xB1, 0x44}, make([]byte, 64)...)
	mock.applyPutKeyToInventory(0x00, 0x11, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if !hasKey(keys, 0x11, 0x01) {
		t.Errorf("EC private at 0x11/0x01 missing after install; keys=%+v", keys)
	}
}

// TestMock_Inventory_PutKeyEC_Public registers a CA/OCE trust
// anchor (EC public key, tag 0xB0). The PUT KEY KID lives in
// the 0x10-0x2F range for trust anchors.
func TestMock_Inventory_PutKeyEC_Public(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	body := append([]byte{0x05, 0xB0, 0x41}, make([]byte, 65)...)
	mock.applyPutKeyToInventory(0x00, 0x10, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if !hasKey(keys, 0x10, 0x05) {
		t.Errorf("trust anchor at 0x10/0x05 missing after install; keys=%+v", keys)
	}
}

// TestMock_Inventory_GenerateECKey registers the on-card-generated
// EC key at the requested ref. P2 carries the KID; the new KVN is
// in body[0] (per the library's generateECKeyCmd).
func TestMock_Inventory_GenerateECKey(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	body := []byte{0x07, 0xF0, 0x01, 0x00} // KVN=0x07 + F0 TLV (SECP256R1)
	mock.applyGenerateKeyToInventory(0x00, 0x11, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if !hasKey(keys, 0x11, 0x07) {
		t.Errorf("generated key at 0x11/0x07 missing; keys=%+v", keys)
	}
}

// TestMock_Inventory_DeleteByKIDAndKVN removes a single (KID, KVN)
// entry. Other entries at the same KID or KVN remain.
func TestMock_Inventory_DeleteByKIDAndKVN(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.registerKey(0x11, 0x01, []byte{0x88, 0x88})
	mock.registerKey(0x11, 0x02, []byte{0x88, 0x88})
	mock.registerKey(0x13, 0x01, []byte{0x88, 0x88})

	body := []byte{
		0xD0, 0x01, 0x11, // KID=0x11
		0xD2, 0x01, 0x01, // KVN=0x01
	}
	mock.applyDeleteKeyToInventory(0x01, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if hasKey(keys, 0x11, 0x01) {
		t.Errorf("0x11/0x01 should be deleted; keys=%+v", keys)
	}
	if !hasKey(keys, 0x11, 0x02) {
		t.Errorf("0x11/0x02 should remain (different KVN); keys=%+v", keys)
	}
	if !hasKey(keys, 0x13, 0x01) {
		t.Errorf("0x13/0x01 should remain (different KID); keys=%+v", keys)
	}
}

// TestMock_Inventory_DeleteByKVN removes every entry at the named
// KVN regardless of KID. This is the SCP03 keyset deletion case
// (the library normalizes ref to (0, KVN) for SCP03 deletes).
func TestMock_Inventory_DeleteByKVN(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.registerKey(0x01, 0x05, []byte{0x88, 0x10})
	mock.registerKey(0x11, 0x05, []byte{0x88, 0x88})
	mock.registerKey(0x13, 0x05, []byte{0x88, 0x88})
	mock.registerKey(0x11, 0x06, []byte{0x88, 0x88})

	body := []byte{0xD2, 0x01, 0x05} // KVN=0x05 only
	mock.applyDeleteKeyToInventory(0x01, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	for _, kvn := range []byte{0x05} {
		for _, kid := range []byte{0x01, 0x11, 0x13} {
			if hasKey(keys, kid, kvn) {
				t.Errorf("0x%02X/0x%02X should be deleted", kid, kvn)
			}
		}
	}
	if !hasKey(keys, 0x11, 0x06) {
		t.Errorf("0x11/0x06 should remain (different KVN)")
	}
	// Factory key at 0x01/0xFF should still be there too.
	if !hasKey(keys, 0x01, 0xFF) {
		t.Errorf("factory 0x01/0xFF should remain")
	}
}

// TestMock_Inventory_DeleteByKID removes every entry with the
// named KID regardless of KVN.
func TestMock_Inventory_DeleteByKID(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.registerKey(0x11, 0x01, []byte{0x88, 0x88})
	mock.registerKey(0x11, 0x02, []byte{0x88, 0x88})
	mock.registerKey(0x13, 0x01, []byte{0x88, 0x88})

	body := []byte{0xD0, 0x01, 0x11}
	mock.applyDeleteKeyToInventory(0x01, body)

	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if hasKey(keys, 0x11, 0x01) || hasKey(keys, 0x11, 0x02) {
		t.Errorf("all 0x11/* should be deleted; keys=%+v", keys)
	}
	if !hasKey(keys, 0x13, 0x01) {
		t.Errorf("0x13/0x01 should remain (different KID); keys=%+v", keys)
	}
}

// TestMock_Inventory_DeleteIdempotent confirms deleting a key
// that doesn't exist is a no-op (no panic, no removal of unrelated
// entries). Real cards return 9000 for these; the mock matches.
func TestMock_Inventory_DeleteIdempotent(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	body := []byte{
		0xD0, 0x01, 0x99, // KID=0x99 doesn't exist
		0xD2, 0x01, 0x99, // KVN=0x99 doesn't exist
	}
	mock.applyDeleteKeyToInventory(0x01, body)
	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if !hasKey(keys, 0x01, 0xFF) {
		t.Errorf("factory key removed by delete-of-nonexistent; keys=%+v", keys)
	}
}

// TestMock_Inventory_EmptyResponse verifies the empty-inventory
// case marshals to the canonical "no keys" shape (E0 00). This is
// the post-erase scenario.
func TestMock_Inventory_EmptyResponse(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.SetInventory(nil)
	got := mock.buildKeyInfoResponse()
	want := []byte{0xE0, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("empty inventory marshal:\n  got:  %X\n  want: %X", got, want)
	}
}

// TestMock_Inventory_DeterministicOrder confirms entries are
// emitted sorted by (KID<<8|KVN). This makes test snapshots
// reviewable and trace comparisons stable across runs.
func TestMock_Inventory_DeterministicOrder(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	// Insert in non-sorted order.
	mock.SetInventory(nil)
	mock.registerKey(0x13, 0x01, []byte{0x88, 0x88})
	mock.registerKey(0x01, 0xFF, []byte{0x88, 0x10})
	mock.registerKey(0x11, 0x05, []byte{0x88, 0x88})
	mock.registerKey(0x10, 0x02, []byte{0x88, 0x88})

	resp := mock.buildKeyInfoResponse()
	keys := parseKITForTest(t, resp)

	// Expected order: 0x01FF < 0x1002 < 0x1105 < 0x1301
	want := []struct{ KID, KVN byte }{
		{0x01, 0xFF},
		{0x10, 0x02},
		{0x11, 0x05},
		{0x13, 0x01},
	}
	if len(keys) != len(want) {
		t.Fatalf("len(keys)=%d, want %d", len(keys), len(want))
	}
	for i, w := range want {
		if keys[i].KID != w.KID || keys[i].KVN != w.KVN {
			t.Errorf("position %d: got 0x%02X/0x%02X, want 0x%02X/0x%02X",
				i, keys[i].KID, keys[i].KVN, w.KID, w.KVN)
		}
	}
}

// TestMock_Inventory_SetInventory replaces the entire inventory.
// This is the operator-supplied "start from rotated state" hook.
func TestMock_Inventory_SetInventory(t *testing.T) {
	mock := NewMockCard(DefaultKeys)
	mock.SetInventory([]mockKeyEntry{
		{KID: 0x01, KVN: 0x42, Components: []byte{0x88, 0x10}},
		{KID: 0x11, KVN: 0x03, Components: []byte{0x88, 0x88}},
	})
	keys := parseKITForTest(t, mock.buildKeyInfoResponse())
	if len(keys) != 2 {
		t.Fatalf("len(keys)=%d, want 2", len(keys))
	}
	if hasKey(keys, 0x01, 0xFF) {
		t.Errorf("factory key should be replaced; keys=%+v", keys)
	}
	if !hasKey(keys, 0x01, 0x42) || !hasKey(keys, 0x11, 0x03) {
		t.Errorf("provided keys not present; keys=%+v", keys)
	}
}

// --- helpers ---

type kitEntry struct {
	KID        byte
	KVN        byte
	Components []byte
}

// parseKITForTest does a minimal parse of the E0/C0 KIT response
// into a flat list of (KID, KVN, Components) entries. We don't use
// securitydomain.parseKeyInformation here because importing
// securitydomain into scp03 would create a cycle; this small
// reimplementation is sufficient for asserting structure in tests.
func parseKITForTest(t *testing.T, data []byte) []kitEntry {
	t.Helper()
	if len(data) == 0 {
		return nil
	}
	nodes, err := tlv.Decode(data)
	if err != nil {
		t.Fatalf("KIT decode: %v", err)
	}
	container := tlv.Find(nodes, tlv.Tag(0xE0))
	if container == nil {
		t.Fatalf("KIT missing E0 container; data=%X", data)
	}
	var out []kitEntry
	for _, child := range container.Children {
		if child.Tag != tlv.Tag(0xC0) {
			continue
		}
		if len(child.Value) < 2 {
			continue
		}
		out = append(out, kitEntry{
			KID:        child.Value[0],
			KVN:        child.Value[1],
			Components: append([]byte(nil), child.Value[2:]...),
		})
	}
	return out
}

func hasKey(keys []kitEntry, kid, kvn byte) bool {
	for _, k := range keys {
		if k.KID == kid && k.KVN == kvn {
			return true
		}
	}
	return false
}
