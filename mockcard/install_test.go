package mockcard

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
)

// helper: drive a single APDU through the card without going
// through SCP secure messaging. The mock's dispatchINS is the
// internal entrypoint after SM is unwrapped; tests here drive it
// directly because INSTALL/LOAD/DELETE are not specific to any
// secure-channel variant and exercising them under SCP03 or
// SCP11b would just add boilerplate without testing anything new.
func dispatchUnsecured(t *testing.T, c *Card, ins, p1, p2 byte, data []byte) *apdu.Response {
	t.Helper()
	resp, err := c.dispatchINS(&apdu.Command{
		CLA:  0x80,
		INS:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
	}, false)
	if err != nil {
		t.Fatalf("dispatchINS INS=0x%02X: %v", ins, err)
	}
	return resp
}


// buildInstallForLoadData wraps gp.BuildInstallForLoadPayload
// for tests that don't carry hash/token. Hash and token are
// zero-length here because the mock does not validate them.
// Test fixtures pass AID-shaped small fields; an overflow here
// would be a test-fixture bug, so we panic rather than thread
// errors through every test setup.
func buildInstallForLoadData(loadAID, sdAID, params []byte) []byte {
	b, err := gp.BuildInstallForLoadPayload(loadAID, sdAID, nil, params, nil)
	if err != nil {
		panic("test fixture: BuildInstallForLoadPayload: " + err.Error())
	}
	return b
}

// buildInstallForInstallData wraps gp.BuildInstallForInstallPayload
// for tests that don't carry install params/token.
func buildInstallForInstallData(loadAID, moduleAID, appletAID, privs []byte) []byte {
	b, err := gp.BuildInstallForInstallPayload(loadAID, moduleAID, appletAID, privs, nil, nil)
	if err != nil {
		panic("test fixture: BuildInstallForInstallPayload: " + err.Error())
	}
	return b
}

// --- INSTALL [for load] -------------------------------------------------

func TestInstallForLoad_HappyPath_StartsLoadContext(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	sdAID := []byte{} // 0-length means "current SD"
	resp := dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(loadAID, sdAID, nil))
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("INSTALL [for load] SW = 0x%04X, want 0x9000", got)
	}
	if c.loadCtx == nil {
		t.Fatal("loadCtx was not initialized")
	}
	if !bytes.Equal(c.loadCtx.loadFileAID, loadAID) {
		t.Errorf("loadFileAID = %X, want %X", c.loadCtx.loadFileAID, loadAID)
	}
	if c.loadCtx.expectedSeq != 0 {
		t.Errorf("expectedSeq = %d, want 0", c.loadCtx.expectedSeq)
	}
}

func TestInstallForLoad_RejectsBadP2(t *testing.T) {
	c, _ := New()
	resp := dispatchUnsecured(t, c, 0xE6, 0x02, 0xFF,
		buildInstallForLoadData([]byte{1, 2, 3, 4, 5}, nil, nil))
	if got := resp.StatusWord(); got != 0x6A86 {
		t.Errorf("SW = 0x%04X, want 0x6A86", got)
	}
}

func TestInstallForLoad_RejectsTruncatedAID(t *testing.T) {
	c, _ := New()
	// Length byte claims 8 bytes, but only 3 follow.
	bad := []byte{0x08, 0x01, 0x02, 0x03}
	resp := dispatchUnsecured(t, c, 0xE6, 0x02, 0x00, bad)
	if got := resp.StatusWord(); got != 0x6A80 {
		t.Errorf("SW = 0x%04X, want 0x6A80 (wrong data)", got)
	}
}

func TestInstallForLoad_RejectsAIDOutOfRange(t *testing.T) {
	c, _ := New()
	tooShort := []byte{1, 2, 3, 4} // 4-byte AID < ISO 7816-5 minimum 5
	resp := dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(tooShort, nil, nil))
	if got := resp.StatusWord(); got != 0x6A80 {
		t.Errorf("SW = 0x%04X, want 0x6A80", got)
	}
}

func TestInstallForLoad_RejectsTrailingBytes(t *testing.T) {
	c, _ := New()
	good := buildInstallForLoadData(
		[]byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}, nil, nil)
	resp := dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		append(good, 0xFF, 0xFF))
	if got := resp.StatusWord(); got != 0x6A80 {
		t.Errorf("SW = 0x%04X, want 0x6A80 (trailing bytes)", got)
	}
}

// --- LOAD ----------------------------------------------------------------

func TestLoad_FullSequence_RegistersLoadFile(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	versionParams := []byte{0xC8, 0x02, 0x01, 0x00} // tag 0xC8 = version 1.0
	dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(loadAID, nil, versionParams))

	// LOAD block 0: not last (P1=0x00).
	resp := dispatchUnsecured(t, c, 0xE8, 0x00, 0x00, []byte{0xAA, 0xBB})
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("LOAD[0] SW = 0x%04X", got)
	}
	// LOAD block 1: last (P1 bit 7 set).
	resp = dispatchUnsecured(t, c, 0xE8, 0x80, 0x01, []byte{0xCC, 0xDD})
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("LOAD[final] SW = 0x%04X", got)
	}
	if c.loadCtx != nil {
		t.Error("loadCtx should be cleared after final block")
	}
	if len(c.RegistryLoadFiles) != 1 {
		t.Fatalf("RegistryLoadFiles count = %d, want 1", len(c.RegistryLoadFiles))
	}
	got := c.RegistryLoadFiles[0]
	if !bytes.Equal(got.AID, loadAID) {
		t.Errorf("registered AID = %X, want %X", got.AID, loadAID)
	}
	if got.Lifecycle != 0x01 {
		t.Errorf("lifecycle = 0x%02X, want 0x01 (LOADED)", got.Lifecycle)
	}
	if !bytes.Equal(got.Version, []byte{0x01, 0x00}) {
		t.Errorf("Version = %X, want 0100 (extracted from tag 0xC8 in params)", got.Version)
	}
}

func TestLoad_WithoutPriorInstall_Returns6985(t *testing.T) {
	c, _ := New()
	resp := dispatchUnsecured(t, c, 0xE8, 0x80, 0x00, []byte{0xAA})
	if got := resp.StatusWord(); got != 0x6985 {
		t.Errorf("SW = 0x%04X, want 0x6985 (conditions not satisfied)", got)
	}
}

func TestLoad_OutOfOrderSequence_Rejected(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(loadAID, nil, nil))

	// Skip seq 0; jump straight to seq 5.
	resp := dispatchUnsecured(t, c, 0xE8, 0x00, 0x05, []byte{0xAA})
	if got := resp.StatusWord(); got != 0x6A86 {
		t.Errorf("SW = 0x%04X, want 0x6A86 (incorrect P1/P2)", got)
	}
}

// --- INSTALL [for install] ----------------------------------------------

func TestInstallForInstall_HappyPath_RegistersApplet(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	moduleAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	privs := []byte{0x00} // no special privileges

	resp := dispatchUnsecured(t, c, 0xE6, 0x04, 0x00,
		buildInstallForInstallData(loadAID, moduleAID, appletAID, privs))
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("SW = 0x%04X, want 0x9000", got)
	}
	if len(c.RegistryApps) != 1 {
		t.Fatalf("RegistryApps count = %d, want 1", len(c.RegistryApps))
	}
	got := c.RegistryApps[0]
	if !bytes.Equal(got.AID, appletAID) {
		t.Errorf("registered applet AID = %X, want %X", got.AID, appletAID)
	}
	if got.Lifecycle != 0x07 {
		t.Errorf("lifecycle = 0x%02X, want 0x07 (INSTALLED+SELECTABLE)", got.Lifecycle)
	}
	if !bytes.Equal(got.AssociatedSDAID, loadAID) {
		t.Errorf("AssociatedSDAID = %X, want %X (link to load file)",
			got.AssociatedSDAID, loadAID)
	}
}

// --- DELETE -------------------------------------------------------------

func TestDelete_RemovesRegisteredApplet(t *testing.T) {
	c, _ := New()
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	c.RegistryApps = []MockRegistryEntry{
		{AID: appletAID, Lifecycle: 0x07},
	}

	deleteData := append([]byte{0x4F, byte(len(appletAID))}, appletAID...)
	resp := dispatchUnsecured(t, c, 0xE4, 0x00, 0x00, deleteData)
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("SW = 0x%04X, want 0x9000", got)
	}
	if len(c.RegistryApps) != 0 {
		t.Errorf("RegistryApps not emptied: %v", c.RegistryApps)
	}
}

func TestDelete_NonexistentAID_Returns6A88(t *testing.T) {
	c, _ := New()
	missing := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	deleteData := append([]byte{0x4F, byte(len(missing))}, missing...)
	resp := dispatchUnsecured(t, c, 0xE4, 0x00, 0x00, deleteData)
	if got := resp.StatusWord(); got != 0x6A88 {
		t.Errorf("SW = 0x%04X, want 0x6A88 (referenced data not found)", got)
	}
}

func TestDelete_WithRelatedFlag_CascadesToLinkedApps(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletA := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0xAA}
	appletB := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0xBB}
	c.RegistryLoadFiles = []MockRegistryEntry{{AID: loadAID, Lifecycle: 0x01}}
	c.RegistryApps = []MockRegistryEntry{
		{AID: appletA, Lifecycle: 0x07, AssociatedSDAID: loadAID},
		{AID: appletB, Lifecycle: 0x07, AssociatedSDAID: loadAID},
	}

	// P2 bit 0 = "delete related"
	deleteData := append([]byte{0x4F, byte(len(loadAID))}, loadAID...)
	resp := dispatchUnsecured(t, c, 0xE4, 0x00, 0x01, deleteData)
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("SW = 0x%04X, want 0x9000", got)
	}
	if len(c.RegistryLoadFiles) != 0 {
		t.Errorf("load file should be deleted: %v", c.RegistryLoadFiles)
	}
	if len(c.RegistryApps) != 0 {
		t.Errorf("linked applets should cascade-delete: %v", c.RegistryApps)
	}
}

func TestDelete_RejectsMalformedTLV(t *testing.T) {
	c, _ := New()
	resp := dispatchUnsecured(t, c, 0xE4, 0x00, 0x00, []byte{0x99, 0x01, 0xFF})
	if got := resp.StatusWord(); got != 0x6A80 {
		t.Errorf("SW = 0x%04X, want 0x6A80 (tag != 0x4F)", got)
	}
}

// --- end-to-end: install then GET STATUS shows it ------------------------

func TestInstallEndToEnd_GetStatusReflectsInstalled(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}

	// 1. INSTALL [for load]
	dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(loadAID, nil, []byte{0xC8, 0x02, 0x01, 0x00}))
	// 2. LOAD final block
	dispatchUnsecured(t, c, 0xE8, 0x80, 0x00, []byte{0xCA, 0xFE, 0xBA, 0xBE})
	// 3. INSTALL [for install]
	dispatchUnsecured(t, c, 0xE6, 0x04, 0x00,
		buildInstallForInstallData(loadAID, loadAID, appletAID, []byte{0x00}))

	// GET STATUS for load files (P1=0x20).
	resp := dispatchUnsecured(t, c, 0xF2, 0x20, 0x02, []byte{0x4F, 0x00})
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("GET STATUS load files: SW = 0x%04X", got)
	}
	if !bytes.Contains(resp.Data, loadAID) {
		t.Errorf("GET STATUS response should contain load file AID %X", loadAID)
	}

	// GET STATUS for applications (P1=0x40).
	resp = dispatchUnsecured(t, c, 0xF2, 0x40, 0x02, []byte{0x4F, 0x00})
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("GET STATUS apps: SW = 0x%04X", got)
	}
	if !bytes.Contains(resp.Data, appletAID) {
		t.Errorf("GET STATUS response should contain applet AID %X", appletAID)
	}
}

// --- end-to-end: install then delete makes registries empty again --------

func TestInstallThenDelete_RestoresEmptyState(t *testing.T) {
	c, _ := New()
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}

	dispatchUnsecured(t, c, 0xE6, 0x02, 0x00,
		buildInstallForLoadData(loadAID, nil, nil))
	dispatchUnsecured(t, c, 0xE8, 0x80, 0x00, []byte{0xCA, 0xFE})
	dispatchUnsecured(t, c, 0xE6, 0x04, 0x00,
		buildInstallForInstallData(loadAID, loadAID, appletAID, []byte{0x00}))

	// Delete with --related flag should remove both the load file
	// and the linked applet.
	deleteData := append([]byte{0x4F, byte(len(loadAID))}, loadAID...)
	resp := dispatchUnsecured(t, c, 0xE4, 0x00, 0x01, deleteData)
	if got := resp.StatusWord(); got != 0x9000 {
		t.Fatalf("DELETE related: SW = 0x%04X", got)
	}
	if len(c.RegistryLoadFiles) != 0 || len(c.RegistryApps) != 0 {
		t.Errorf("registries should be empty: load=%v apps=%v",
			c.RegistryLoadFiles, c.RegistryApps)
	}
}
