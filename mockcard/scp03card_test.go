package mockcard_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
)

// TestSCP03Card_GPInstallRoundTrip is the keystone end-to-end
// test for the SCP03+GP combined simulator (Appendix B.10). It
// exercises the full chain:
//
//  1. SCP03 INITIALIZE UPDATE / EXTERNAL AUTHENTICATE handshake
//     against the mock card, producing an authenticated session.
//  2. INSTALL [for load] sent under SCP03 secure messaging,
//     decrypted by the SCP03 mock, dispatched via PlainHandler
//     into the embedded GPState.
//  3. LOAD chunked CAP image bytes (single-block here for brevity)
//     under SCP03 SM, dispatched the same way.
//  4. INSTALL [for install] under SCP03 SM, registering the applet.
//  5. DELETE under SCP03 SM, removing the load file with cascade.
//
// The test goes through scp03.Session.Transmit directly rather
// than through securitydomain.Session because the destructive
// install/delete API on Session is what B.3 will design — at this
// stage we're verifying the underlying composition works so B.3
// has a foundation to build on.
//
// If any step regresses (SCP03 wrap/unwrap drift, PlainHandler
// not invoked, GP dispatch not routed), this test fails loudly.
func TestSCP03Card_GPInstallRoundTrip(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}

	cfg := &scp03.Config{Keys: scp03.DefaultKeys}
	ctx := context.Background()
	sess, err := scp03.Open(ctx, mc.Transport(), cfg)
	if err != nil {
		t.Fatalf("scp03.Open: %v", err)
	}
	defer sess.Close()

	// 1. INSTALL [for load]
	installLoadData := buildInstallForLoad(loadAID, nil, []byte{0xC8, 0x02, 0x01, 0x00})
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE6, P1: 0x02, P2: 0x00, Data: installLoadData,
	})
	if err != nil {
		t.Fatalf("INSTALL [for load]: %v", err)
	}
	if sw := resp.StatusWord(); sw != 0x9000 {
		t.Fatalf("INSTALL [for load] SW=0x%04X, want 9000", sw)
	}

	// 2. LOAD final block (P1 bit 7 = last)
	resp, err = sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE8, P1: 0x80, P2: 0x00,
		Data: []byte{0xCA, 0xFE, 0xBA, 0xBE},
	})
	if err != nil {
		t.Fatalf("LOAD: %v", err)
	}
	if sw := resp.StatusWord(); sw != 0x9000 {
		t.Fatalf("LOAD SW=0x%04X, want 9000", sw)
	}

	// 3. INSTALL [for install]
	installInstallData := buildInstallForInstall(loadAID, loadAID, appletAID, []byte{0x00})
	resp, err = sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE6, P1: 0x04, P2: 0x00, Data: installInstallData,
	})
	if err != nil {
		t.Fatalf("INSTALL [for install]: %v", err)
	}
	if sw := resp.StatusWord(); sw != 0x9000 {
		t.Fatalf("INSTALL [for install] SW=0x%04X, want 9000", sw)
	}

	// 4. Verify mock's registry directly: load file + applet present.
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("RegistryLoadFiles count = %d, want 1", len(mc.RegistryLoadFiles))
	}
	if !bytes.Equal(mc.RegistryLoadFiles[0].AID, loadAID) {
		t.Errorf("load file AID = %X, want %X",
			mc.RegistryLoadFiles[0].AID, loadAID)
	}
	if len(mc.RegistryApps) != 1 {
		t.Fatalf("RegistryApps count = %d, want 1", len(mc.RegistryApps))
	}
	if !bytes.Equal(mc.RegistryApps[0].AID, appletAID) {
		t.Errorf("applet AID = %X, want %X",
			mc.RegistryApps[0].AID, appletAID)
	}

	// 5. DELETE with cascade (P2 bit 0 = delete-related)
	deleteData := append([]byte{0x4F, byte(len(loadAID))}, loadAID...)
	resp, err = sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xE4, P1: 0x00, P2: 0x01, Data: deleteData,
	})
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	if sw := resp.StatusWord(); sw != 0x9000 {
		t.Fatalf("DELETE SW=0x%04X, want 9000", sw)
	}

	// 6. Verify cascade: both load file and linked applet are gone.
	if len(mc.RegistryLoadFiles) != 0 {
		t.Errorf("RegistryLoadFiles should be empty post-delete: %v",
			mc.RegistryLoadFiles)
	}
	if len(mc.RegistryApps) != 0 {
		t.Errorf("RegistryApps should be empty post-cascade-delete: %v",
			mc.RegistryApps)
	}
}

// TestSCP03Card_GetStatus_PreSeededRegistry confirms that tests
// can pre-populate the embedded GPState's registries (a common
// pattern for tests that want a registry walk without going
// through an install sequence first).
func TestSCP03Card_GetStatus_PreSeededRegistry(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:       []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle: 0x0F,
		},
	}

	cfg := &scp03.Config{Keys: scp03.DefaultKeys}
	ctx := context.Background()
	sess, err := scp03.Open(ctx, mc.Transport(), cfg)
	if err != nil {
		t.Fatalf("scp03.Open: %v", err)
	}
	defer sess.Close()

	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xF2, P1: 0x80, P2: 0x02,
		Data: []byte{0x4F, 0x00},
	})
	if err != nil {
		t.Fatalf("GET STATUS: %v", err)
	}
	if sw := resp.StatusWord(); sw != 0x9000 {
		t.Fatalf("GET STATUS SW=0x%04X, want 9000", sw)
	}
	if !bytes.Contains(resp.Data,
		[]byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}) {
		t.Errorf("GET STATUS response should contain pre-seeded ISD AID; got %X", resp.Data)
	}
}

// --- test helpers -------------------------------------------------------


func buildInstallForLoad(loadAID, sdAID, params []byte) []byte {
	return gp.BuildInstallForLoadPayload(loadAID, sdAID, nil, params, nil)
}

func buildInstallForInstall(loadAID, moduleAID, appletAID, privs []byte) []byte {
	return gp.BuildInstallForInstallPayload(loadAID, moduleAID, appletAID, privs, nil, nil)
}
