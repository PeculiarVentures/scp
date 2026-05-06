package securitydomain_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

func openInstallSession(t *testing.T) (*securitydomain.Session, *mockcard.SCP03Card) {
	t.Helper()
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	sess, err := securitydomain.OpenSCP03(context.Background(), mc.Transport(), &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: 0xFF,
	})
	if err != nil {
		t.Fatalf("OpenSCP03: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess, mc
}

func sampleOpts() securitydomain.InstallOptions {
	return securitydomain.InstallOptions{
		LoadFileAID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01},
		ModuleAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
		AppletAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
		LoadImage:   bytes.Repeat([]byte{0xCA, 0xFE, 0xBA, 0xBE}, 200), // 800 bytes => 4 LOAD blocks at default 200/block
		LoadParams:  []byte{0xC8, 0x02, 0x01, 0x00},
		Privileges:  []byte{0x00},
	}
}

// --- happy path ---------------------------------------------------------

func TestSession_Install_HappyPath_RegistryReflectsState(t *testing.T) {
	sess, mc := openInstallSession(t)
	opts := sampleOpts()

	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Load file recorded.
	if len(mc.RegistryLoadFiles) != 1 {
		t.Fatalf("RegistryLoadFiles count = %d, want 1", len(mc.RegistryLoadFiles))
	}
	if !bytes.Equal(mc.RegistryLoadFiles[0].AID, opts.LoadFileAID) {
		t.Errorf("load file AID = %X, want %X",
			mc.RegistryLoadFiles[0].AID, opts.LoadFileAID)
	}
	// Applet registered with AssociatedSDAID linking to the load file.
	if len(mc.RegistryApps) != 1 {
		t.Fatalf("RegistryApps count = %d, want 1", len(mc.RegistryApps))
	}
	if !bytes.Equal(mc.RegistryApps[0].AID, opts.AppletAID) {
		t.Errorf("applet AID = %X, want %X",
			mc.RegistryApps[0].AID, opts.AppletAID)
	}
	if !bytes.Equal(mc.RegistryApps[0].AssociatedSDAID, opts.LoadFileAID) {
		t.Errorf("applet AssociatedSDAID = %X, want load file %X",
			mc.RegistryApps[0].AssociatedSDAID, opts.LoadFileAID)
	}
}

// --- stage 1: INSTALL [for load] failure --------------------------------

func TestSession_Install_FailsAtInstallForLoad(t *testing.T) {
	sess, mc := openInstallSession(t)
	mc.AddFault(mockcard.FailInstallForLoad(0x6A84)) // not enough memory

	err := sess.Install(context.Background(), sampleOpts())
	if err == nil {
		t.Fatal("Install should have failed")
	}

	var pe *securitydomain.PartialInstallError
	if !errors.As(err, &pe) {
		t.Fatalf("error type = %T, want *PartialInstallError", err)
	}
	if pe.Stage != securitydomain.StageInstallForLoad {
		t.Errorf("Stage = %v, want StageInstallForLoad", pe.Stage)
	}
	if pe.SW != 0x6A84 {
		t.Errorf("SW = 0x%04X, want 0x6A84", pe.SW)
	}
	if len(pe.LoadFileAID) != 0 {
		t.Errorf("LoadFileAID should be empty before INSTALL [for load] succeeds; got %X",
			pe.LoadFileAID)
	}
	if pe.BytesLoaded != 0 {
		t.Errorf("BytesLoaded = %d, want 0", pe.BytesLoaded)
	}
	if pe.LastBlockSeq != -1 {
		t.Errorf("LastBlockSeq = %d, want -1", pe.LastBlockSeq)
	}
	// No registry mutation should have happened.
	if len(mc.RegistryLoadFiles) != 0 || len(mc.RegistryApps) != 0 {
		t.Errorf("registries should be empty after stage-1 failure: load=%v apps=%v",
			mc.RegistryLoadFiles, mc.RegistryApps)
	}
	// CleanupRecipe is empty when nothing was applied.
	if got := pe.CleanupRecipe(); got != "" {
		t.Errorf("CleanupRecipe = %q, want empty (nothing to clean up)", got)
	}
	// Error message contains the stage name.
	if !strings.Contains(err.Error(), "INSTALL [for load]") {
		t.Errorf("error message should mention INSTALL [for load]: %v", err)
	}
}

// --- stage 2: LOAD failure ----------------------------------------------

func TestSession_Install_FailsAtLoadMidStream(t *testing.T) {
	sess, mc := openInstallSession(t)
	mc.AddFault(mockcard.FailLoadAtSeq(2, 0x6A84)) // fail the third LOAD block

	opts := sampleOpts()
	err := sess.Install(context.Background(), opts)
	if err == nil {
		t.Fatal("Install should have failed")
	}
	var pe *securitydomain.PartialInstallError
	if !errors.As(err, &pe) {
		t.Fatalf("error type = %T, want *PartialInstallError", err)
	}
	if pe.Stage != securitydomain.StageLoad {
		t.Errorf("Stage = %v, want StageLoad", pe.Stage)
	}
	if pe.SW != 0x6A84 {
		t.Errorf("SW = 0x%04X, want 0x6A84", pe.SW)
	}
	// LoadFileAID should be set since INSTALL [for load] succeeded.
	if !bytes.Equal(pe.LoadFileAID, opts.LoadFileAID) {
		t.Errorf("LoadFileAID = %X, want %X (set after INSTALL [for load] success)",
			pe.LoadFileAID, opts.LoadFileAID)
	}
	// Two blocks made it through (seq 0 and 1); seq 2 failed.
	if pe.LastBlockSeq != 1 {
		t.Errorf("LastBlockSeq = %d, want 1 (seq 0 and 1 succeeded)", pe.LastBlockSeq)
	}
	expectedBytesLoaded := 2 * 200 // two blocks of default 200 bytes each
	if pe.BytesLoaded != expectedBytesLoaded {
		t.Errorf("BytesLoaded = %d, want %d", pe.BytesLoaded, expectedBytesLoaded)
	}
	if pe.TotalLoadBytes != len(opts.LoadImage) {
		t.Errorf("TotalLoadBytes = %d, want %d", pe.TotalLoadBytes, len(opts.LoadImage))
	}
	// CleanupRecipe should mention DELETE since the load file is partially registered.
	recipe := pe.CleanupRecipe()
	if !strings.Contains(recipe, "DELETE") {
		t.Errorf("CleanupRecipe should mention DELETE: %q", recipe)
	}
	// No applet was registered (didn't reach stage 3).
	if len(mc.RegistryApps) != 0 {
		t.Errorf("RegistryApps should be empty after stage-2 failure: %v", mc.RegistryApps)
	}
	// Error message should mention LOAD and the byte progress.
	if !strings.Contains(err.Error(), "LOAD") {
		t.Errorf("error message should mention LOAD: %v", err)
	}
	if !strings.Contains(err.Error(), "400/800") {
		t.Errorf("error message should report byte progress 400/800: %v", err)
	}
}

// --- stage 3: INSTALL [for install] failure -----------------------------

func TestSession_Install_FailsAtInstallForInstall(t *testing.T) {
	sess, mc := openInstallSession(t)
	mc.AddFault(mockcard.FailInstallForInstall(0x6A80))

	opts := sampleOpts()
	err := sess.Install(context.Background(), opts)
	if err == nil {
		t.Fatal("Install should have failed")
	}
	var pe *securitydomain.PartialInstallError
	if !errors.As(err, &pe) {
		t.Fatalf("error type = %T, want *PartialInstallError", err)
	}
	if pe.Stage != securitydomain.StageInstallForInstall {
		t.Errorf("Stage = %v, want StageInstallForInstall", pe.Stage)
	}
	if pe.SW != 0x6A80 {
		t.Errorf("SW = 0x%04X, want 0x6A80", pe.SW)
	}
	if !bytes.Equal(pe.LoadFileAID, opts.LoadFileAID) {
		t.Errorf("LoadFileAID = %X, want %X", pe.LoadFileAID, opts.LoadFileAID)
	}
	if !bytes.Equal(pe.AppletAID, opts.AppletAID) {
		t.Errorf("AppletAID = %X, want %X", pe.AppletAID, opts.AppletAID)
	}
	if pe.BytesLoaded != len(opts.LoadImage) {
		t.Errorf("BytesLoaded = %d, want full length %d (LOAD completed before stage-3 failure)",
			pe.BytesLoaded, len(opts.LoadImage))
	}
	// Load file IS registered (LOAD completed); applet is NOT.
	if len(mc.RegistryLoadFiles) != 1 {
		t.Errorf("load file should be registered after LOAD completes: %v", mc.RegistryLoadFiles)
	}
	if len(mc.RegistryApps) != 0 {
		t.Errorf("applet should NOT be registered after stage-3 failure: %v", mc.RegistryApps)
	}
}

// --- recovery flow: failure + delete + retry succeeds -------------------

func TestSession_Install_AfterPartialFailure_DeleteThenRetrySucceeds(t *testing.T) {
	sess, mc := openInstallSession(t)
	mc.AddFault(mockcard.FailLoadAtSeq(1, 0x6A84))

	opts := sampleOpts()
	if err := sess.Install(context.Background(), opts); err == nil {
		t.Fatal("first Install should have failed")
	}
	// Card is in partial-load state. Delete the load file with cascade.
	if err := sess.Delete(context.Background(), opts.LoadFileAID, true); err != nil {
		// Note: the half-loaded load file is NOT yet in the
		// registry (LOAD didn't reach the final block). On a real
		// card, DELETE would still need to clean up the
		// allocated-but-unregistered space; on the mock there's
		// nothing in any registry to delete, so this returns
		// 6A88. The CLI will encounter the same situation on
		// real cards that don't register the load file until the
		// last LOAD block; we treat that as nominal recovery.
		var ae *securitydomain.APDUError
		if !errors.As(err, &ae) || ae.SW != 0x6A88 {
			t.Errorf("Delete after partial load: %v", err)
		}
	}

	// Retry the install — now without injected failure.
	if err := sess.Install(context.Background(), opts); err != nil {
		t.Fatalf("retry Install: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 1 {
		t.Errorf("expected load file registered after retry; got %v", mc.RegistryLoadFiles)
	}
	if len(mc.RegistryApps) != 1 {
		t.Errorf("expected applet registered after retry; got %v", mc.RegistryApps)
	}
}

// --- Delete --------------------------------------------------------------

func TestSession_Delete_NonexistentAID_ReturnsAPDUError(t *testing.T) {
	sess, _ := openInstallSession(t)
	missing := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err := sess.Delete(context.Background(), missing, false)
	if err == nil {
		t.Fatal("Delete on missing AID should fail")
	}
	var ae *securitydomain.APDUError
	if !errors.As(err, &ae) {
		t.Fatalf("err type = %T, want *APDUError", err)
	}
	if ae.SW != 0x6A88 {
		t.Errorf("SW = 0x%04X, want 0x6A88", ae.SW)
	}
}

func TestSession_Delete_RemovesAppletWithoutCascade(t *testing.T) {
	sess, mc := openInstallSession(t)
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{AID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0xAA}, Lifecycle: 0x07},
	}
	if err := sess.Delete(context.Background(), mc.RegistryApps[0].AID, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(mc.RegistryApps) != 0 {
		t.Errorf("applet should have been removed: %v", mc.RegistryApps)
	}
}

func TestSession_Delete_RelatedCascadesToLinkedApps(t *testing.T) {
	sess, mc := openInstallSession(t)
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{{AID: loadAID, Lifecycle: 0x01}}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{
			AID:             []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0xAA},
			Lifecycle:       0x07,
			AssociatedSDAID: loadAID,
		},
	}

	if err := sess.Delete(context.Background(), loadAID, true); err != nil {
		t.Fatalf("Delete with related: %v", err)
	}
	if len(mc.RegistryLoadFiles) != 0 {
		t.Errorf("load file should be deleted: %v", mc.RegistryLoadFiles)
	}
	if len(mc.RegistryApps) != 0 {
		t.Errorf("linked applet should cascade-delete: %v", mc.RegistryApps)
	}
}

// --- input validation ---------------------------------------------------

func TestSession_Install_RejectsInvalidOptions(t *testing.T) {
	sess, _ := openInstallSession(t)

	cases := []struct {
		name string
		opts securitydomain.InstallOptions
	}{
		{
			name: "missing LoadFileAID",
			opts: securitydomain.InstallOptions{
				ModuleAID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
				AppletAID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
				LoadImage: []byte{0xCA, 0xFE},
			},
		},
		{
			name: "AID too short",
			opts: securitydomain.InstallOptions{
				LoadFileAID: []byte{0x01, 0x02}, // < 5 bytes
				ModuleAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
				AppletAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
				LoadImage:   []byte{0xCA, 0xFE},
			},
		},
		{
			name: "AID too long",
			opts: securitydomain.InstallOptions{
				LoadFileAID: bytes.Repeat([]byte{0xFF}, 17),
				ModuleAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
				AppletAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
				LoadImage:   []byte{0xCA, 0xFE},
			},
		},
		{
			name: "empty LoadImage",
			opts: securitydomain.InstallOptions{
				LoadFileAID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01},
				ModuleAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
				AppletAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
				LoadImage:   nil,
			},
		},
		{
			name: "Privileges too long",
			opts: securitydomain.InstallOptions{
				LoadFileAID: []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01},
				ModuleAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01},
				AppletAID:   []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01},
				LoadImage:   []byte{0xCA, 0xFE},
				Privileges:  []byte{0x01, 0x02, 0x03, 0x04}, // >3
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sess.Install(context.Background(), tc.opts)
			if err == nil {
				t.Fatal("expected validation error")
			}
			// Validation errors should NOT be wrapped in
			// PartialInstallError — nothing got partially
			// applied because the chain never started.
			var pe *securitydomain.PartialInstallError
			if errors.As(err, &pe) {
				t.Errorf("validation error should not be wrapped in PartialInstallError: %v", err)
			}
		})
	}
}

// --- requireAuth path ---------------------------------------------------

func TestSession_Install_RequiresAuthentication(t *testing.T) {
	// Use the unauthenticated session opener so requireAuth fails.
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	sess, err := securitydomain.OpenUnauthenticated(context.Background(), mc.Transport(), nil)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sess.Close()

	err = sess.Install(context.Background(), sampleOpts())
	if err == nil {
		t.Fatal("Install on unauthenticated session should fail")
	}
}

// --- LOAD blocks > 256 ---------------------------------------------------

func TestSession_Install_RejectsImageTooLargeForOneByteSeq(t *testing.T) {
	sess, _ := openInstallSession(t)
	opts := sampleOpts()
	// Force 257 blocks at 1-byte block size: 257 bytes total.
	opts.LoadImage = bytes.Repeat([]byte{0x55}, 257)
	opts.LoadBlockSize = 1

	err := sess.Install(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for image exceeding 256-block sequence range")
	}
	var pe *securitydomain.PartialInstallError
	if !errors.As(err, &pe) {
		t.Fatalf("err type = %T, want *PartialInstallError", err)
	}
	if pe.Stage != securitydomain.StageLoad {
		t.Errorf("Stage = %v, want StageLoad", pe.Stage)
	}
}
