package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
)

func TestSession_ChangePIN(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	// Verify with the factory PIN to set the PIN-verified flag.
	if err := sess.VerifyPIN(ctx, []byte("123456")); err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if !sess.PINVerified() {
		t.Fatal("expected PINVerified true before change")
	}

	if err := sess.ChangePIN(ctx, []byte("123456"), []byte("654321")); err != nil {
		t.Fatalf("ChangePIN: %v", err)
	}
	if sess.PINVerified() {
		t.Error("PINVerified should be cleared after ChangePIN")
	}

	// Verifying with the old PIN should now fail.
	if err := sess.VerifyPIN(ctx, []byte("123456")); err == nil {
		t.Error("expected VerifyPIN with old PIN to fail after change")
	}
	// Verifying with the new PIN should succeed.
	if err := sess.VerifyPIN(ctx, []byte("654321")); err != nil {
		t.Errorf("VerifyPIN with new PIN: %v", err)
	}
}

func TestSession_ChangePIN_WrongOldPIN(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	err := sess.ChangePIN(ctx, []byte("000000"), []byte("654321"))
	if err == nil {
		t.Fatal("expected error on wrong old PIN")
	}
	if !piv.IsWrongPIN(err) {
		t.Errorf("expected IsWrongPIN, got %v", err)
	}
}

func TestSession_ChangePUK(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	if err := sess.ChangePUK(context.Background(), []byte("12345678"), []byte("87654321")); err != nil {
		t.Fatalf("ChangePUK: %v", err)
	}
	// Verify by trying UnblockPIN with old PUK (should fail) then new PUK.
	if err := sess.UnblockPIN(context.Background(), []byte("12345678"), []byte("999999")); err == nil {
		t.Error("UnblockPIN with old PUK should fail after change")
	}
}

func TestSession_UnblockPIN(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	// Block the PIN by exhausting retries.
	for i := 0; i < 5; i++ {
		_ = sess.VerifyPIN(ctx, []byte("000000"))
	}

	// Unblock with PUK + new PIN.
	if err := sess.UnblockPIN(ctx, []byte("12345678"), []byte("999999")); err != nil {
		t.Fatalf("UnblockPIN: %v", err)
	}
	if sess.PINVerified() {
		t.Error("UnblockPIN must not set PINVerified")
	}
	// The new PIN should now work.
	if err := sess.VerifyPIN(ctx, []byte("999999")); err != nil {
		t.Errorf("VerifyPIN with new PIN: %v", err)
	}
}

func TestSession_GetCertificate_RoundtripWithPut(t *testing.T) {
	c := newYKMock(t)
	preset, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.PIVPresetKey = preset

	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatalf("mgmt auth: %v", err)
	}
	if _, err := sess.GenerateKey(ctx,
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256},
	); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certBytes := mustSelfSignedCert(t, &preset.PublicKey, preset)
	cert, _ := x509.ParseCertificate(certBytes)
	if err := sess.PutCertificate(ctx,
		piv.SlotPIVAuthentication, cert,
		PutCertificateOptions{RequirePubKeyBinding: true},
	); err != nil {
		t.Fatalf("PutCertificate: %v", err)
	}

	// Read it back.
	got, err := sess.GetCertificate(ctx, piv.SlotPIVAuthentication)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("GetCertificate returned nil cert after install")
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("read-back cert bytes do not match installed cert")
	}
}

func TestSession_GetCertificate_NotInstalled(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	cert, err := sess.GetCertificate(context.Background(), piv.SlotPIVAuthentication)
	// Mock returns 6A82 (file not found) for an unwritten slot; the
	// session surfaces that as a CardError, not a (nil, nil) result.
	// The (nil, nil) shape is reserved for an explicitly-deleted
	// (empty 0x53 wrapper) state.
	if err == nil {
		t.Errorf("expected error for slot with no cert, got cert %v", cert)
	}
	if !piv.IsNotFound(err) {
		t.Errorf("expected IsNotFound, got %v", err)
	}
}

func TestSession_DeleteCertificate(t *testing.T) {
	c := newYKMock(t)
	preset, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.PIVPresetKey = preset

	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.GenerateKey(ctx, piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256}); err != nil {
		t.Fatal(err)
	}
	certBytes := mustSelfSignedCert(t, &preset.PublicKey, preset)
	cert, _ := x509.ParseCertificate(certBytes)
	if err := sess.PutCertificate(ctx, piv.SlotPIVAuthentication, cert,
		PutCertificateOptions{RequirePubKeyBinding: true}); err != nil {
		t.Fatal(err)
	}

	// Confirm cert is there.
	if got, err := sess.GetCertificate(ctx, piv.SlotPIVAuthentication); err != nil || got == nil {
		t.Fatalf("pre-delete read failed: cert=%v err=%v", got, err)
	}

	// Delete and confirm it returns nil cert (empty wrapper, not 6A82).
	if err := sess.DeleteCertificate(ctx, piv.SlotPIVAuthentication); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	got, err := sess.GetCertificate(ctx, piv.SlotPIVAuthentication)
	if err != nil {
		t.Errorf("GetCertificate after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil cert after delete")
	}
}

func TestSession_DeleteCertificate_RequiresMgmtAuth(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	err := sess.DeleteCertificate(context.Background(), piv.SlotPIVAuthentication)
	if err == nil {
		t.Fatal("expected error without mgmt auth")
	}
	if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}
}

func TestSession_ReadObject_WriteObject(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatal(err)
	}

	chuid := piv.ObjectID{0x5F, 0xC1, 0x02} // CHUID
	payload := []byte{0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED}

	if err := sess.WriteObject(ctx, chuid, payload); err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	got, err := sess.ReadObject(ctx, chuid)
	if err != nil {
		t.Fatalf("ReadObject: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("ReadObject = %X, want %X", got, payload)
	}
}

func TestSession_WriteObject_RequiresMgmtAuth(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	err := sess.WriteObject(context.Background(),
		piv.ObjectID{0x5F, 0xC1, 0x02}, []byte{0xAA})
	if err == nil {
		t.Fatal("expected error without mgmt auth")
	}
	if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}
}

func TestSession_Info(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	info := sess.Info()
	if info.ProfileName == "" {
		t.Error("ProfileName empty")
	}
	if info.PINVerified || info.MgmtKeyAuthenticated {
		t.Error("Info should report no auth before any auth call")
	}

	if err := sess.VerifyPIN(ctx, []byte("123456")); err != nil {
		t.Fatal(err)
	}
	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatal(err)
	}

	info = sess.Info()
	if !info.PINVerified || !info.MgmtKeyAuthenticated {
		t.Errorf("expected both flags true after auth, got pin=%v mgmt=%v",
			info.PINVerified, info.MgmtKeyAuthenticated)
	}
}

func TestSession_ImportKey_RefusedByStandardPIV(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	err := sess.ImportKey(context.Background(), piv.SlotPIVAuthentication,
		ImportKeyOptions{
			Algorithm:     piv.AlgorithmECCP256,
			RawPrivateKey: make([]byte, 32),
		})
	if err == nil {
		t.Fatal("expected refusal of ImportKey under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_ImportKey_RequiresMgmtAuth(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	err := sess.ImportKey(context.Background(), piv.SlotPIVAuthentication,
		ImportKeyOptions{
			Algorithm:     piv.AlgorithmECCP256,
			RawPrivateKey: make([]byte, 32),
		})
	if err == nil {
		t.Fatal("expected error without mgmt auth")
	}
	if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}
}

func TestSession_ChangeManagementKey_RefusedWithoutPriorAuth(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	newKey := make([]byte, 24)
	for i := range newKey {
		newKey[i] = 0x42
	}
	err := sess.ChangeManagementKey(context.Background(),
		piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: newKey},
		ChangeManagementKeyOptions{},
	)
	if err == nil {
		t.Fatal("expected error without prior mgmt auth")
	}
	if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}
}

func TestSession_ChangeManagementKey_RefusedAlgUnsupported(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatal(err)
	}

	// Use a profile that does not advertise AES-256.
	narrow := narrowProfile{
		name: "narrow",
		caps: profile.Capabilities{
			MgmtKeyAlgs: []piv.ManagementKeyAlgorithm{piv.ManagementKeyAlgAES192},
		},
	}
	// Replace the profile mid-session for this test; not a public
	// API but the test does it via test-only access through the
	// narrowProfile wrapper.
	narrowed := narrow.caps
	narrowed.MgmtKeyAlgs = []piv.ManagementKeyAlgorithm{piv.ManagementKeyAlgAES192}
	// Build a new session over the same mock with the narrow profile.
	sess2, err := New(ctx, c.Transport(), Options{Profile: narrow, SkipProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.Close()
	if err := sess2.AuthenticateManagementKey(ctx, mk); err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, 32)
	err = sess2.ChangeManagementKey(ctx,
		piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES256, Key: newKey},
		ChangeManagementKeyOptions{},
	)
	if err == nil {
		t.Fatal("expected refusal of AES-256 under AES-192-only profile")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_New_SkipSelectRequiresProfile(t *testing.T) {
	c := newYKMock(t)
	_, err := New(context.Background(), c.Transport(), Options{SkipSelect: true})
	if err == nil {
		t.Fatal("expected error when SkipSelect is true and Profile is nil")
	}
}

// TestSession_ChangeManagementKey_ClearsAuthState verifies that a
// successful management-key change clears the in-memory mgmtAuthed
// flag. The card invalidates the prior auth on key change; the
// session must reflect that so subsequent mgmt-gated operations
// re-authenticate with the new key rather than fail with a stale
// "already authenticated" assumption.
//
// This guards against the regression class where a host-side cache
// drifts out of sync with the card after a credential change. The
// operator pattern (rotate management key, then immediately do
// another mgmt-gated operation) must work and must use the new
// key, not silently rely on stale session state.
func TestSession_ChangeManagementKey_ClearsAuthState(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	// Authenticate with the factory key.
	oldMK := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       piv.DefaultMgmtKey,
	}
	if err := sess.AuthenticateManagementKey(ctx, oldMK); err != nil {
		t.Fatalf("AuthenticateManagementKey: %v", err)
	}
	if !sess.MgmtKeyAuthenticated() {
		t.Fatal("MgmtKeyAuthenticated should be true after auth")
	}

	// Rotate to a new key.
	newKeyBytes := make([]byte, 24)
	for i := range newKeyBytes {
		newKeyBytes[i] = 0x42
	}
	newMK := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       newKeyBytes,
	}
	if err := sess.ChangeManagementKey(ctx, newMK, ChangeManagementKeyOptions{}); err != nil {
		t.Fatalf("ChangeManagementKey: %v", err)
	}

	// Auth state must be cleared after a successful rotation.
	if sess.MgmtKeyAuthenticated() {
		t.Error("MgmtKeyAuthenticated should be cleared after ChangeManagementKey")
	}

	// Mgmt-gated operations should now refuse without re-auth.
	if err := sess.ChangeManagementKey(ctx, oldMK, ChangeManagementKeyOptions{}); err == nil {
		t.Error("expected ErrNotAuthenticated when running mgmt-gated op after rotation")
	} else if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}

	// Re-authenticate with the new key.
	if err := sess.AuthenticateManagementKey(ctx, newMK); err != nil {
		t.Fatalf("re-auth with new key: %v", err)
	}
	// And the old key should no longer work.
	if err := sess.AuthenticateManagementKey(ctx, oldMK); err == nil {
		t.Error("expected old key to fail after rotation")
	}
}

// TestSession_ChangeManagementKey_RejectsRequireTouch verifies the
// host-side rejection of opts.RequireTouch. The pivapdu builder
// hardcodes the no-touch P1 byte, so silently accepting the option
// would let a caller think they enabled touch enforcement when
// they actually got a touch-disabled key. Reject explicitly with
// ErrUnsupportedByProfile until the encoding work lands; see the
// commit message of 9fabdd8 for the design choice.
func TestSession_ChangeManagementKey_RejectsRequireTouch(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	ctx := context.Background()

	// Authenticate with the factory key first; otherwise we'd hit
	// ErrNotAuthenticated before reaching the RequireTouch gate.
	if err := sess.AuthenticateManagementKey(ctx, piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       piv.DefaultMgmtKey,
	}); err != nil {
		t.Fatalf("mgmt auth: %v", err)
	}

	newKeyBytes := make([]byte, 24)
	err := sess.ChangeManagementKey(ctx,
		piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: newKeyBytes},
		ChangeManagementKeyOptions{RequireTouch: true},
	)
	if err == nil {
		t.Fatal("expected refusal of RequireTouch")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should explain why: %v", err)
	}

	// The card must NOT have been touched: auth state should still
	// be set because the rejection happened host-side before any
	// CHANGE MGMT KEY APDU went on the wire.
	if !sess.MgmtKeyAuthenticated() {
		t.Error("MgmtKeyAuthenticated should still be true after a host-side rejection")
	}
}
