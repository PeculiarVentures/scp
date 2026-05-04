package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
)

// newYKMock returns a mockcard.Card configured to look like a
// YubiKey 5.7+ for PIV purposes: AES-192 management key set to the
// well-known default, PIN/PUK set to factory values.
func newYKMock(t *testing.T) *mockcard.Card {
	t.Helper()
	c, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	c.PIVMgmtKey = piv.DefaultMgmtKey
	c.PIVMgmtKeyAlgo = piv.AlgoMgmtAES192
	return c
}

// newSessionWithProfile returns a Session over the mock card with the
// given profile, skipping the auto-probe (the mock's SELECT PIV
// response shape works but skipping cuts the round-trip noise out of
// tests that exercise specific flows).
func newSessionWithProfile(t *testing.T, c *mockcard.Card, prof profile.Profile) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := New(ctx, c.Transport(), Options{Profile: prof, SkipProbe: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sess
}

func TestSession_VerifyPIN_Success(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	if sess.PINVerified() {
		t.Error("PINVerified should start false")
	}

	ctx := context.Background()
	if err := sess.VerifyPIN(ctx, []byte("123456")); err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if !sess.PINVerified() {
		t.Error("PINVerified should be true after success")
	}
}

func TestSession_VerifyPIN_WrongPIN_ExposesRetries(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	err := sess.VerifyPIN(context.Background(), []byte("000000"))
	if err == nil {
		t.Fatal("expected error on wrong PIN")
	}
	if !piv.IsWrongPIN(err) {
		t.Errorf("expected IsWrongPIN, got %v", err)
	}
	if retries, ok := piv.RetriesRemaining(err); !ok || retries == 0 {
		t.Errorf("expected RetriesRemaining > 0, got (%d, %v)", retries, ok)
	}
	if sess.PINVerified() {
		t.Error("PINVerified must be false after failure")
	}
}

func TestSession_AuthenticateManagementKey_Success(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	if sess.MgmtKeyAuthenticated() {
		t.Error("should start unauthenticated")
	}

	mk := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       piv.DefaultMgmtKey,
	}
	if err := sess.AuthenticateManagementKey(context.Background(), mk); err != nil {
		t.Fatalf("AuthenticateManagementKey: %v", err)
	}
	if !sess.MgmtKeyAuthenticated() {
		t.Error("should be authenticated after success")
	}
}

func TestSession_AuthenticateManagementKey_WrongKey(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	wrong := make([]byte, 24)
	for i := range wrong {
		wrong[i] = 0xFF
	}
	mk := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       wrong,
	}
	if err := sess.AuthenticateManagementKey(context.Background(), mk); err == nil {
		t.Fatal("expected error with wrong management key")
	}
	if sess.MgmtKeyAuthenticated() {
		t.Error("should not be marked authenticated after failure")
	}
}

func TestSession_AuthenticateManagementKey_RefusedByProfile(t *testing.T) {
	c := newYKMock(t)
	// Standard PIV does not refuse 3DES per spec, so use a profile
	// where the algorithm is genuinely not in the set: a
	// custom-narrowed YubiKey profile.
	narrow := narrowProfile{
		name: "narrow",
		caps: profile.Capabilities{
			MgmtKeyAlgs: []piv.ManagementKeyAlgorithm{piv.ManagementKeyAlgAES128},
		},
	}
	sess := newSessionWithProfile(t, c, narrow)
	defer sess.Close()

	mk := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       piv.DefaultMgmtKey,
	}
	err := sess.AuthenticateManagementKey(context.Background(), mk)
	if err == nil {
		t.Fatal("expected refusal for AES-192 under AES-128-only profile")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_GenerateKey_RequiresMgmtAuth(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	_, err := sess.GenerateKey(context.Background(),
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256},
	)
	if err == nil {
		t.Fatal("expected error without mgmt auth")
	}
	if !errors.Is(err, piv.ErrNotAuthenticated) {
		t.Errorf("expected ErrNotAuthenticated, got %v", err)
	}
}

func TestSession_GenerateKey_StandardPIVRefusesEd25519(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.GenerateKey(context.Background(),
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmEd25519},
	)
	if err == nil {
		t.Fatal("expected refusal of Ed25519 under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_GenerateKey_StandardPIVRefusesPolicy(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.GenerateKey(context.Background(),
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{
			Algorithm: piv.AlgorithmECCP256,
			PINPolicy: piv.PINPolicyOncePIV,
		},
	)
	if err == nil {
		t.Fatal("expected refusal of PIN policy under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_GenerateKey_StandardPIVRefusesAttestationSlot(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.GenerateKey(context.Background(),
		piv.SlotYubiKeyAttestation,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256},
	)
	if err == nil {
		t.Fatal("expected refusal of f9 slot under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_GenerateKey_GenerateThenInstall(t *testing.T) {
	c := newYKMock(t)
	// Preset the mock's generate response so the session sees a real
	// public key.
	preset, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("preset key: %v", err)
	}
	c.PIVPresetKey = preset

	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	mk := piv.ManagementKey{
		Algorithm: piv.ManagementKeyAlgAES192,
		Key:       piv.DefaultMgmtKey,
	}
	if err := sess.AuthenticateManagementKey(context.Background(), mk); err != nil {
		t.Fatalf("mgmt auth: %v", err)
	}

	pub, err := sess.GenerateKey(context.Background(),
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256},
	)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if pub == nil {
		t.Fatal("GenerateKey returned nil public key")
	}

	// Verify the cache.
	cached, slot, ok := sess.LastGeneratedPublicKey()
	if !ok {
		t.Fatal("LastGeneratedPublicKey not populated")
	}
	if slot != piv.SlotPIVAuthentication {
		t.Errorf("cached slot = %s, want 9a", slot)
	}
	if !piv.PublicKeysEqual(cached, pub) {
		t.Error("cached pub does not match returned pub")
	}

	// Build a self-signed cert with the matching public key and install.
	certBytes := mustSelfSignedCert(t, &preset.PublicKey, preset)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if err := sess.PutCertificate(context.Background(),
		piv.SlotPIVAuthentication, cert,
		PutCertificateOptions{RequirePubKeyBinding: true},
	); err != nil {
		t.Fatalf("PutCertificate with matching binding: %v", err)
	}
}

func TestSession_PutCertificate_BindingMismatch(t *testing.T) {
	c := newYKMock(t)
	preset, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.PIVPresetKey = preset

	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()
	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(context.Background(), mk); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.GenerateKey(context.Background(),
		piv.SlotPIVAuthentication,
		GenerateKeyOptions{Algorithm: piv.AlgorithmECCP256},
	); err != nil {
		t.Fatal(err)
	}

	// Different key entirely.
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certBytes := mustSelfSignedCert(t, &wrong.PublicKey, wrong)
	cert, _ := x509.ParseCertificate(certBytes)

	err := sess.PutCertificate(context.Background(),
		piv.SlotPIVAuthentication, cert,
		PutCertificateOptions{RequirePubKeyBinding: true},
	)
	if err == nil {
		t.Fatal("expected binding mismatch error")
	}
}

func TestSession_PutCertificate_BindingRequiresExpectedKey(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	// No GenerateKey call. Caller asks for binding but supplies no key.
	preset, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := x509.ParseCertificate(mustSelfSignedCert(t, &preset.PublicKey, preset))

	err := sess.PutCertificate(context.Background(),
		piv.SlotPIVAuthentication, cert,
		PutCertificateOptions{RequirePubKeyBinding: true},
	)
	if err == nil {
		t.Fatal("expected error for binding without expected key or recent generate")
	}
}

func TestSession_Attest_RefusedByStandardPIV(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.Attest(context.Background(), piv.SlotPIVAuthentication)
	if err == nil {
		t.Fatal("expected refusal of Attest under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_Reset_RefusedByStandardPIV(t *testing.T) {
	c := newYKMock(t)
	sess := newSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	err := sess.Reset(context.Background(), ResetOptions{})
	if err == nil {
		t.Fatal("expected refusal of Reset under Standard PIV")
	}
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Errorf("expected ErrUnsupportedByProfile, got %v", err)
	}
}

func TestSession_Reset_ClearsAuthState(t *testing.T) {
	c := newYKMock(t)

	sess := newSessionWithProfile(t, c, profile.NewYubiKeyProfile())
	defer sess.Close()

	// Force authenticated state first.
	mk := piv.ManagementKey{Algorithm: piv.ManagementKeyAlgAES192, Key: piv.DefaultMgmtKey}
	if err := sess.AuthenticateManagementKey(context.Background(), mk); err != nil {
		t.Fatalf("mgmt auth: %v", err)
	}
	if err := sess.VerifyPIN(context.Background(), []byte("123456")); err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if !sess.MgmtKeyAuthenticated() || !sess.PINVerified() {
		t.Fatal("preconditions for reset test not met")
	}

	// Block PIN by sending wrong PINs until 6983. The mock starts at
	// 3 retries; loop 4 times to be safe across implementations.
	for i := 0; i < 5; i++ {
		_ = sess.VerifyPIN(context.Background(), []byte("000000"))
	}
	// Block PUK by sending wrong PUKs to RESET RETRY COUNTER. We do
	// this directly via the existing piv builder because there's no
	// session method for unblock-with-wrong-PUK; the test only needs
	// to drive the mock's PUK counter to zero.
	for i := 0; i < 5; i++ {
		cmd, err := piv.ResetRetryCounter([]byte("00000000"), []byte("999999"))
		if err != nil {
			t.Fatalf("build RESET RETRY COUNTER: %v", err)
		}
		_, _ = c.Transport().Transmit(context.Background(), cmd)
	}

	if err := sess.Reset(context.Background(), ResetOptions{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if sess.MgmtKeyAuthenticated() {
		t.Error("Reset should clear MgmtKeyAuthenticated")
	}
	if sess.PINVerified() {
		t.Error("Reset should clear PINVerified")
	}
}

// narrowProfile is a test-only profile that lets a test exercise
// capability gating without depending on the YubiKey/StandardPIV
// constructors.
type narrowProfile struct {
	name string
	caps profile.Capabilities
}

func (n narrowProfile) Name() string                       { return n.name }
func (n narrowProfile) Capabilities() profile.Capabilities { return n.caps }

func mustSelfSignedCert(t *testing.T, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "session test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}
