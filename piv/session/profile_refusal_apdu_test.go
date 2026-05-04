package session

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/transport"
)

// countingTransport wraps an underlying transport and counts every
// Transmit call. The host-side capability gates in piv/session and
// piv/profile claim to refuse unsupported operations BEFORE any
// APDU goes on the wire; this test type exists to assert that
// claim mechanically rather than rely on visual code review.
//
// Counter is atomic so tests can sample it from any goroutine if
// the production code ever transmits in parallel (it does not
// today, but the cost of using atomic is zero).
type countingTransport struct {
	inner transport.Transport
	count int64
}

func (c *countingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	atomic.AddInt64(&c.count, 1)
	return c.inner.Transmit(ctx, cmd)
}

func (c *countingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	atomic.AddInt64(&c.count, 1)
	return c.inner.TransmitRaw(ctx, raw)
}

func (c *countingTransport) Close() error { return c.inner.Close() }

func (c *countingTransport) APDUCount() int64 { return atomic.LoadInt64(&c.count) }

// newCountingSessionWithProfile returns a Session whose underlying
// transport is wrapped in a counting transport, with SkipSelect
// and SkipProbe set so the New call itself transmits nothing. This
// makes the post-creation count exactly zero, which keeps the
// per-test 'expected zero' assertion clean: tests can compare
// directly against APDUCount() rather than tracking a baseline.
func newCountingSessionWithProfile(t *testing.T, c *mockcard.Card, prof profile.Profile) (*Session, *countingTransport) {
	t.Helper()
	wrapped := &countingTransport{inner: c.Transport()}
	sess, err := New(context.Background(), wrapped, Options{Profile: prof, SkipProbe: true, SkipSelect: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := wrapped.APDUCount(); got != 0 {
		t.Fatalf("session.New with SkipSelect+SkipProbe should emit 0 APDUs; got %d", got)
	}
	return sess, wrapped
}

// TestProfileRefusal_NoAPDUEmitted_Generate verifies that key
// generation refused by profile (Ed25519 under Standard PIV)
// does not emit any APDU. The host-side gate in
// piv/session.GenerateKey checks profile.Capabilities() and
// returns piv.ErrUnsupportedByProfile before reaching the
// transmit path.
func TestProfileRefusal_NoAPDUEmitted_Generate(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.GenerateKey(context.Background(), piv.SlotPIVAuthentication, GenerateKeyOptions{
		Algorithm: piv.AlgorithmEd25519,
	})
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Fatalf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs emitted on profile refusal; got %d", got)
	}
}

// TestProfileRefusal_NoAPDUEmitted_Attest verifies that ATTEST
// refused by profile (Standard PIV does not support YubiKey-
// specific attestation) does not emit any APDU.
func TestProfileRefusal_NoAPDUEmitted_Attest(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	_, err := sess.Attest(context.Background(), piv.SlotPIVAuthentication)
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Fatalf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs emitted on profile refusal; got %d", got)
	}
}

// TestProfileRefusal_NoAPDUEmitted_Reset verifies that RESET
// refused by profile (Standard PIV has no equivalent of the
// YubiKey-specific INS=0xFB reset) does not emit any APDU.
func TestProfileRefusal_NoAPDUEmitted_Reset(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	err := sess.Reset(context.Background(), ResetOptions{})
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Fatalf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs emitted on profile refusal; got %d", got)
	}
}

// TestProfileRefusal_NoAPDUEmitted_ImportKey verifies that
// IMPORT KEY refused by profile (Standard PIV does not support
// the YubiKey-specific INS=0xFE import) does not emit any APDU.
func TestProfileRefusal_NoAPDUEmitted_ImportKey(t *testing.T) {
	c := newYKMock(t)
	sess, ct := newCountingSessionWithProfile(t, c, profile.NewStandardPIVProfile())
	defer sess.Close()

	err := sess.ImportKey(context.Background(), piv.SlotPIVAuthentication, ImportKeyOptions{
		Algorithm:     piv.AlgorithmECCP256,
		RawPrivateKey: make([]byte, 32),
	})
	if !errors.Is(err, piv.ErrUnsupportedByProfile) {
		t.Fatalf("expected ErrUnsupportedByProfile, got %v", err)
	}
	if got := ct.APDUCount(); got != 0 {
		t.Errorf("expected zero APDUs emitted on profile refusal; got %d", got)
	}
}

// Note: a 'no-APDU on management-key algorithm refused by profile'
// test is not included because every profile in the current model
// claims the full management-key algorithm set (3DES, AES-128/192/
// 256). The structural gate exists (Capabilities.SupportsMgmtKeyAlg
// is checked before transmit in AuthenticateManagementKey and
// ChangeManagementKey, see TestSession_ChangeManagementKey_RefusedAlgUnsupported)
// but there is no test scenario where it fires today. A future
// profile that narrows the algorithm list (a non-YubiKey card with
// only AES-128, say) would activate this gate; add the test then.
