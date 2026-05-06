package securitydomain_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
)

func openIdentitySession(t *testing.T) (*securitydomain.Session, *mockcard.SCP03Card) {
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

func TestSession_GetCIN_HappyPath(t *testing.T) {
	sess, mc := openIdentitySession(t)
	mc.CIN = []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

	got, err := sess.GetCIN(context.Background())
	if err != nil {
		t.Fatalf("GetCIN: %v", err)
	}
	if !bytes.Equal(got, mc.CIN) {
		t.Errorf("CIN = %X, want %X", got, mc.CIN)
	}
}

func TestSession_GetIIN_HappyPath(t *testing.T) {
	sess, mc := openIdentitySession(t)
	mc.IIN = []byte{0x12, 0x34, 0x56, 0x78, 0x90}

	got, err := sess.GetIIN(context.Background())
	if err != nil {
		t.Fatalf("GetIIN: %v", err)
	}
	if !bytes.Equal(got, mc.IIN) {
		t.Errorf("IIN = %X, want %X", got, mc.IIN)
	}
}

func TestSession_GetCIN_AbsentReturnsSentinel(t *testing.T) {
	sess, _ := openIdentitySession(t)
	// CIN field left empty: mock returns SW=6A88

	_, err := sess.GetCIN(context.Background())
	if err == nil {
		t.Fatal("expected error when CIN absent")
	}
	if !errors.Is(err, securitydomain.ErrCardIdentityMissing) {
		t.Errorf("err = %v, want wrap of ErrCardIdentityMissing", err)
	}
}

func TestSession_GetIIN_AbsentReturnsSentinel(t *testing.T) {
	sess, _ := openIdentitySession(t)

	_, err := sess.GetIIN(context.Background())
	if err == nil {
		t.Fatal("expected error when IIN absent")
	}
	if !errors.Is(err, securitydomain.ErrCardIdentityMissing) {
		t.Errorf("err = %v, want wrap of ErrCardIdentityMissing", err)
	}
}
