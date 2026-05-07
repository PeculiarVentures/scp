package securitydomain

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// recordingResetTransport wraps an inner transport and counts every
// outgoing APDU by (INS, KID, KVN) so tests can assert which keys
// got the brute-force treatment and how many attempts per key.
type recordingResetTransport struct {
	inner     transport.Transport
	attempts  map[[3]byte]int // [INS, KID, KVN] -> count
	respondSW uint16          // SW to return for our reset INS bytes (0 = pass to inner)
}

func (r *recordingResetTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	// Track only the reset-related INS bytes; SELECT, GET DATA,
	// etc. flow through the inner transport untouched.
	switch cmd.INS {
	case insInitializeUpdate, insExtAuth, insIntAuth, insPerformSecOp:
		key := [3]byte{cmd.INS, cmd.P2, cmd.P1}
		if r.attempts == nil {
			r.attempts = make(map[[3]byte]int)
		}
		r.attempts[key]++
		// Stub a card response. After the configured threshold,
		// return AUTH_METHOD_BLOCKED so the loop exits cleanly.
		if r.respondSW != 0 && r.attempts[key] >= 3 {
			return &apdu.Response{
				SW1: byte(r.respondSW >> 8),
				SW2: byte(r.respondSW & 0xFF),
			}, nil
		}
		// 0x6300 = warning, no information — doesn't match the
		// loop's exit conditions, so the loop keeps trying.
		return &apdu.Response{SW1: 0x63, SW2: 0x00}, nil
	}
	return r.inner.Transmit(ctx, cmd)
}

func (r *recordingResetTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *recordingResetTransport) Close() error {
	return r.inner.Close()
}

func (r *recordingResetTransport) TrustBoundary() transport.TrustBoundary {
	return r.inner.TrustBoundary()
}

// TestResetSecurityDomain_UnauthenticatedPath confirms the top-level
// helper opens an unauthenticated session, enumerates installed
// keys via GET DATA E0, and brute-forces each key with the right
// INS for its type. This is the recovery path: card has been
// provisioned with custom keys, factory SCP03 is gone, no auth is
// possible — but reset still works because every attempt is wrong
// by construction.
func TestResetSecurityDomain_UnauthenticatedPath(t *testing.T) {
	// mockcard for SELECT and GET DATA E0; the recording transport
	// intercepts the reset INS bytes themselves.
	innerCard, transport := mockcardWithKIT(t, []KeyInfo{
		// SCP03 default keys.
		{Reference: NewKeyReference(KeyIDSCP03, 0xFF)},
		{Reference: NewKeyReference(0x02, 0xFF)},
		{Reference: NewKeyReference(0x03, 0xFF)},
		// SCP11b factory.
		{Reference: NewKeyReference(KeyIDSCP11b, 0x01)},
		// Custom OCE CA + SCP11a SD key (typical post-bootstrap state).
		{Reference: NewKeyReference(KeyIDOCE, 0x03)},
		{Reference: NewKeyReference(KeyIDSCP11a, 0x01)},
	})
	rec := &recordingResetTransport{
		inner:     transport,
		respondSW: swAuthMethodBlocked, // exit each loop cleanly after 3 attempts
	}

	if err := ResetSecurityDomain(context.Background(), rec); err != nil {
		t.Fatalf("ResetSecurityDomain: %v", err)
	}
	_ = innerCard

	// Confirm SCP03 hit INITIALIZE UPDATE with KID=0/KVN=0 (the
	// "default keys" sentinel — see Reset's SCP03 special case).
	if rec.attempts[[3]byte{insInitializeUpdate, 0x00, 0x00}] == 0 {
		t.Errorf("SCP03 should have been hit with INITIALIZE UPDATE at KID=0/KVN=0; attempts: %+v", rec.attempts)
	}

	// SCP03 sub-keys (KID=0x02, 0x03) must NOT be touched directly —
	// they're cleared as a side effect of the SCP03 reset.
	for kid := byte(0x02); kid <= 0x03; kid++ {
		for ins := range []byte{insInitializeUpdate, insExtAuth, insIntAuth, insPerformSecOp} {
			if rec.attempts[[3]byte{byte(ins), kid, 0xFF}] > 0 {
				t.Errorf("SCP03 sub-key KID=0x%02X should not be hit directly; attempts: %+v",
					kid, rec.attempts)
			}
		}
	}

	// SCP11b (KID=0x13) must use INTERNAL AUTHENTICATE.
	if rec.attempts[[3]byte{insIntAuth, KeyIDSCP11b, 0x01}] == 0 {
		t.Errorf("SCP11b (KID=0x13/KVN=0x01) should have been hit with INTERNAL AUTHENTICATE")
	}

	// SCP11a (KID=0x11) must use EXTERNAL AUTHENTICATE.
	if rec.attempts[[3]byte{insExtAuth, KeyIDSCP11a, 0x01}] == 0 {
		t.Errorf("SCP11a (KID=0x11/KVN=0x01) should have been hit with EXTERNAL AUTHENTICATE")
	}

	// OCE CA (KID=0x10) must use PERFORM SECURITY OPERATION.
	if rec.attempts[[3]byte{insPerformSecOp, KeyIDOCE, 0x03}] == 0 {
		t.Errorf("OCE CA (KID=0x10/KVN=0x03) should have been hit with PERFORM SECURITY OPERATION")
	}

	// Cap check: each key should hit exactly 3 attempts (where the
	// stub returns AUTH_METHOD_BLOCKED). Yubikit's loop is 65; ours
	// is 65 with early exit on AUTH_METHOD_BLOCKED. The early exit
	// is the path we exercise.
	for k, n := range rec.attempts {
		if n > 3 {
			t.Errorf("key %v hit %d times; expected early exit at 3", k, n)
		}
	}
}

// TestSession_Reset_UnauthenticatedAllowed confirms the host-side
// gate on Session.Reset allows unauthenticated sessions through.
// The recovery path depends on this.
func TestSession_Reset_UnauthenticatedAllowed(t *testing.T) {
	_, transport := mockcardWithKIT(t, []KeyInfo{
		{Reference: NewKeyReference(KeyIDSCP03, 0xFF)},
	})
	rec := &recordingResetTransport{
		inner:     transport,
		respondSW: swAuthMethodBlocked,
	}

	sd, err := OpenUnauthenticated(context.Background(), rec, nil)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()

	if err := sd.Reset(context.Background()); err != nil {
		t.Fatalf("Reset on unauthenticated session: %v", err)
	}
	if rec.attempts[[3]byte{insInitializeUpdate, 0x00, 0x00}] == 0 {
		t.Error("expected SCP03 reset attempts on unauthenticated session")
	}
}
