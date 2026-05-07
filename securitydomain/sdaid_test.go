package securitydomain_test

// Open*WithAID regression tests for the Finding 2 plumb-through.
//
// These tests pin three contracts:
//
//   1. The default-AID code path (existing OpenSCP03, OpenSCP11,
//      OpenUnauthenticated) is unchanged: still targets the GP-
//      standard ISD AID A0000001510000. Backward compat for every
//      caller that doesn't pass an explicit AID.
//
//   2. The *WithAID variants honor a non-default AID. SELECT goes
//      to the named AID; the resulting Session reports the same AID
//      via SDAID().
//
//   3. nil/empty sdAID on the *WithAID variants is equivalent to the
//      default — important so callers that always go through the
//      *WithAID path can pass nil from a CLI flag that wasn't set.
//
// The library-layer tests use a recordingTransport to assert wire
// shape without requiring a real card. The integration test against
// mockcard.Card exercises the SELECT round-trip and demonstrates
// that mockcard's MockSDAID override gates the SELECT correctly.
//
// Per the external review on feat/sd-keys-cli, Finding 2: --sd-aid
// plumbed through generic SD commands.

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// factoryConfig returns the smallest valid *scp03.Config for tests
// that don't run a full handshake (the recordingSelectTransport
// can't complete EXTERNAL AUTHENTICATE). Just enough for the API
// boundary checks (DEK validation) to pass so the SELECT goes out.
func factoryConfig() *scp03.Config {
	return &scp03.Config{Keys: scp03.DefaultKeys}
}

// recordingSelectTransport is the smallest possible Transport for
// asserting OpenUnauthenticatedWithAID's SELECT shape. It records
// every command and returns the canned response. Real handshakes
// (SCP03 INITIALIZE UPDATE, SCP11 PSO) need richer mocks; this is
// sufficient for the unauthenticated path and for SELECT-shape
// assertions.
type recordingSelectTransport struct {
	commands []*apdu.Command
	resp     *apdu.Response
	err      error
}

func (r *recordingSelectTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	r.commands = append(r.commands, cmd)
	if r.err != nil {
		return nil, r.err
	}
	return r.resp, nil
}

// TransmitRaw is part of the transport.Transport contract; not used
// by these tests (every interesting call goes through Transmit).
// Returns an error so a stray TransmitRaw caller is loud.
func (r *recordingSelectTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errSelectTransportRawUnsupported
}

func (r *recordingSelectTransport) Close() error { return nil }

// TrustBoundary returns Local for tests; not consulted by the
// SD layer paths these tests exercise but required to satisfy
// the transport.Transport interface.
func (r *recordingSelectTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryLocalPCSC
}

var errSelectTransportRawUnsupported = errSelectTransportSentinel("TransmitRaw not supported by recordingSelectTransport")

type errSelectTransportSentinel string

func (e errSelectTransportSentinel) Error() string { return string(e) }

// TestOpenUnauthenticated_DefaultAIDUnchanged pins the backward-
// compat contract: OpenUnauthenticated (no -WithAID suffix) still
// targets the GP-standard ISD AID. The function delegates to
// OpenUnauthenticatedWithAID(nil) under the hood.
func TestOpenUnauthenticated_DefaultAIDUnchanged(t *testing.T) {
	rt := &recordingSelectTransport{
		resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
	}
	sd, err := securitydomain.OpenUnauthenticated(context.Background(), rt)
	if err != nil {
		t.Fatalf("OpenUnauthenticated: %v", err)
	}
	defer sd.Close()
	if got := len(rt.commands); got != 1 {
		t.Fatalf("transport saw %d commands, want 1", got)
	}
	if got := rt.commands[0].INS; got != 0xA4 {
		t.Errorf("SELECT INS = 0x%02X, want 0xA4", got)
	}
	if !bytes.Equal(rt.commands[0].Data, securitydomain.AIDSecurityDomain) {
		t.Errorf("SELECT data = % X, want % X (GP-standard ISD)",
			rt.commands[0].Data, securitydomain.AIDSecurityDomain)
	}
	if !bytes.Equal(sd.SDAID(), securitydomain.AIDSecurityDomain) {
		t.Errorf("session.SDAID() = % X, want % X",
			sd.SDAID(), securitydomain.AIDSecurityDomain)
	}
}

// TestOpenUnauthenticatedWithAID_NilEqualsDefault pins that nil
// AID input takes the default path — important for callers that
// always plumb through *WithAID and pass nil when --sd-aid wasn't
// set.
func TestOpenUnauthenticatedWithAID_NilEqualsDefault(t *testing.T) {
	rt := &recordingSelectTransport{
		resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
	}
	sd, err := securitydomain.OpenUnauthenticatedWithAID(context.Background(), rt, nil)
	if err != nil {
		t.Fatalf("OpenUnauthenticatedWithAID(nil): %v", err)
	}
	defer sd.Close()
	if !bytes.Equal(rt.commands[0].Data, securitydomain.AIDSecurityDomain) {
		t.Errorf("nil AID should default to GP-standard ISD; got % X",
			rt.commands[0].Data)
	}
	if !bytes.Equal(sd.SDAID(), securitydomain.AIDSecurityDomain) {
		t.Errorf("session.SDAID() = % X, want default % X",
			sd.SDAID(), securitydomain.AIDSecurityDomain)
	}
}

// TestOpenUnauthenticatedWithAID_CustomAIDIsHonored pins the new
// path: a non-default AID flows through SELECT and is recorded on
// the resulting Session.
func TestOpenUnauthenticatedWithAID_CustomAIDIsHonored(t *testing.T) {
	customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	rt := &recordingSelectTransport{
		resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
	}
	sd, err := securitydomain.OpenUnauthenticatedWithAID(context.Background(), rt, customAID)
	if err != nil {
		t.Fatalf("OpenUnauthenticatedWithAID(custom): %v", err)
	}
	defer sd.Close()
	if !bytes.Equal(rt.commands[0].Data, customAID) {
		t.Errorf("SELECT data = % X, want custom % X",
			rt.commands[0].Data, customAID)
	}
	if !bytes.Equal(sd.SDAID(), customAID) {
		t.Errorf("session.SDAID() = % X, want custom % X",
			sd.SDAID(), customAID)
	}
}

// TestOpenUnauthenticatedWithAID_SDAIDIsDefensiveCopy verifies that
// mutating the input slice after Open* doesn't corrupt the session's
// stored AID, and that mutating the SDAID() return value doesn't
// corrupt the session either. Two separate guards: cloneAID at
// construction, cloneAID at accessor.
func TestOpenUnauthenticatedWithAID_SDAIDIsDefensiveCopy(t *testing.T) {
	rt := &recordingSelectTransport{
		resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
	}
	customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	sd, err := securitydomain.OpenUnauthenticatedWithAID(context.Background(), rt, customAID)
	if err != nil {
		t.Fatalf("OpenUnauthenticatedWithAID: %v", err)
	}
	defer sd.Close()

	// Mutate the input slice. Session must keep the original.
	customAID[0] = 0xFF
	if got := sd.SDAID()[0]; got != 0xA0 {
		t.Errorf("input mutation corrupted session AID; got first byte 0x%02X, want 0xA0", got)
	}

	// Mutate the accessor return. Session must still return the unmutated value.
	got := sd.SDAID()
	got[0] = 0xEE
	if again := sd.SDAID()[0]; again != 0xA0 {
		t.Errorf("accessor mutation corrupted session AID; got first byte 0x%02X, want 0xA0", again)
	}
}

// TestOpenUnauthenticatedWithAID_AgainstMockcard exercises the full
// SELECT round-trip against a mockcard configured with a non-default
// SD AID. Confirms the host-side AID parameter and the mock's
// MockSDAID override agree.
func TestOpenUnauthenticatedWithAID_AgainstMockcard(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	mc.MockSDAID = customAID
	t_ := mc.Transport()

	// Wrong AID (the GP default) should be rejected — the override
	// is in effect, so the standard ISD AID is no longer recognized.
	if _, err := securitydomain.OpenUnauthenticated(context.Background(), t_); err == nil {
		t.Error("OpenUnauthenticated should fail when MockSDAID is set; got nil")
	}

	// Correct AID resolves cleanly.
	sd, err := securitydomain.OpenUnauthenticatedWithAID(context.Background(), t_, customAID)
	if err != nil {
		t.Fatalf("OpenUnauthenticatedWithAID(custom): %v", err)
	}
	defer sd.Close()
	if !bytes.Equal(sd.SDAID(), customAID) {
		t.Errorf("session.SDAID() = % X, want % X", sd.SDAID(), customAID)
	}
}

// TestOpenSCP03_DefaultAIDUnchanged pins backward compat for the
// SCP03 path. Doesn't run a full handshake (recordingSelectTransport
// can't); just asserts the function reaches scp03.Open with the
// expected SelectAID before the handshake fails. The error return
// is fine — what matters is the SELECT shape.
func TestOpenSCP03_DefaultAIDUnchanged(t *testing.T) {
	t.Run("OpenSCP03 (no AID arg) targets ISD", func(t *testing.T) {
		rt := &recordingSelectTransport{
			// scp03.Open issues SELECT first; we don't need a
			// successful handshake, just the recorded SELECT.
			resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
		}
		_, _ = securitydomain.OpenSCP03(context.Background(), rt, factoryConfig())
		assertSelectAID(t, rt, securitydomain.AIDSecurityDomain)
	})

	t.Run("OpenSCP03WithAID(nil) targets ISD", func(t *testing.T) {
		rt := &recordingSelectTransport{
			resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
		}
		_, _ = securitydomain.OpenSCP03WithAID(context.Background(), rt, factoryConfig(), nil)
		assertSelectAID(t, rt, securitydomain.AIDSecurityDomain)
	})

	t.Run("OpenSCP03WithAID(custom) targets custom", func(t *testing.T) {
		customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02}
		rt := &recordingSelectTransport{
			resp: &apdu.Response{SW1: 0x90, SW2: 0x00},
		}
		_, _ = securitydomain.OpenSCP03WithAID(context.Background(), rt, factoryConfig(), customAID)
		assertSelectAID(t, rt, customAID)
	})
}

// assertSelectAID finds the first SELECT (INS=0xA4) command in the
// recorded stream and asserts it carries the expected AID.
func assertSelectAID(t *testing.T, rt *recordingSelectTransport, want []byte) {
	t.Helper()
	for _, cmd := range rt.commands {
		if cmd.INS == 0xA4 {
			if !bytes.Equal(cmd.Data, want) {
				t.Errorf("SELECT data = % X, want % X", cmd.Data, want)
			}
			return
		}
	}
	t.Errorf("no SELECT (INS=0xA4) recorded among %d commands", len(rt.commands))
}

// Compile-time guard: recordingSelectTransport satisfies transport.Transport.
var _ transport.Transport = (*recordingSelectTransport)(nil)
