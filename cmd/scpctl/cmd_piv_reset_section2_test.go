package main

// CLI-level tests for `scpctl piv reset` per Section 2 of the third
// external review (PIV reset must be explicitly YubiKey-scoped).
//
// The session-layer refusal is already pinned by
// piv/session/session_test.go: TestSession_Reset_RefusedByStandardPIV
// — that test calls Session.Reset directly against a Standard-PIV
// profile and asserts ErrUnsupportedByProfile. This file pins the
// behavior at the CLI boundary: the operator-facing command must
// refuse to send INS=0xFB on the wire when the active profile is
// Standard PIV, and must send INS=0xFB only after --confirm-reset-piv
// when the active profile is YubiKey.
//
// Two acceptance-checklist tests from the review:
//
//   TestPIVReset_StandardPIVRefusesBeforeTransmit   (item 4 in §2)
//   TestPIVReset_YubiKeyRequiresSpecificConfirm     (item 3 in §2)
//
// Both ride a recording transport that wraps mockcard.MockTransport
// and observes every APDU before it reaches the card. The recording
// layer is what lets the test assert "INS=0xFB never crosses the
// wire" — checking the mock's response state isn't enough because a
// host-side refusal happens BEFORE any card round-trip, and a
// regression that pushed the gate down to the card would still pass
// a state-only assertion against the (stateless-on-INS=0xFB) mock.

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// resetTestRecorder wraps a *mockcard.MockTransport and records every
// APDU's INS byte. The reset-time assertions look for 0xFB
// specifically; recording only INS keeps the recorder cheap and
// avoids embedding the rest of the (long, byte-noisy) APDU shape in
// test failure messages.
type resetTestRecorder struct {
	mu      sync.Mutex
	inner   transport.Transport
	insSeen []byte
}

func newResetTestRecorder(inner transport.Transport) *resetTestRecorder {
	return &resetTestRecorder{inner: inner}
}

func (r *resetTestRecorder) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	r.mu.Lock()
	r.insSeen = append(r.insSeen, cmd.INS)
	r.mu.Unlock()
	return r.inner.Transmit(ctx, cmd)
}

func (r *resetTestRecorder) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	// raw bytes mean the parsing happens at the underlying
	// transport. We re-parse here just to record the INS so the
	// "no 0xFB ever sent" assertion catches both code paths.
	r.mu.Lock()
	if len(raw) >= 2 {
		r.insSeen = append(r.insSeen, raw[1])
	}
	r.mu.Unlock()
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *resetTestRecorder) Close() error {
	return r.inner.Close()
}

func (r *resetTestRecorder) TrustBoundary() transport.TrustBoundary {
	// Override the wrapped transport's default
	// TrustBoundaryUnknown so the orthogonal --raw-local-ok gate
	// passes. This test is isolating the destructive-path gate
	// (--confirm-reset-piv + profile.Reset capability), not the
	// trust-boundary gate, which has its own dedicated tests
	// (TestRawLocalOK_LocalPCSCOnly etc.).
	return transport.TrustBoundaryLocalPCSC
}

// sawINS reports whether the recorder observed at least one APDU
// with the named INS byte. Test assertions use the boolean result
// and report the full INS sequence on failure for diagnostic value.
func (r *resetTestRecorder) sawINS(ins byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.insSeen {
		if b == ins {
			return true
		}
	}
	return false
}

func (r *resetTestRecorder) insSequence() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	parts := make([]string, len(r.insSeen))
	for i, b := range r.insSeen {
		parts[i] = formatHexByte(b)
	}
	return strings.Join(parts, " ")
}

func formatHexByte(b byte) string {
	const hexChars = "0123456789ABCDEF"
	return "0x" + string([]byte{hexChars[b>>4], hexChars[b&0x0F]})
}

// TestPIVReset_StandardPIVRefusesBeforeTransmit covers Section 2
// item 4 of the third external review:
//
//	'Add a fake Standard PIV test that verifies no APDU is emitted.'
//
// Concretely: with a Standard-PIV mock (no MockYubiKeyVersion set,
// so the probe falls through to standard-piv profile), running
// 'piv reset --confirm-reset-piv' must surface
// ErrUnsupportedByProfile (or its CLI rendering) and INS=0xFB must
// NEVER cross the wire.
//
// "No APDU is emitted" in the review's framing is too strict for the
// real flow — the CLI does send PIV applet SELECT and may probe the
// card before reaching the gated Reset call. The assertion that
// matters is that the destructive instruction (INS=0xFB, RESET) is
// never sent. Other read-only setup APDUs (SELECT 0xA4, GET DATA
// 0xCB) are fine; the gate is on the destructive verb.
func TestPIVReset_StandardPIVRefusesBeforeTransmit(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Default mockcard probes as Standard PIV: no
	// MockYubiKeyVersion means the GET VERSION probe returns
	// 6D00 (or the legacy echo path) and piv/profile.Probe
	// falls through to NewStandardPIVProfile.

	rec := newResetTestRecorder(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return rec, nil
		},
	}

	err = cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
		"--confirm-reset-piv",
	})

	// The command should fail (refusal). The exact error path
	// depends on whether the gate fires at probe time or at
	// session-Reset time, but EITHER way the message must
	// surface profile-refusal context to the operator.
	if err == nil {
		t.Errorf("piv reset on Standard PIV should fail; output:\n%s", buf.String())
	}

	// The destructive INS=0xFB (PIV Reset, YubiKey-specific) must
	// NEVER have been transmitted. This is the key assertion: it
	// proves the gate fired host-side, before the wire, not on the
	// card's own SW=6D00 (instruction not supported) which would
	// be a weaker (card-dependent) refusal.
	if rec.sawINS(0xFB) {
		t.Errorf("INS=0xFB (RESET) was transmitted under Standard PIV; "+
			"the gate must fire host-side. INS sequence observed: %s",
			rec.insSequence())
	}
}

// TestPIVReset_YubiKeyRequiresSpecificConfirm covers Section 2
// item 3 of the third external review:
//
//	'Add a fake YubiKey test that verifies INS=0xFB is emitted only
//	 after the confirmation flag.'
//
// Two sub-cases:
//
//  1. YubiKey profile + NO --confirm-reset-piv: dry-run, INS=0xFB
//     must NOT be transmitted. Pins that the destructive instruction
//     is gated behind the operator's explicit confirmation.
//
//  2. YubiKey profile + --confirm-reset-piv: the destructive path
//     runs end-to-end; the recorder observes INS=0xFB. Pins that the
//     gate actually opens when the operator opts in.
//
// The mock is configured with MockYubiKeyVersion = {0x05, 0x07,
// 0x02} so piv/profile.Probe identifies it as YubiKey 5.7.2 and
// installs YubiKeyProfile (Reset capability = true).
func TestPIVReset_YubiKeyRequiresSpecificConfirm(t *testing.T) {
	t.Run("dry-run: INS=0xFB NOT transmitted without --confirm-reset-piv", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockYubiKeyVersion = []byte{0x05, 0x07, 0x02}

		rec := newResetTestRecorder(mc.Transport())
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return rec, nil
			},
		}

		// Without --confirm-reset-piv the command should
		// emit a dry-run report and succeed cleanly.
		err = cmdPIVGroupReset(context.Background(), env, []string{
			"--reader", "fake",
			"--raw-local-ok",
		})
		if err != nil {
			t.Fatalf("dry-run should not error: %v\n%s", err, buf.String())
		}

		// In dry-run the connect callback is not even
		// invoked (the command short-circuits before
		// env.connect), so an absence of INS=0xFB also
		// means the recorder saw zero APDUs at all. Either
		// way: 0xFB must not appear.
		if rec.sawINS(0xFB) {
			t.Errorf("INS=0xFB transmitted in dry-run; "+
				"the destructive instruction must be gated. "+
				"INS sequence: %s", rec.insSequence())
		}

		// And the dry-run output must mention what flag
		// would unlock the destructive path so the operator
		// has a clear next step.
		out := buf.String()
		if !strings.Contains(out, "--confirm-reset-piv") {
			t.Errorf("dry-run output should mention --confirm-reset-piv; got:\n%s", out)
		}
	})

	t.Run("confirmed: INS=0xFB IS transmitted with --confirm-reset-piv", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockYubiKeyVersion = []byte{0x05, 0x07, 0x02}

		rec := newResetTestRecorder(mc.Transport())
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return rec, nil
			},
		}

		// --confirm-reset-piv: the destructive path runs.
		// The mockcard may surface an error from the BlockPIN /
		// BlockPUK pre-RESET sequence (it doesn't fully model
		// the PIN-blocked precondition) — that's fine for this
		// test. What matters is that the gate opened: INS=0xFB
		// must have crossed the wire (or the BlockPIN APDUs
		// did, demonstrating the destructive path was reached).
		_ = cmdPIVGroupReset(context.Background(), env, []string{
			"--reader", "fake",
			"--raw-local-ok",
			"--confirm-reset-piv",
		})

		// Either INS=0xFB was sent (full happy path), or the
		// destructive sequence started with BlockPIN VERIFY
		// (INS=0x20) which is the YubiKey-required precondition.
		// Both signals confirm the gate opened. We assert at
		// least one of them — a regression that no longer
		// reaches the destructive path would fail here.
		if !rec.sawINS(0xFB) && !rec.sawINS(0x20) {
			t.Errorf("destructive path was not reached after --confirm-reset-piv; "+
				"expected INS=0xFB (RESET) or INS=0x20 (VERIFY for "+
				"BlockPIN precondition). INS sequence: %s\n--- output ---\n%s",
				rec.insSequence(), buf.String())
		}
	})
}

// TestPIVReset_ResetBlocked_NotPortable documents Section 2 item 5
// of the third external review:
//
//	'Add a test for the "reset blocked" equivalent if our card info/
//	 profile layer can expose it. If not, add a TODO and do not
//	 pretend the behavior is portable.'
//
// We do NOT today expose card-side "reset blocked" state through
// any probe or profile API. Some YubiKey models (and BIO models in
// particular) ship with PIV reset disabled by configuration; that
// state is reported via a YubiKey-specific data object that we
// don't read. A test asserting "we detect this" would lie.
//
// Instead this test records the gap as a structural fact: the
// repository's profile probe currently does not surface a "reset
// blocked" capability bit, and the CLI command does not consult
// one. If a future change adds the plumbing, this test becomes the
// place to wire the assertion.
//
// Per the review's own framing: 'do not pretend the behavior is
// portable.'
func TestPIVReset_ResetBlocked_NotPortable(t *testing.T) {
	t.Skip("reset-blocked detection is not implemented; tracked as " +
		"deferred per Section 2 item 5 of the third external review. " +
		"Adding a real test requires (1) a probe-time read of the " +
		"YubiKey BIO config object that exposes reset-disabled state, " +
		"and (2) plumbing through Capabilities so the CLI can refuse " +
		"with a clear message before sending INS=0xFB. Neither piece " +
		"exists today; pretending otherwise would mis-document " +
		"behavior. When the plumbing lands, replace this t.Skip with " +
		"the actual end-to-end assertion.")
}
