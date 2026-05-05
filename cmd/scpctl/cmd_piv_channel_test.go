package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// pivHandler is the signature every cmdPIV* handler shares.
type pivHandler func(context.Context, *runEnv, []string) error

// pivCommandSpec describes one PIV subcommand for the table-driven
// channel-mode and confirm-write tests. The argv slice carries
// every flag the handler needs except the channel-mode pair and
// the confirmation flags; the test variants add or omit those to
// exercise each gate.
type pivCommandSpec struct {
	name string
	fn   pivHandler

	// argvWithoutChannelMode is everything the handler needs other
	// than --scp11b/--raw-local-ok and the destructive-confirmation
	// flags. The reader name is always "fake"; the connect func
	// in the test runEnv ignores it.
	argvWithoutChannelMode []string

	// destructive: handler requires --confirm-write. Some
	// credential-bearing handlers (pin verify, mgmt auth) are
	// not destructive.
	destructive bool

	// destructiveTwoGate: handler requires --confirm-reset-piv in
	// addition to --confirm-write (reset only).
	destructiveTwoGate bool
}

// pivCommandSpecs is the matrix every channel-mode test iterates
// over. New commands added to the PIV surface go here so the
// channel-mode and confirm-write coverage updates without per-
// command test duplication.
func pivCommandSpecs() []pivCommandSpec {
	return []pivCommandSpec{
		{
			name: "pin verify",
			fn:   cmdPIVPinVerify,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--pin", "123456",
			},
		},
		{
			name: "pin change",
			fn:   cmdPIVPinChange,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--old-pin", "123456",
				"--new-pin", "654321",
			},
		},
		{
			name: "pin unblock",
			fn:   cmdPIVPinUnblock,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--puk", "12345678",
				"--new-pin", "654321",
			},
		},
		{
			name: "puk change",
			fn:   cmdPIVPukChange,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--old-puk", "12345678",
				"--new-puk", "87654321",
			},
		},
		{
			name: "mgmt auth",
			fn:   cmdPIVMgmtAuth,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
			},
		},
		{
			name: "mgmt change-key",
			fn:   cmdPIVMgmtChangeKey,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--new-mgmt-key", "0102030405060708090A0B0C0D0E0F101112131415161718",
			},
			destructive: true,
		},
		{
			name: "key generate",
			fn:   cmdPIVKeyGenerate,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--slot", "9a",
			},
			destructive: true,
		},
		{
			name: "cert put",
			fn:   cmdPIVCertPut,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--slot", "9a",
				"--cert", "/dev/null",
				"--no-pubkey-binding",
			},
			destructive: true,
		},
		{
			name: "cert delete",
			fn:   cmdPIVCertDelete,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--slot", "9a",
			},
			destructive: true,
		},
		{
			name: "object put",
			fn:   cmdPIVObjectPut,
			argvWithoutChannelMode: []string{
				"--reader", "fake",
				"--id", "5fc102",
				"--in", "/dev/null",
			},
			destructive: true,
		},
		{
			name:                   "reset",
			fn:                     cmdPIVGroupReset,
			argvWithoutChannelMode: []string{"--reader", "fake"},
			destructive:            true,
			destructiveTwoGate:     true,
		},
	}
}

// newChannelTestEnv returns a runEnv backed by a mockcard, suitable
// for exercising flag-validation gates. The mock is configured with
// the Yubico factory mgmt-key so handlers that get past the channel-
// mode gate can at least open a session.
func newChannelTestEnv(t *testing.T) (*runEnv, *bytes.Buffer) {
	t.Helper()
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	return &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return card.Transport(), nil
		},
	}, &buf
}

// withDestructiveFlags returns args with the appropriate
// confirmation flag(s) prepended:
//   - slot-scoped destructive commands get --confirm-write.
//   - reset (applet-scoped) gets --confirm-reset-piv.
//
// Both flags are passed for reset-shaped commands when destructive
// is true alongside destructiveTwoGate; the legacy --confirm-write
// is now accepted-but-ignored on reset, but passing it doesn't
// hurt because --confirm-reset-piv is the operative gate.
func withDestructiveFlags(spec pivCommandSpec, args []string) []string {
	out := append([]string(nil), args...)
	if spec.destructive {
		out = append(out, "--confirm-write")
	}
	if spec.destructiveTwoGate {
		out = append(out, "--confirm-reset-piv")
	}
	return out
}

// TestChannelMode_RequiredOnEverySensitiveCommand verifies every
// credential-bearing or destructive scpctl piv command refuses to
// run without an explicit --scp11b or --raw-local-ok. This is the
// regression-protection test for the silent-downgrade gap closed
// in commit bdaff19; an operator who forgets to type a channel-
// mode flag must see a clear error before any APDU goes on the
// wire.
//
// Destructive commands additionally require --confirm-write (and
// --confirm-reset-piv for reset); to isolate the channel-mode
// gate from the confirmation gates, this test passes the
// confirmation flags so the channel-mode check is the only thing
// in front of the handler's opening of the session.
func TestChannelMode_RequiredOnEverySensitiveCommand(t *testing.T) {
	for _, spec := range pivCommandSpecs() {
		t.Run(spec.name, func(t *testing.T) {
			env, _ := newChannelTestEnv(t)
			argv := withDestructiveFlags(spec, spec.argvWithoutChannelMode)
			err := spec.fn(context.Background(), env, argv)
			if err == nil {
				t.Fatalf("%s: expected error when neither --scp11b nor --raw-local-ok is set", spec.name)
			}
			msg := err.Error()
			if !strings.Contains(msg, "--scp11b") || !strings.Contains(msg, "--raw-local-ok") {
				t.Errorf("%s: error should name both flags; got: %v", spec.name, err)
			}
		})
	}
}

// TestChannelMode_BothFlagsRejected verifies every sensitive
// command rejects --scp11b and --raw-local-ok together. An
// operator who passes both has not made a clear choice; the
// command refuses rather than silently picking one.
func TestChannelMode_BothFlagsRejected(t *testing.T) {
	for _, spec := range pivCommandSpecs() {
		t.Run(spec.name, func(t *testing.T) {
			env, _ := newChannelTestEnv(t)
			argv := withDestructiveFlags(spec, append(
				append([]string(nil), spec.argvWithoutChannelMode...),
				"--scp11b", "--raw-local-ok",
			))
			err := spec.fn(context.Background(), env, argv)
			if err == nil {
				t.Fatalf("%s: expected error when both channel-mode flags set", spec.name)
			}
			if !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("%s: error should mention mutual exclusion: %v", spec.name, err)
			}
		})
	}
}

// TestConfirmWrite_RequiredOnDestructive verifies every
// slot-scoped destructive scpctl piv command refuses to run
// without --confirm-write. The confirmation gate fires before any
// session-open or APDU-transmit, so this test exercises pure
// flag validation.
//
// 'piv reset' is excluded: it's applet-scoped, not slot-scoped,
// so its confirmation gate is --confirm-reset-piv, not
// --confirm-write. Its dry-run-with-deprecation-SKIP behavior is
// asserted by TestConfirmResetPIV_LegacyConfirmWriteIsDryRun
// instead.
//
// The channel-mode flags are NOT passed here, but the test does
// not expect the channel-mode error: the confirm-write gate fires
// first because it lives before openPIVSession in the handler.
// The error must mention --confirm-write specifically.
func TestConfirmWrite_RequiredOnDestructive(t *testing.T) {
	for _, spec := range pivCommandSpecs() {
		if !spec.destructive {
			continue
		}
		// Reset's gate is --confirm-reset-piv (applet-scoped),
		// not --confirm-write (slot-scoped). Tested separately.
		if spec.destructiveTwoGate {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			env, _ := newChannelTestEnv(t)
			// Pass --raw-local-ok so the channel-mode gate would
			// be satisfied; this isolates the test to the
			// destructive-confirmation gate.
			argv := append(
				append([]string(nil), spec.argvWithoutChannelMode...),
				"--raw-local-ok",
			)
			err := spec.fn(context.Background(), env, argv)
			if err == nil {
				t.Fatalf("%s: expected error without --confirm-write", spec.name)
			}
			if !strings.Contains(err.Error(), "--confirm-write") {
				t.Errorf("%s: error should mention --confirm-write: %v", spec.name, err)
			}
		})
	}
}

// TestConfirmResetPIV_LegacyConfirmWriteIsDryRun verifies the
// --confirm-write → --confirm-reset-piv flag rename is safe for
// stale scripts. Passing --confirm-write alone (without
// --confirm-reset-piv) does NOT trigger the destructive path;
// instead, the run is treated as dry-run with a deprecation SKIP
// in the output. This mirrors the same protection added to
// 'scpctl piv reset' (which has the same semantics) and the
// equivalent gate from 'scpctl sd reset'.
//
// Silently treating the old flag as the new one would defeat the
// rename — stale scripts could reset cards their authors didn't
// intend, which is exactly what the spec rename prevents.
func TestConfirmResetPIV_LegacyConfirmWriteIsDryRun(t *testing.T) {
	env, buf := newChannelTestEnv(t)
	if err := cmdPIVGroupReset(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
		"--confirm-write",
	}); err != nil {
		t.Fatalf("legacy --confirm-write should not error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"--confirm-write (deprecated)",
		"--confirm-reset-piv",
		"dry-run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "PIV applet reset to factory state") {
		t.Errorf("legacy --confirm-write alone should not trigger destructive reset\n--- output ---\n%s", out)
	}
}

// TestChannelMode_RawLocalOK_RefusedAgainstNonLocalTransport
// verifies the production gate that --raw-local-ok requires the
// transport to report TrustBoundaryLocalPCSC. The mock card returns
// TrustBoundaryUnknown by design; without the asLocal wrapper, the
// gate must refuse with an error naming the boundary mismatch.
//
// This is the safety-relevant test for the trust-boundary feature:
// it pins the behavior that an operator cannot raw-mode their way
// past the gate just by passing --raw-local-ok against a transport
// whose underlying boundary disagrees. Future relay or browser-
// mediated transports inherit this protection automatically because
// the gate is structural, not flag-driven.
func TestChannelMode_RawLocalOK_RefusedAgainstNonLocalTransport(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			// Bare mock; TrustBoundary() returns Unknown.
			return card.Transport(), nil
		},
	}

	err = cmdPIVMgmtAuth(context.Background(), env, []string{
		"--reader", "fake",
		"--raw-local-ok",
	})
	if err != nil {
		// The CLI handler swallows the gate error into the report
		// rather than returning it; check the buffer below.
		t.Logf("handler returned: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "--raw-local-ok refused") {
		t.Errorf("expected gate-refusal text in output:\n%s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected error to name the actual boundary 'unknown':\n%s", out)
	}
	if !strings.Contains(out, "local-pcsc") {
		t.Errorf("expected error to name required 'local-pcsc' boundary:\n%s", out)
	}
}
