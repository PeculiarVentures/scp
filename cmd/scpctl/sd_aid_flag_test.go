package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDAIDFlag_Empty pins the default-ISD path: empty flag value
// resolves to (nil, nil) so callers can pass straight through to
// Open*WithAID without a special-case branch.
func TestSDAIDFlag_Empty(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := registerSDAIDFlag(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := f.Resolve()
	if err != nil {
		t.Errorf("Resolve(empty): err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("Resolve(empty): got = % X, want nil", got)
	}
}

// TestSDAIDFlag_ValidHex covers happy-path parsing across the input-
// shape variants the help text promises: bare hex, colons, spaces,
// case-insensitive.
func TestSDAIDFlag_ValidHex(t *testing.T) {
	want := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}
	cases := []struct {
		name, input string
	}{
		{"bare lower", "a000000647 2f0001"[:0] + "a0000006472f0001"},
		{"bare upper", "A0000006472F0001"},
		{"mixed case", "a0000006472F0001"},
		{"colon-separated", "A0:00:00:06:47:2F:00:01"},
		{"space-separated", "A0 00 00 06 47 2F 00 01"},
		{"dash-separated", "A0-00-00-06-47-2F-00-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			f := registerSDAIDFlag(fs)
			if err := fs.Parse([]string{"--sd-aid", tc.input}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := f.Resolve()
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Resolve(%q) = % X, want % X", tc.input, got, want)
			}
		})
	}
}

// TestSDAIDFlag_RejectsInvalid covers the four usage-error paths:
// odd-length input, non-hex characters, too short, too long.
// Every rejection should surface as *usageError so the CLI's
// flag-error reporter handles it consistently.
func TestSDAIDFlag_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name, input, contains string
	}{
		{"odd length", "A0000", "even length"},
		{"non-hex", "A000ZZ06", "invalid hex"},
		{"too short (4 bytes)", "A0000647", "out of range"},
		{"too long (17 bytes)", strings.Repeat("AB", 17), "out of range"},
		{"empty after stripping seps", "::::", "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			f := registerSDAIDFlag(fs)
			if err := fs.Parse([]string{"--sd-aid", tc.input}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := f.Resolve()
			if err == nil {
				t.Fatalf("Resolve(%q) succeeded with %X; want usage error", tc.input, got)
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("err type = %T, want *usageError", err)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("err = %q, want it to contain %q", err.Error(), tc.contains)
			}
		})
	}
}

// TestSDAIDFlag_NilHandle pins that a nil receiver Resolves cleanly
// (returns nil bytes / nil err). Callers that resolve unconditionally
// even when the flag wasn't registered (e.g. in shared helper paths
// that traverse multiple command shapes) need this to be safe.
func TestSDAIDFlag_NilHandle(t *testing.T) {
	var f *sdAIDFlag
	got, err := f.Resolve()
	if err != nil {
		t.Errorf("nil-handle Resolve: err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("nil-handle Resolve: got = % X, want nil", got)
	}
}

// TestSDAIDFlag_BoundaryLengths covers the ISO 7816-5 endpoints
// inclusive: exactly 5 bytes and exactly 16 bytes both pass.
func TestSDAIDFlag_BoundaryLengths(t *testing.T) {
	for _, n := range []int{5, 16} {
		t.Run("len "+itoa(n), func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			f := registerSDAIDFlag(fs)
			input := strings.Repeat("AB", n)
			if err := fs.Parse([]string{"--sd-aid", input}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := f.Resolve()
			if err != nil {
				t.Fatalf("Resolve(len %d): %v", n, err)
			}
			if len(got) != n {
				t.Errorf("Resolve(len %d): got len %d", n, len(got))
			}
		})
	}
}

// itoa avoids pulling in strconv just for one test format.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestSDAIDFlag_Probe_DefaultUsesISDAID confirms the unauthenticated
// probe path SELECTs the GP-default ISD AID when no override is
// supplied. Captures the on-wire SELECT and compares.
func TestSDAIDFlag_Probe_DefaultUsesISDAID(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPProbe(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdGPProbe: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("default SELECT AID = %X, want %X (GP ISD)", sel.Data, want)
	}
}

// TestSDAIDFlag_Probe_OverridePassesThrough confirms --sd-aid
// reaches the SELECT command's data field.
func TestSDAIDFlag_Probe_OverridePassesThrough(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	custom := "A0000005591010"
	if err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", custom,
	}); err != nil {
		t.Fatalf("cmdGPProbe with --sd-aid: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("--sd-aid override SELECT data = %X, want %X", sel.Data, want)
	}
}

// TestSDAIDFlag_Probe_RejectsMalformed: too-short AIDs fail at
// flag parse time before any I/O.
func TestSDAIDFlag_Probe_RejectsMalformed(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", "AB", // 1 byte — below ISO 7816-5 5-byte minimum
	})
	if err == nil {
		t.Fatal("expected validation error for too-short AID")
	}
	// Connection should not have been opened on flag-parse errors.
	if len(rec.cmds) != 0 {
		t.Errorf("malformed --sd-aid should fail before any I/O; saw %d APDUs", len(rec.cmds))
	}
}

// TestSDAIDFlag_Registry_OverridePassesThrough: the SCP03
// authenticated path threads the override through cfg.SelectAID
// and the underlying scp03.Open SELECTs that AID.
func TestSDAIDFlag_Registry_OverridePassesThrough(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", "A0000001515350",
		"--scp03-keys-default",
	}); err != nil {
		t.Fatalf("cmdGPRegistry: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("--sd-aid override SELECT data = %X, want %X", sel.Data, want)
	}
}
