package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSecretFlags_DefaultArgvOnly verifies the legacy argv path
// keeps working: a value passed as --pin "1234" resolves to the
// same string with no stdin or file involvement.
func TestSecretFlags_DefaultArgvOnly(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin", "1234"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := pin.resolve(newSingleShotStdin(strings.NewReader("")))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "1234" {
		t.Errorf("got %q, want %q", got, "1234")
	}
}

// TestSecretFlags_StdinPath verifies the --pin-stdin path strips
// the trailing newline and returns the line.
func TestSecretFlags_StdinPath(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin-stdin"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	src := newSingleShotStdin(strings.NewReader("4321\n"))
	got, err := pin.resolve(src)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "4321" {
		t.Errorf("got %q, want %q", got, "4321")
	}
}

// TestSecretFlags_StdinNoNewline verifies a stdin source with no
// trailing newline (e.g. EOF mid-line) still returns what was read.
func TestSecretFlags_StdinNoNewline(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin-stdin"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	src := newSingleShotStdin(strings.NewReader("9999"))
	got, err := pin.resolve(src)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "9999" {
		t.Errorf("got %q, want %q", got, "9999")
	}
}

// TestSecretFlags_FilePath verifies --pin-file reads from disk and
// strips a single trailing newline.
func TestSecretFlags_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin")
	if err := os.WriteFile(path, []byte("5555\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin-file", path}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := pin.resolve(nil) // nil stdin is fine; file path does not touch it.
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "5555" {
		t.Errorf("got %q, want %q", got, "5555")
	}
}

// TestSecretFlags_FileMissing verifies --pin-file with a bad path
// surfaces a clear error rather than crashing.
func TestSecretFlags_FileMissing(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin-file", "/no/such/path/sched"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := pin.resolve(nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "--pin-file") {
		t.Errorf("error should name the offending flag: %v", err)
	}
}

// TestSecretFlags_MutuallyExclusive verifies that supplying more
// than one form is a usage error.
func TestSecretFlags_MutuallyExclusive(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
	if err := fs.Parse([]string{"--pin", "1111", "--pin-stdin"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := pin.resolve(newSingleShotStdin(strings.NewReader("2222")))
	if err == nil {
		t.Fatal("expected error for mutually exclusive flags")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion: %v", err)
	}
}

// TestSecretFlags_StdinDoubleConsume verifies that two --*-stdin
// flags in the same invocation produce a clear error rather than
// silently feeding empty content to the second consumer.
func TestSecretFlags_StdinDoubleConsume(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	oldPIN := registerSecretFlags(fs, "old-pin", "", "Old PIN.")
	newPIN := registerSecretFlags(fs, "new-pin", "", "New PIN.")
	if err := fs.Parse([]string{"--old-pin-stdin", "--new-pin-stdin"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	src := newSingleShotStdin(strings.NewReader("first-line\nsecond-line\n"))
	if _, err := oldPIN.resolve(src); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	_, err := newPIN.resolve(src)
	if err == nil {
		t.Fatal("expected error for double stdin consumption")
	}
	if !strings.Contains(err.Error(), "already consumed") {
		t.Errorf("error should name the consumption issue: %v", err)
	}
}

// TestSecretFlags_MgmtKeyDefaultIsNotAValue verifies the management
// key 'default' literal is treated as the registered default and
// does not count as 'argv supplied a value' for mutual-exclusion
// purposes. This means --mgmt-key-stdin works without requiring
// the operator to pass an explicit non-default --mgmt-key first.
func TestSecretFlags_MgmtKeyDefaultIsNotAValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	mk := registerSecretFlags(fs, "mgmt-key", "default", "Management key.")
	// User passes only --mgmt-key-stdin; the argv default 'default'
	// is still in place but should not trigger 'mutually exclusive'.
	if err := fs.Parse([]string{"--mgmt-key-stdin"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	src := newSingleShotStdin(strings.NewReader("0102030405060708\n"))
	got, err := mk.resolve(src)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "0102030405060708" {
		t.Errorf("got %q, want hex bytes", got)
	}
}

// TestPIVPinVerify_StdinIntegration is an end-to-end test through
// the cmdPIVPinVerify handler against the mock card. Verifies the
// stdin path actually flows from runEnv into the session.
func TestPIVPinVerify_StdinIntegration(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	var buf bytes.Buffer
	env := &runEnv{
		out:    &buf,
		errOut: &buf,
		stdin:  newSingleShotStdin(strings.NewReader("123456\n")),
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return asLocal(card.Transport()), nil
		},
	}

	err = cmdPIVPinVerify(context.Background(), env, []string{
		"--reader", "fake",
		"--pin-stdin",
		"--raw-local-ok",
	})
	// Mock card's default PIN is 123456 (Yubico factory default);
	// the verify should succeed.
	if err != nil {
		t.Fatalf("cmdPIVPinVerify: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "verified") {
		t.Errorf("expected 'verified' in output:\n%s", buf.String())
	}
}

// TestSecretFlags_SecretsDoNotLeakIntoJSON exercises the credential
// paths through the CLI handlers and verifies that the secret
// values themselves never appear in the JSON output. This is the
// regression guard against accidentally adding a fmt.Sprintf("%s",
// pin) somewhere that ends up in a Report Detail or Data field.
//
// The test uses a deliberately recognizable PIN (a 12-digit value
// no real factory ships with) so a substring match on the output
// reliably catches a leak. Argument-form, stdin-form, and file-form
// inputs are all exercised because each flows through a different
// code path.
func TestSecretFlags_SecretsDoNotLeakIntoJSON(t *testing.T) {
	const sentinel = "999000111222"

	cases := []struct {
		name string
		args []string
		// Setup the runEnv: stdin source if stdin form is in args,
		// any file pre-creation, etc.
		setup func(t *testing.T) *runEnv
	}{
		{
			name: "argv_form",
			args: []string{
				"--reader", "fake",
				"--pin", sentinel,
				"--raw-local-ok",
				"--json",
			},
			setup: func(t *testing.T) *runEnv {
				return makeLeakTestEnv(t, "")
			},
		},
		{
			name: "stdin_form",
			args: []string{
				"--reader", "fake",
				"--pin-stdin",
				"--raw-local-ok",
				"--json",
			},
			setup: func(t *testing.T) *runEnv {
				return makeLeakTestEnv(t, sentinel+"\n")
			},
		},
		{
			name: "file_form",
			args: func() []string {
				dir := t.TempDir()
				path := filepath.Join(dir, "pin")
				if err := os.WriteFile(path, []byte(sentinel+"\n"), 0o600); err != nil {
					t.Fatalf("write pin file: %v", err)
				}
				return []string{
					"--reader", "fake",
					"--pin-file", path,
					"--raw-local-ok",
					"--json",
				}
			}(),
			setup: func(t *testing.T) *runEnv {
				return makeLeakTestEnv(t, "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.setup(t)
			// The verify will fail (sentinel is not the mock's PIN);
			// we intentionally want the failure path because failure
			// reports are the most likely place for a secret to leak.
			err := cmdPIVPinVerify(context.Background(), env, tc.args)

			// Every byte we emit, in stdout, stderr, AND any returned
			// error message, must NOT contain the sentinel value.
			outBuf := env.out.(*bytes.Buffer).String()
			errBuf := env.errOut.(*bytes.Buffer).String()
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			combined := outBuf + "\n" + errBuf + "\n" + errMsg
			if strings.Contains(combined, sentinel) {
				t.Errorf("secret leaked into output:\n--- combined ---\n%s\n--- end ---", combined)
			}
		})
	}
}

// makeLeakTestEnv builds a runEnv pointed at a fresh mockcard with
// the given stdin content. The buffers are concrete *bytes.Buffer
// so the leak test can read them back; the io.Writer interface
// would hide that.
func makeLeakTestEnv(t *testing.T, stdinContent string) *runEnv {
	t.Helper()
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	env := &runEnv{
		out:    out,
		errOut: errOut,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return card.Transport(), nil
		},
	}
	if stdinContent != "" {
		env.stdin = newSingleShotStdin(strings.NewReader(stdinContent))
	}
	return env
}

// TestSecretFlags_MgmtKeySecretsDoNotLeak is the same shape of
// test but for the management-key flag. Mgmt keys are typically
// hex-encoded (24, 32, or 48 bytes); the sentinel here is a hex
// string that's the right length for AES-192 (24 bytes = 48 hex
// chars). We verify that this material does not appear in any
// output stream when the mgmt-auth call fails.
func TestSecretFlags_MgmtKeySecretsDoNotLeak(t *testing.T) {
	const sentinelHex = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

	env := makeLeakTestEnv(t, "")
	// mgmt auth with the wrong key will fail; the failure path is
	// where a leak is most likely to surface.
	_ = cmdPIVMgmtAuth(context.Background(), env, []string{
		"--reader", "fake",
		"--mgmt-key", sentinelHex,
		"--mgmt-alg", "aes192",
		"--raw-local-ok",
		"--json",
	})

	combined := env.out.(*bytes.Buffer).String() + "\n" + env.errOut.(*bytes.Buffer).String()
	if strings.Contains(combined, sentinelHex) {
		t.Errorf("mgmt-key value leaked into output:\n%s", combined)
	}
	// Also check lowercase form because some renderers downcase hex.
	if strings.Contains(strings.ToLower(combined), strings.ToLower(sentinelHex)) {
		t.Errorf("mgmt-key value (case-insensitive) leaked into output:\n%s", combined)
	}
}
