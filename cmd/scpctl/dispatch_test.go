package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// scpctlBinary builds the scpctl binary once per test run and
// returns its path. Subsequent calls reuse the cached path. The
// binary is built into the test's TempDir so it gets cleaned up
// automatically when the test process exits.
//
// Subprocess-based dispatch testing is the right shape for this
// because the dispatcher in main() calls os.Exit on every code
// path; rebuilding it as a return-int function would be a real
// refactor of production code. Forking the binary keeps the
// production code paths exactly as shipped and tests them through
// their actual entry point.
var (
	binaryPath string
	binaryOnce sync.Once
	binaryErr  error
)

func ensureBinary(t *testing.T) string {
	t.Helper()
	binaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "scpctl-test-*")
		if err != nil {
			binaryErr = err
			return
		}
		path := filepath.Join(dir, "scpctl")
		// `go build` from the package dir. The test binary's CWD is
		// the package dir already, so a bare `.` works.
		cmd := exec.Command("go", "build", "-o", path, ".")
		out, err := cmd.CombinedOutput()
		if err != nil {
			binaryErr = err
			t.Logf("go build output:\n%s", out)
			return
		}
		binaryPath = path
	})
	if binaryErr != nil {
		t.Fatalf("build scpctl: %v", binaryErr)
	}
	return binaryPath
}

// runScpctl executes the binary with args and returns stdout,
// stderr, and the exit code. Hardware-touching subcommands will
// fail at PC/SC connect (the test environment has no readers),
// but that failure happens *after* dispatch, so the dispatcher's
// own success or failure is what these tests care about.
func runScpctl(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := ensureBinary(t)
	cmd := exec.Command(bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run scpctl: %v (stderr: %s)", err, errBuf.String())
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// TestDispatch_Help verifies that help, --help, and -h all return
// exit 0 with the usage text on stdout (not stderr). An operator
// who asks for help has not made an error and should not see help
// on stderr.
func TestDispatch_Help(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			stdout, stderr, code := runScpctl(t, arg)
			if code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if !strings.Contains(stdout, "scpctl - administrative CLI") {
				t.Errorf("stdout should contain usage banner; got:\n%s", stdout)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty for help; got:\n%s", stderr)
			}
		})
	}
}

// TestDispatch_Version verifies version and --version both work
// and exit zero.
func TestDispatch_Version(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			stdout, _, code := runScpctl(t, arg)
			if code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if !strings.Contains(stdout, "scpctl") {
				t.Errorf("stdout should mention scpctl; got: %q", stdout)
			}
		})
	}
}

// TestDispatch_NoArgs verifies that running scpctl with no arguments
// prints usage to stderr and exits 2 (not 1, not 0). Exit 2 is the
// shell convention for "incorrect usage"; reserving exit 1 for
// runtime failures makes shell pipelines easier to write.
func TestDispatch_NoArgs(t *testing.T) {
	_, stderr, code := runScpctl(t)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr should contain usage; got:\n%s", stderr)
	}
}

// TestDispatch_UnknownGroup verifies that an unknown top-level
// subcommand prints a "unknown subcommand" message and exits 2.
func TestDispatch_UnknownGroup(t *testing.T) {
	_, stderr, code := runScpctl(t, "no-such-group")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, `unknown subcommand "no-such-group"`) {
		t.Errorf("stderr should name the unknown subcommand; got:\n%s", stderr)
	}
}

// TestDispatch_GroupHelp verifies that 'scpctl <group> help' (and
// the bare group form, which prints usage and exits 2) reach the
// expected paths.
func TestDispatch_GroupHelp(t *testing.T) {
	cases := []struct {
		group       string
		wantInUsage string
	}{
		{"test", "test subcommand"},
		{"piv", "piv subcommand"},
		{"sd", "sd subcommand"},
	}
	for _, tc := range cases {
		t.Run(tc.group+"_help", func(t *testing.T) {
			stdout, stderr, code := runScpctl(t, tc.group, "help")
			if code != 0 {
				t.Errorf("'%s help' exit = %d, want 0; stderr=%s", tc.group, code, stderr)
			}
			combined := stdout + stderr
			if !strings.Contains(strings.ToLower(combined), tc.group) {
				t.Errorf("'%s help' output should mention the group; got:\n%s", tc.group, combined)
			}
		})
		t.Run(tc.group+"_bare", func(t *testing.T) {
			// 'scpctl piv' with no subcommand prints usage to stderr
			// and exits 2.
			_, stderr, code := runScpctl(t, tc.group)
			if code != 2 {
				t.Errorf("'%s' (no sub) exit = %d, want 2", tc.group, code)
			}
			if !strings.Contains(strings.ToLower(stderr), tc.group) {
				t.Errorf("'%s' (no sub) stderr should mention the group; got:\n%s", tc.group, stderr)
			}
		})
	}
}

// TestDispatch_UnknownSubcommand verifies that 'scpctl <group>
// <bad-sub>' produces a clear error naming both the group and the
// subcommand, and exits 2.
func TestDispatch_UnknownSubcommand(t *testing.T) {
	cases := []struct {
		group string
		sub   string
	}{
		{"test", "no-such-sub"},
		{"piv", "no-such-sub"},
		{"sd", "no-such-sub"},
	}
	for _, tc := range cases {
		t.Run(tc.group+"_"+tc.sub, func(t *testing.T) {
			_, stderr, code := runScpctl(t, tc.group, tc.sub)
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if !strings.Contains(stderr, tc.group) {
				t.Errorf("stderr should name the group %q; got:\n%s", tc.group, stderr)
			}
			if !strings.Contains(stderr, tc.sub) {
				t.Errorf("stderr should name the bad subcommand %q; got:\n%s", tc.sub, stderr)
			}
		})
	}
}

// TestDispatch_PIVSubcommandHelp verifies that 'scpctl piv <sub>
// --help' reaches each PIV subcommand handler and produces flag
// usage. This is dispatch-level testing, not handler-level: we
// don't care what the help text says, only that the dispatcher
// reached the right handler.
func TestDispatch_PIVSubcommandHelp(t *testing.T) {
	subcommands := []string{
		"info",
		"pin",
		"puk",
		"mgmt",
		"key",
		"cert",
		"object",
		"reset",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			// Some of these are nested ('pin verify', 'cert put');
			// passing -h to the bare verb either prints flag usage
			// or prints the nested-verb usage. Exit codes vary:
			// 0 when usage is intentional, 1 when the underlying
			// flag package returns 'help requested' to the handler
			// and the handler propagates it as an error, 2 when
			// the parser rejects the bare -h. Any of those mean
			// the dispatcher reached the handler. The dispatcher's
			// own failure mode (unknown subcommand) is what we're
			// guarding against, and that produces stderr containing
			// 'unknown subcommand'.
			_, stderr, code := runScpctl(t, "piv", sub, "-h")
			if code == 0 || code == 1 || code == 2 {
				// Reached the handler.
			} else {
				t.Errorf("'piv %s -h' exit = %d, want 0/1/2; stderr=%s",
					sub, code, stderr)
			}
			if strings.Contains(stderr, "unknown subcommand") {
				t.Errorf("dispatcher reported unknown subcommand for 'piv %s'; stderr:\n%s",
					sub, stderr)
			}
		})
	}
}

// TestDispatch_SDSubcommandHelp verifies that 'scpctl sd <sub> -h'
// reaches each SD subcommand handler. Includes 'keys' which is a
// nested-verb dispatcher; the bare '-h' on it prints the verb list.
//
// Same structural shape as TestDispatch_PIVSubcommandHelp: we don't
// assert on the help text content, only that the dispatcher reached
// the handler (no "unknown subcommand" message).
func TestDispatch_SDSubcommandHelp(t *testing.T) {
	subcommands := []string{
		"info",
		"reset",
		"lock",
		"unlock",
		"terminate",
		"keys",
		"allowlist",
		"bootstrap-oce",
		"bootstrap-scp11a",
		"bootstrap-scp11a-sd",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			_, stderr, code := runScpctl(t, "sd", sub, "-h")
			if code != 0 && code != 1 && code != 2 {
				t.Errorf("'sd %s -h' exit = %d, want 0/1/2; stderr=%s",
					sub, code, stderr)
			}
			if strings.Contains(stderr, "unknown subcommand") {
				t.Errorf("dispatcher reported unknown subcommand for 'sd %s'; stderr:\n%s",
					sub, stderr)
			}
		})
	}
}

// TestDispatch_SDKeysVerbs verifies that 'scpctl sd keys <verb> -h'
// reaches the per-verb handler. This is the nested-dispatcher case:
// 'sd' → 'keys' → 'list'/'export'/'delete'/'generate'. Each verb has
// its own flag set, so '-h' produces flag usage output rather than
// the bare-verb-list help that 'sd keys -h' produces.
func TestDispatch_SDKeysVerbs(t *testing.T) {
	verbs := []string{"list", "export", "delete", "generate"}
	for _, v := range verbs {
		t.Run(v, func(t *testing.T) {
			_, stderr, code := runScpctl(t, "sd", "keys", v, "-h")
			if code != 0 && code != 1 && code != 2 {
				t.Errorf("'sd keys %s -h' exit = %d, want 0/1/2; stderr=%s",
					v, code, stderr)
			}
			if strings.Contains(stderr, "unknown subcommand") {
				t.Errorf("dispatcher reported unknown subcommand for 'sd keys %s'; stderr:\n%s",
					v, stderr)
			}
			if strings.Contains(stderr, "unknown keys subcommand") {
				t.Errorf("'sd keys %s' reached the keys dispatcher but the verb was rejected; stderr:\n%s",
					v, stderr)
			}
		})
	}
}

// TestDispatch_SDKeysHelpContent is a tighter version of the loose
// TestDispatch_SDKeysVerbs check: 'scpctl sd keys help' must exit 0
// AND the stdout must describe both verbs. Catches regressions where
// a future change drops the verb list, prints the wrong subcommand,
// or routes 'help' to the parent group instead of the keys handler.
func TestDispatch_SDKeysHelpContent(t *testing.T) {
	stdout, stderr, code := runScpctl(t, "sd", "keys", "help")
	if code != 0 {
		t.Errorf("'sd keys help' exit = %d, want 0; stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"scpctl sd keys",
		"list",
		"export",
		"delete",
		"generate",
		"PEM",
		"--der",
		"--confirm-delete-key",
		"INS=0xF1", // Yubico-extension transparency
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("'sd keys help' stdout missing %q; got:\n%s", want, stdout)
		}
	}
	// Help must go to stdout (not stderr) so 'cmd | less' works.
	if strings.Contains(stderr, "list") || strings.Contains(stderr, "export") {
		t.Errorf("help content leaked to stderr; stderr:\n%s", stderr)
	}
}

// TestDispatch_SDAllowlistVerbs verifies that 'scpctl sd allowlist
// <verb> -h' reaches the per-verb handler. Same shape as
// TestDispatch_SDKeysVerbs.
func TestDispatch_SDAllowlistVerbs(t *testing.T) {
	verbs := []string{"set", "clear"}
	for _, v := range verbs {
		t.Run(v, func(t *testing.T) {
			_, stderr, code := runScpctl(t, "sd", "allowlist", v, "-h")
			if code != 0 && code != 1 && code != 2 {
				t.Errorf("'sd allowlist %s -h' exit = %d, want 0/1/2; stderr=%s",
					v, code, stderr)
			}
			if strings.Contains(stderr, "unknown subcommand") {
				t.Errorf("dispatcher reported unknown subcommand for 'sd allowlist %s'; stderr:\n%s",
					v, stderr)
			}
			if strings.Contains(stderr, "unknown allowlist subcommand") {
				t.Errorf("'sd allowlist %s' reached the allowlist dispatcher but the verb was rejected; stderr:\n%s",
					v, stderr)
			}
		})
	}
}

// TestDispatch_SDAllowlistHelpContent pins that 'sd allowlist help'
// exits 0 and stdout describes both verbs plus the no-get rationale.
// The no-get note is operator-facing context that should not silently
// regress out of the help text.
func TestDispatch_SDAllowlistHelpContent(t *testing.T) {
	stdout, stderr, code := runScpctl(t, "sd", "allowlist", "help")
	if code != 0 {
		t.Errorf("'sd allowlist help' exit = %d, want 0; stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"scpctl sd allowlist",
		"set",
		"clear",
		"write-only", // the design note that there is no get verb
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("'sd allowlist help' stdout missing %q; got:\n%s", want, stdout)
		}
	}
}

// TestDispatch_TopLevelUtilities verifies the readers/probe
// dispatch paths reach their handlers. Both touch hardware so
// they will fail at the PC/SC connect step; we test that the
// failure message comes from the handler (mentions PC/SC or
// "no readers") rather than from the dispatcher (which would
// say "unknown subcommand").
func TestDispatch_TopLevelUtilities(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		wantOK bool // exit code may be nonzero (no hardware), but dispatcher should not produce 'unknown subcommand'
	}{
		{name: "readers", args: []string{"readers"}},
		{name: "probe_no_reader", args: []string{"probe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, _ := runScpctl(t, tc.args...)
			// The dispatcher's "unknown subcommand" message is what
			// we're guarding against; any other failure is the
			// handler running, which is what we want.
			if strings.Contains(stderr, "unknown subcommand") {
				t.Errorf("dispatcher reported unknown subcommand for %q; got stderr:\n%s",
					tc.name, stderr)
			}
		})
	}
}
