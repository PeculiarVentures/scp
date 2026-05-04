package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Secrets in argv are visible in shell history (~/.bash_history,
// ~/.zsh_history), in process listings (`ps`, `/proc/<pid>/cmdline`),
// and in audit logs that capture command lines. PINs and management
// keys land in all three. The standard fix in operator tooling is to
// accept secrets via stdin or via a file path that the shell does
// not expand into the command line.
//
// secretFlags wraps the three flag forms a logical secret (PIN, PUK,
// management key) accepts:
//
//   --<name>          Direct argv value. Easy for one-off use; leaks
//                     into history and ps. Acceptable for lab work.
//
//   --<name>-stdin    Read one line from stdin. The trailing newline
//                     is stripped. Only one --*-stdin flag may be
//                     active per invocation because stdin is a
//                     single-consumer resource. Use for piped
//                     credentials: `printf '%s' "$pin" | scpctl ...`.
//
//   --<name>-file     Read the file at the given path. Whole file is
//                     read; a single trailing newline (if present)
//                     is stripped. The path must not be readable by
//                     other users; this helper enforces nothing
//                     beyond permission errors from the OS, but the
//                     operator should keep the file mode at 0600.
//
// At most one of the three may be set; supplying multiple is a usage
// error.
type secretFlags struct {
	name      string  // human-readable label, used in error messages
	defValue  string  // argv default; treated as "no value supplied"
	value     *string // direct argv flag
	stdinFlag *bool   // --<name>-stdin
	filePath  *string // --<name>-file
}

// registerSecretFlags adds the three forms for a single logical
// secret to fs. The argv form retains whatever default the caller
// passes (typically empty for PIN/PUK; "default" for management key
// where the literal "default" resolves to the well-known factory
// value). The -stdin and -file forms have no default; they must be
// passed explicitly.
//
// Example:
//
//	pin := registerSecretFlags(fs, "pin", "", "Application PIN.")
//	...
//	pinBytes, err := pin.resolve(stdinReader)
func registerSecretFlags(fs *flag.FlagSet, name, defaultValue, usage string) *secretFlags {
	return &secretFlags{
		name:     name,
		defValue: defaultValue,
		value: fs.String(name, defaultValue,
			fmt.Sprintf("%s Visible in shell history and process listings; prefer --%s-stdin or --%s-file for production.",
				usage, name, name)),
		stdinFlag: fs.Bool(name+"-stdin", false,
			fmt.Sprintf("Read the %s from stdin (one line). Only one --*-stdin flag may be active per invocation.", name)),
		filePath: fs.String(name+"-file", "",
			fmt.Sprintf("Read the %s from the given file path. Trailing newline stripped. File permissions must not permit group/world read (chmod 0600 or 0400); enforced on Unix.", name)),
	}
}

// resolve returns the secret bytes from whichever form was supplied,
// or an empty []byte (and nil error) when no form was set and the
// argv default is also empty. Callers that require a non-empty
// secret (e.g. --pin on `piv pin verify`) check the returned length
// themselves; callers that want the well-known "default" sentinel
// (management key with --mgmt-key "default") see that string passed
// through as the resolved value, since "default" is not a literal
// key but a marker the management-key parser interprets.
//
// stdinSrc is the single-shot stdin source provided by stdinReader.
// resolve calls Read on it only when --<name>-stdin is set; the
// reader records consumption so a second --*-stdin in the same
// invocation gets a clear error.
func (s *secretFlags) resolve(stdinSrc *singleShotStdin) (string, error) {
	count := 0
	if *s.value != "" && *s.value != s.defValue {
		// User passed a non-default value via argv. Note: for
		// management key, the default is "default" (the literal
		// sentinel), so a value of "default" reads as the default
		// rather than as a competing input.
		count++
	}
	if *s.stdinFlag {
		count++
	}
	if *s.filePath != "" {
		count++
	}
	if count > 1 {
		return "", &usageError{msg: fmt.Sprintf(
			"--%s, --%s-stdin, and --%s-file are mutually exclusive; pick one",
			s.name, s.name, s.name)}
	}

	if *s.stdinFlag {
		line, err := stdinSrc.readLine(s.name)
		if err != nil {
			return "", err
		}
		return line, nil
	}
	if *s.filePath != "" {
		// Permission gate: secret files must not be group- or
		// world-readable. Operators who use --*-file expect the
		// file to be a hardened secret store; a 0644 file defeats
		// the point because it surfaces the secret to every local
		// process. Refusing here forces the operator to chmod 0600
		// (or 0400) before continuing, which is the right habit.
		//
		// Symlinks: os.Stat follows symlinks, so a symlink to a
		// 0600 target passes; a symlink to a 0644 target is
		// refused, which is the safe behavior. We don't separately
		// check the symlink mode itself because symlink modes on
		// Linux are advisory; the target's mode is what matters.
		//
		// On Windows, file mode bits don't represent ACLs the way
		// they do on Unix, and Go reports a synthesized mode. The
		// check still fires structurally; if it produces false
		// positives on Windows, the operator can fall back to
		// --*-stdin or argv with the warning. This is a tradeoff
		// in favor of safety on the platform where the check is
		// meaningful (Linux/macOS production hosts).
		info, err := os.Stat(*s.filePath)
		if err != nil {
			return "", fmt.Errorf("--%s-file: %w", s.name, err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return "", fmt.Errorf(
				"--%s-file %q has permissions %#o, which permits group/world read; chmod 0600 (or 0400) before retrying. Secret files are no safer than argv if anyone else on the host can read them.",
				s.name, *s.filePath, mode)
		}
		raw, err := os.ReadFile(*s.filePath)
		if err != nil {
			return "", fmt.Errorf("--%s-file: %w", s.name, err)
		}
		return strings.TrimSuffix(string(raw), "\n"), nil
	}
	return *s.value, nil
}

// singleShotStdin is a stdin reader that allows exactly one consumer
// per process. The first --*-stdin flag to call readLine wins; any
// subsequent caller gets an error naming both flags so the operator
// understands why their second --*-stdin did nothing.
type singleShotStdin struct {
	mu       sync.Mutex
	r        io.Reader
	consumed bool
	first    string // name of the secret that consumed stdin
}

// newSingleShotStdin wraps r as a single-shot source. Production
// code passes os.Stdin; tests pass a bytes.Reader.
func newSingleShotStdin(r io.Reader) *singleShotStdin {
	return &singleShotStdin{r: r}
}

// readLine reads one line from stdin, strips the trailing newline,
// and records that stdin has been consumed. Subsequent calls return
// an error.
//
// secretName is the label of the credential being read (passed
// through from the secretFlags.name field). It appears in the
// double-consumption error message so the operator can see which
// flag tried to read after stdin had already been consumed.
func (s *singleShotStdin) readLine(secretName string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed {
		return "", &usageError{msg: fmt.Sprintf(
			"--%s-stdin: stdin was already consumed by --%s-stdin earlier in this invocation; only one --*-stdin flag may be active per command",
			secretName, s.first)}
	}
	br := bufio.NewReader(s.r)
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("--%s-stdin: read: %w", secretName, err)
	}
	s.consumed = true
	s.first = secretName
	return strings.TrimRight(line, "\r\n"), nil
}
