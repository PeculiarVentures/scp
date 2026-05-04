// Command scp-smoke is a hardware smoke-test harness for retail
// YubiKeys (and, more cautiously, other GlobalPlatform cards). It
// validates the two core protocols of github.com/PeculiarVentures/scp:
//
//   - SCP03 symmetric secure channel against the Issuer Security
//     Domain using factory SCP03 credentials.
//   - SCP11 asymmetric secure channel against the ISD and the PIV
//     applet.
//
// # Safety
//
// The harness is read-only by default. It does NOT rotate keys, does
// NOT attempt Security Domain writes over SCP11b, does NOT trigger
// authentication lockouts as a recovery mechanism, and does NOT
// perform broad non-YubiKey card recovery. The destructive
// "restore-yubikey-factory" subcommand documented in the design
// document is deliberately out of scope for this initial CLI; it
// will land in a follow-up under heavy guards.
//
// # Subcommands
//
//	scp-smoke readers
//	scp-smoke probe
//	scp-smoke scp03-sd-read
//	scp-smoke scp11b-sd-read
//	scp-smoke scp11b-piv-verify
//	scp-smoke test
//
// Use `scp-smoke <subcommand> -h` for per-command flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time via -ldflags. Unset in `go run` builds.
var version = "dev"

// commands maps subcommand names to handlers. Each handler parses its
// own flags from args and writes results to env.out.
var commands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"readers":           cmdReaders,
	"probe":             cmdProbe,
	"scp03-sd-read":     cmdSCP03SDRead,
	"scp11b-sd-read":    cmdSCP11bSDRead,
	"scp11b-piv-verify": cmdSCP11bPIVVerify,
	"test":              cmdTest,
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return
	case "-v", "--version", "version":
		fmt.Println("scp-smoke", version)
		return
	}

	sub := os.Args[1]
	handler, ok := commands[sub]
	if !ok {
		fmt.Fprintf(os.Stderr, "scp-smoke: unknown subcommand %q\n\n", sub)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	env := &runEnv{
		out:     os.Stdout,
		errOut:  os.Stderr,
		connect: pcscConnect,
	}
	if err := handler(ctx, env, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "scp-smoke:", err)
		os.Exit(1)
	}
}

// runEnv is the runtime environment shared across subcommands. It carries
// the writers used for output and the function used to obtain a
// transport; both can be replaced by tests.
type runEnv struct {
	out     io.Writer
	errOut  io.Writer
	connect connectFunc
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `scp-smoke - hardware smoke-test harness for the SCP library

Usage:
  scp-smoke <subcommand> [flags]

Subcommands:
  readers              List PC/SC readers visible to the OS.
  probe                Open an unauthenticated SD session, read CRD,
                       parse, and print the card's claimed capabilities.
  scp03-sd-read        Open an SCP03 SD session and verify a read works.
                       Defaults to YubiKey factory credentials.
  scp11b-sd-read       Open an SCP11b SD session and verify a read works.
  scp11b-piv-verify    Open an SCP11b session against the PIV applet
                       and verify the PIN.
  test                 Run probe + the three smoke tests; emit a
                       PASS/FAIL/SKIP summary.

  version              Print the binary version.
  help                 Print this message.

Common flags (all subcommands that touch hardware):
  --reader NAME              PC/SC reader name (substring match).
  --json                     Emit machine-readable JSON output.
  --lab-skip-scp11-trust     Skip card certificate validation for
                             SCP11; lab use only. See the smoke harness
                             design doc for when this is appropriate.
  --assume-yubikey           Allow YubiKey-specific defaults
                             (e.g. factory SCP03 KVN 0xFF) when the
                             probe cannot positively identify the card.

This tool will never intentionally cause authentication lockouts,
will never rotate SCP03 keys silently, and will refuse Security
Domain write operations over SCP11b. See "scp-smoke <cmd> -h" for
per-command details and safety notes.
`)
}

// usageError is returned by subcommands when flag parsing fails.
// Wrapping in a distinct type lets the dispatcher distinguish "user
// passed bad flags" from "the card said no."
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }

// newSubcommandFlagSet creates a FlagSet that prints to env.errOut on
// usage errors and uses ContinueOnError so errors propagate up rather
// than calling os.Exit inside the flag library.
func newSubcommandFlagSet(name string, env *runEnv) *flag.FlagSet {
	fs := flag.NewFlagSet("scp-smoke "+name, flag.ContinueOnError)
	fs.SetOutput(env.errOut)
	return fs
}
