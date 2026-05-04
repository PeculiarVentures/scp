// Command scpctl is the unified administrative CLI for the
// PeculiarVentures/scp library. It groups three layers of
// functionality:
//
//   - smoke   hardware validation and regression checks (the
//             original scp-smoke surface, preserved unchanged
//             behaviorally)
//   - piv     user-facing PIV operations (PIN, key, cert, attest,
//             reset) over the piv/session library
//   - sd      Security Domain read and bootstrap operations
//
// plus a small set of top-level utilities (readers, probe, version,
// help) that do not belong to any group.
//
// # Safety
//
// All destructive operations require --confirm-write. SCP11 trust
// validation is on by default; --lab-skip-scp11-trust opts out and
// is visible in JSON output. Security Domain writes are never
// attempted over SCP11b. Authentication lockouts are never used as
// a recovery mechanism except by the explicit `smoke piv-reset`
// command and only behind --confirm-write.
//
// # Subcommands
//
//	scpctl readers
//	scpctl probe
//	scpctl smoke <subcommand>
//	scpctl piv <subcommand>
//	scpctl sd  <subcommand>
//	scpctl version
//	scpctl help
//
// Use `scpctl <group> <subcommand> -h` for per-command flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// version is set at build time via -ldflags. Unset in `go run` builds.
var version = "dev"

// pivCommands maps the piv-group subcommand names to handlers.
// These commands operate on the PIV applet via the piv/session
// library, not via the SCP-wrapped paths in 'scpctl smoke
// piv-provision' which establish a full SCP11b channel first.
//
// The split is intentional: 'piv' is for raw-transport operator
// flows (probe a card, read its applet info), 'smoke' covers the
// existing SCP-secured provisioning paths until they migrate over.
var pivCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"info":   cmdPIVInfo,
	"pin":    cmdPIVPin,
	"puk":    cmdPIVPuk,
	"mgmt":   cmdPIVMgmt,
	"key":    cmdPIVKey,
	"cert":   cmdPIVCert,
	"object": cmdPIVObject,
	"reset":  cmdPIVGroupReset,
}

// sdCommands maps the sd-group subcommand names. Today only 'info'
// is wired; the remaining flows (scp03-read, scp11b-read,
// scp11a-read, bootstrap-oce) still live under 'scpctl smoke' and
// will move when their dependencies on the smoke-specific report
// shape are decoupled.
var sdCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"info": cmdSDInfo,
}

// smokeCommands maps the smoke-group subcommand names to handlers.
// These are the original scp-smoke commands; the names are preserved
// verbatim (including hyphens like scp03-sd-read) so existing
// scripts that called `scp-smoke scp03-sd-read` translate to
// `scpctl smoke scp03-sd-read` with no other changes.
var smokeCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"readers":           cmdReaders,
	"probe":             cmdProbe,
	"scp03-sd-read":     cmdSCP03SDRead,
	"scp11b-sd-read":    cmdSCP11bSDRead,
	"scp11a-sd-read":    cmdSCP11aSDRead,
	"scp11b-piv-verify": cmdSCP11bPIVVerify,
	"bootstrap-oce":         cmdBootstrapOCE,
	"bootstrap-scp11a-sd":   cmdBootstrapSCP11aSD,
	"piv-provision":         cmdPIVProvision,
	"piv-reset":         cmdPIVReset,
	"test":              cmdTest,
}

// topLevelCommands maps top-level utility subcommands. readers and
// probe are also reachable under `scpctl smoke` because they were
// originally part of the smoke harness; exposing them at the top
// level mirrors how operators reach for them.
var topLevelCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"readers": cmdReaders,
	"probe":   cmdProbe,
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
		fmt.Println("scpctl", version)
		return
	}

	env := &runEnv{
		out:     os.Stdout,
		errOut:  os.Stderr,
		connect: pcscConnect,
		stdin:   newSingleShotStdin(os.Stdin),
	}

	group := os.Args[1]
	switch group {
	case "smoke":
		runGroup(ctx, env, "smoke", smokeCommands, os.Args[2:], smokeUsage)
		return
	case "piv":
		runGroup(ctx, env, "piv", pivCommands, os.Args[2:], pivUsage)
		return
	case "sd":
		runGroup(ctx, env, "sd", sdCommands, os.Args[2:], sdUsage)
		return
	}

	// Top-level utility subcommands.
	if handler, ok := topLevelCommands[group]; ok {
		if err := handler(ctx, env, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "scpctl:", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "scpctl: unknown subcommand %q\n\n", group)
	printUsage(os.Stderr)
	os.Exit(2)
}

// runGroup dispatches a `scpctl <group> <sub>` invocation. Extracted
// so future groups (piv, sd) reuse identical error and usage handling.
func runGroup(
	ctx context.Context,
	env *runEnv,
	groupName string,
	registry map[string]func(context.Context, *runEnv, []string) error,
	args []string,
	usage func(io.Writer),
) {
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	}
	sub := args[0]
	handler, ok := registry[sub]
	if !ok {
		fmt.Fprintf(os.Stderr, "scpctl %s: unknown subcommand %q\n\n", groupName, sub)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err := handler(ctx, env, args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "scpctl "+groupName+":", err)
		os.Exit(1)
	}
}

// runEnv is the runtime environment shared across subcommands. It
// carries the writers used for output and the function used to
// obtain a transport; both can be replaced by tests.
type runEnv struct {
	out     io.Writer
	errOut  io.Writer
	connect connectFunc

	// stdin is the single-shot stdin source used by --*-stdin
	// secret flags. Production main wires this to os.Stdin; tests
	// that exercise --*-stdin pass a bytes.Reader instead. Tests
	// that do not exercise stdin can leave this nil; resolve() does
	// not call into it unless --*-stdin is set, so the nil case is
	// a programmer error rather than a runtime crash.
	stdin *singleShotStdin
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl - administrative CLI for github.com/PeculiarVentures/scp

Usage:
  scpctl <group> <subcommand> [flags]
  scpctl <utility> [flags]

Groups:
  smoke       Hardware smoke tests and regression checks
              (originally the 'scp-smoke' binary; preserved verbatim).

  piv         User-facing PIV operations over piv/session.
              Wired: info, pin, puk, mgmt, key, cert, object, reset.

  sd          Security Domain operations.
              Wired: info. SCP-secured read paths still under
              'scpctl smoke' until they migrate.

Top-level utilities:
  readers     List PC/SC readers visible to the OS.
  probe       Open an unauthenticated SD session and report card
              capabilities.
  version     Print the binary version.
  help        Print this message.

Smoke subcommands:
  scpctl smoke readers
  scpctl smoke probe
  scpctl smoke scp03-sd-read
  scpctl smoke scp11b-sd-read
  scpctl smoke scp11a-sd-read
  scpctl smoke scp11b-piv-verify
  scpctl smoke bootstrap-oce
  scpctl smoke piv-provision
  scpctl smoke piv-reset
  scpctl smoke test

Common flags (all subcommands that touch hardware):
  --reader NAME              PC/SC reader name (substring match).
  --json                     Emit machine-readable JSON output.
  --lab-skip-scp11-trust     Skip card certificate validation for
                             SCP11; lab use only.
  --assume-yubikey           Allow YubiKey-specific defaults when
                             the probe cannot positively identify
                             the card.

This tool will never intentionally cause authentication lockouts,
will never rotate SCP03 keys silently, and will refuse Security
Domain write operations over SCP11b. See "scpctl <group> <cmd> -h"
for per-command details and safety notes.
`)
}

func smokeUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl smoke - hardware smoke tests and regression checks

Usage:
  scpctl smoke <subcommand> [flags]

Subcommands:
  readers              List PC/SC readers visible to the OS.
  probe                Open an unauthenticated SD session, read CRD,
                       parse, and print the card's claimed capabilities.
  scp03-sd-read        Open an SCP03 SD session and verify a read works.
                       Defaults to YubiKey factory credentials.
  scp11b-sd-read       Open an SCP11b SD session and verify a read works.
  scp11a-sd-read       Open an SCP11a (mutual-auth) SD session and verify
                       a read works. Requires --oce-key and --oce-cert
                       and a card with OCE provisioned.
  scp11b-piv-verify    Open an SCP11b session against the PIV applet
                       and verify the PIN.
  bootstrap-oce        Install an OCE public key (and optionally cert
                       chain + CA SKI) onto a card via SCP03. Day-1
                       provisioning step that enables scp11a-sd-read.
                       Destructive; gated by --confirm-write.
  bootstrap-scp11a-sd  Install the card-side SCP11a SD ECDH key
                       (SK.SD.ECKA, KID=0x11/KVN=0x01 by default)
                       via SCP03. Two modes: 'oncard' uses Yubico's
                       GENERATE KEY extension so the private key
                       never leaves the SE; 'import' uses GP PUT KEY
                       to install a host-generated or supplied
                       keypair. Destructive; gated by --confirm-write.
  piv-provision        Generate a PIV slot keypair and optionally install
                       a certificate / fetch attestation, all over an
                       SCP11b session targeting the PIV applet.
                       Destructive; gated by --confirm-write.
  piv-reset            Reset the YubiKey PIV applet to factory state by
                       deliberately blocking PIN and PUK, then sending
                       INS=0xFB. Erases ALL slot keys and certs.
                       Destructive; gated by --confirm-write.
  test                 Run probe + the three smoke tests; emit a
                       PASS/FAIL/SKIP summary.

Use "scpctl smoke <subcommand> -h" for per-command flags.
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
//
// The name argument is the full subcommand path that should appear
// in usage messages. Callers in the smoke group still pass the bare
// subcommand and get the "scpctl smoke <sub>" prefix automatically;
// callers in other groups pass the full "scpctl piv key generate"
// form to keep the usage line accurate.
func newSubcommandFlagSet(name string, env *runEnv) *flag.FlagSet {
	prefix := "scpctl"
	// Heuristic: if name does not already start with a known group
	// prefix, treat it as a smoke subcommand for back-compat with
	// the original scp-smoke help shape.
	if !strings.HasPrefix(name, "piv ") && !strings.HasPrefix(name, "sd ") && !strings.HasPrefix(name, "smoke ") {
		prefix = "scpctl smoke"
	}
	fs := flag.NewFlagSet(prefix+" "+name, flag.ContinueOnError)
	fs.SetOutput(env.errOut)
	return fs
}

func pivUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl piv - user-facing PIV operations

Usage:
  scpctl piv <subcommand> [flags]
  scpctl piv <group> <verb> [flags]

Subcommands:
  info                  Probe the PIV applet and report the detected
                        profile and capability set. Read-only.

  pin verify            Verify the application PIN.
  pin change            Change the application PIN.
  pin unblock           Use the PUK to unblock and reset the PIN.
  puk change            Change the PUK.

  mgmt auth             Authenticate to the PIV management key.
  mgmt change-key       Rotate the PIV management key. Destructive.

  key generate          Generate an asymmetric key in a slot. Destructive.
  key attest            Fetch the YubiKey attestation certificate
                        for a slot (YubiKey-only).

  cert get              Read the certificate from a slot.
  cert put              Install a certificate into a slot. Destructive.
  cert delete           Clear the certificate from a slot. Destructive.

  object get            Read a PIV data object by ID.
  object put            Write a PIV data object by ID. Destructive.

  reset                 Reset the PIV applet to factory state. Erases
                        all slots, certificates, and credentials.
                        YubiKey-only. Destructive. Requires both
                        --confirm-write and --confirm-reset-piv.
                        The card-side precondition (PIN and PUK
                        both blocked) is the operator's
                        responsibility; for the block-then-reset
                        harness flow, see 'scpctl smoke piv-reset'.

Destructive subcommands all require --confirm-write. 'reset' takes
the additional --confirm-reset-piv flag because a full applet wipe
is qualitatively different from a single-slot operation; the second
flag prevents an operator from accidentally turning a slot rotation
into a full reset by pasting a stale command line. Operations that
the active profile does not claim (e.g. ATTEST under StandardPIV,
Ed25519 under YubiKey 5.6) are refused host-side before any APDU
goes on the wire, with piv.ErrUnsupportedByProfile.

Channel mode (destructive and credential-bearing subcommands):
  Exactly one of --scp11b or --raw-local-ok must be set. Absence
  of both is a usage error: scpctl piv refuses to silently default
  to raw, because operators migrating from 'scp-smoke piv-provision'
  (which used SCP11b unconditionally) should not be downgraded by
  forgetting to type a flag.

  --scp11b                  Run the operation over an SCP11b-on-PIV
                            secure channel. Required for any host
                            path not in the operator's trust
                            boundary (APDU relay, remote
                            provisioning, multi-tenant CI).
  --raw-local-ok            Explicitly assert that raw APDUs are
                            acceptable: the host running scpctl is
                            in the operator's trust boundary, which
                            is the typical local-USB administration
                            case. Mutually exclusive with --scp11b.
  --trust-roots <pem>       SCP11 card-cert trust anchors.
                            Required with --scp11b for production.
  --lab-skip-scp11-trust    Skip card-cert validation entirely.
                            Lab use only; opportunistic encryption,
                            not authenticated key agreement.

Credential input (PIN, PUK, and management-key flags):
  --<name>                  Pass the credential as an argv value.
                            Visible in shell history (~/.bash_history)
                            and process listings (ps, /proc/<pid>/
                            cmdline). Acceptable for lab work.
  --<name>-stdin            Read the credential from stdin (one
                            line; trailing newline stripped). Only
                            one --*-stdin flag may be active per
                            invocation because stdin is single-
                            consumer. Use for piped credentials
                            (e.g. printf with no trailing newline
                            piped to scpctl).
  --<name>-file <path>      Read the credential from a file. Whole
                            file is read; one trailing newline (if
                            present) is stripped. Keep the file at
                            mode 0600.

  Affected flags: --pin, --old-pin, --new-pin, --puk, --old-puk,
  --new-puk, --mgmt-key, --old-mgmt-key, --new-mgmt-key. Each
  registers all three forms; the three are mutually exclusive per
  logical credential.

See docs/piv.md for the threat-model split between raw and SCP11b.

Use "scpctl piv <subcommand> -h" for per-command flags.
`)
}

func sdUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl sd - Security Domain operations

Usage:
  scpctl sd <subcommand> [flags]

Subcommands:
  info     Open an unauthenticated SD session and report Card
           Recognition Data. Equivalent to 'scpctl probe' /
           'scpctl smoke probe'. Read-only.

Forthcoming subcommands (still reachable under 'scpctl smoke' for now):
  scp03-read           SCP03 SD session read.
  scp11b-read          SCP11b SD session read.
  scp11a-read          SCP11a (mutual auth) SD session read.
  bootstrap-oce        Install OCE public key onto a card via SCP03.
  bootstrap-scp11a-sd  Install card-side SCP11a SD ECDH key via SCP03.

Use "scpctl sd <subcommand> -h" for per-command flags.
`)
}
