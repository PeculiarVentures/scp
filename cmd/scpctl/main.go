// Command scpctl is the unified administrative CLI for the
// PeculiarVentures/scp library. It groups five layers of
// functionality:
//
//   - test    hardware regression checks (read-only smoke against
//             real cards: scp03/scp11a/scp11b reads + PIN-verify)
//   - piv     user-facing PIV operations (info, PIN, PUK, mgmt,
//             key, cert, object, reset, provision) over the
//             piv/session library
//   - sd      Security Domain operations (info, reset, lock,
//             unlock, terminate, OCE/SCP11a bootstraps)
//   - oce     off-card OCE certificate diagnostics (host-only;
//             does not touch a card)
//   - gp      generic GlobalPlatform card-content management
//             (probe, registry walk over arbitrary GP cards,
//             host-side CAP file inspection)
//
// plus a small set of top-level utilities (readers, probe, version,
// help) that do not belong to any group.
//
// # Safety
//
// Most destructive operations require --confirm-write. Two
// exceptions where overloading a single confirm flag would be a
// foot-gun get their own opt-in:
//
//   - sd reset uses --confirm-reset-sd. SD reset and PIV reset
//     have different blast radii; sharing a flag would mean a
//     single careless invocation could clear keys the operator
//     didn't intend to touch.
//   - sd terminate uses --confirm-terminate-card. Terminate is
//     IRREVERSIBLE — a TERMINATED card cannot be recovered by any
//     operation. Sharing the gate with reversible operations
//     (lock, unlock, bootstraps) would mean a typo could brick
//     a card.
//
// SCP11 trust validation is on by default; --lab-skip-scp11-trust
// opts out and is visible in JSON output. Security Domain writes
// are never attempted over SCP11b. Authentication lockouts are
// never used as a recovery mechanism except by the explicit
// `piv reset` command and only behind --confirm-write and
// --confirm-reset-piv.
//
// # Subcommands
//
//	scpctl readers
//	scpctl probe
//	scpctl test <subcommand>
//	scpctl piv  <subcommand>
//	scpctl sd   <subcommand>
//	scpctl oce  <subcommand>
//	scpctl gp   <subcommand>
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
	"syscall"
)

// version is set at build time via -ldflags. Unset in `go run` builds.
var version = "dev"

// pivCommands maps the piv-group subcommand names to handlers.
// Most operate on the PIV applet via the piv/session library; the
// 'provision' subcommand is the SCP11b-secured channel-then-key-gen
// flow.
var pivCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"info":      cmdPIVInfo,
	"pin":       cmdPIVPin,
	"puk":       cmdPIVPuk,
	"mgmt":      cmdPIVMgmt,
	"key":       cmdPIVKey,
	"cert":      cmdPIVCert,
	"object":    cmdPIVObject,
	"reset":     cmdPIVGroupReset,
	"provision": cmdPIVProvision,
}

// sdCommands maps the sd-group subcommand names. info and reset are
// the read paths; the bootstrap-* entries are day-1 provisioning
// flows that install the OCE public key and the SCP11a SD ECDH key
// onto fresh cards. All bootstrap entries are state-changing and
// gated by --confirm-write.
var sdCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"info":                cmdSDInfo,
	"reset":               cmdSDReset,
	"lock":                cmdSDLock,
	"unlock":              cmdSDUnlock,
	"terminate":           cmdSDTerminate,
	"bootstrap-oce":       cmdBootstrapOCE,
	"bootstrap-scp11a":    cmdBootstrapSCP11a,
	"bootstrap-scp11a-sd": cmdBootstrapSCP11aSD,
}

// testCommands maps the test-group subcommand names. These are
// regression checks against real hardware: open a session, perform
// a known read, validate the wire bytes the library produces are
// accepted by the card. None of them mutate card state. Renamed
// from the original 'smoke' group; the read smokes stayed but the
// destructive bootstraps and PIV provisioning moved to sd / piv.
var testCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"scp03-sd-read":     cmdSCP03SDRead,
	"scp11b-sd-read":    cmdSCP11bSDRead,
	"scp11a-sd-read":    cmdSCP11aSDRead,
	"scp11b-piv-verify": cmdSCP11bPIVVerify,
	"all":               cmdTest,
}

// gpCommands maps the gp-group subcommand names. The gp group is
// the operator surface for generic GlobalPlatform card-content
// management, distinct from the YubiKey-flavored sd group: probe
// and registry are read-path operations on arbitrary GP cards;
// cap is a host-side sub-grouping for CAP file utilities. Future
// destructive applet-management commands (install, delete) land
// here too once the Appendix B prerequisites are in place.
var gpCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"probe":    cmdGPProbe,
	"registry": cmdGPRegistry,
	"cap":      cmdGPCap,
}

// topLevelCommands maps top-level utility subcommands. These are
// reader-discovery and unauthenticated-probe operations that don't
// belong to any of the protocol or applet groups.
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
	case "test":
		runGroup(ctx, env, "test", testCommands, os.Args[2:], testUsage)
		return
	case "piv":
		runGroup(ctx, env, "piv", pivCommands, os.Args[2:], pivUsage)
		return
	case "sd":
		runGroup(ctx, env, "sd", sdCommands, os.Args[2:], sdUsage)
		return
	case "oce":
		runGroup(ctx, env, "oce", oceCommands, os.Args[2:], oceUsage)
		return
	case "gp":
		runGroup(ctx, env, "gp", gpCommands, os.Args[2:], gpUsage)
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
  test        Hardware regression checks. Read-only against real
              cards; validates the wire bytes the library produces
              are accepted. Renamed from the legacy 'smoke' group.

  piv         User-facing PIV operations over piv/session.
              Wired: info, pin, puk, mgmt, key, cert, object,
              reset, provision.

  sd          Security Domain operations.
              Wired: info, reset, lock, unlock, terminate,
              bootstrap-oce, bootstrap-scp11a, bootstrap-scp11a-sd.

  oce         Off-card OCE certificate diagnostics. Host-only;
              does not touch a card. Wired: verify, gen.

  gp          Generic GlobalPlatform card-content management.
              Wired: probe, registry, cap inspect.

Top-level utilities:
  readers     List PC/SC readers visible to the OS.
  probe       Open an unauthenticated SD session and report card
              capabilities.
  version     Print the binary version.
  help        Print this message.

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

func testUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl test - hardware regression checks

Usage:
  scpctl test <subcommand> [flags]

Subcommands:
  scp03-sd-read        Open an SCP03 SD session and verify a read works.
                       Defaults to YubiKey factory credentials.
  scp11b-sd-read       Open an SCP11b SD session and verify a read works.
  scp11a-sd-read       Open an SCP11a (mutual-auth) SD session and verify
                       a read works. Requires --oce-key and --oce-cert
                       and a card with OCE provisioned.
  scp11b-piv-verify    Open an SCP11b session against the PIV applet
                       and verify the PIN.
  all                  Run probe + the four read smokes; emit a
                       PASS/FAIL/SKIP summary.

These subcommands are read-only against the card. Destructive
provisioning flows that used to live under 'smoke' (bootstrap-oce,
bootstrap-scp11a, bootstrap-scp11a-sd, piv-provision) are now in
their proper groups under 'sd' and 'piv'.

Use "scpctl test <subcommand> -h" for per-command flags.
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
// The name argument is the full subcommand path (without the "scpctl"
// prefix) that should appear in usage messages: "test scp03-sd-read",
// "piv key generate", "sd bootstrap-oce". Each handler is responsible
// for passing the right form so its usage line is accurate.
func newSubcommandFlagSet(name string, env *runEnv) *flag.FlagSet {
	fs := flag.NewFlagSet("scpctl "+name, flag.ContinueOnError)
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
                        --confirm-write and --confirm-reset-piv. The
                        card-side precondition (PIN and PUK both
                        blocked) is the operator's responsibility.

  provision             Generate a PIV slot keypair and optionally
                        install a certificate / fetch attestation,
                        all over an SCP11b session targeting the PIV
                        applet. Destructive; gated by --confirm-write.

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
  to raw, because a missed channel-mode flag should not silently
  downgrade an SCP11b-secured operation to raw transport.

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
  info                 Open an unauthenticated SD session and report
                       Card Recognition Data. Equivalent to 'scpctl
                       probe'. Read-only.
  reset                Factory-reset Security Domain key material.
                       Restores the factory SCP03 key set, regenerates
                       the SCP11b key, and removes any custom OCE /
                       SCP11a / SCP11c keys. Dry-run by default; pass
                       --confirm-reset-sd to mutate. Does NOT touch
                       PIV applet state — for that, see 'scpctl piv
                       reset'.
  lock                 Transition the ISD to CARD_LOCKED via GP SET
                       STATUS. Recoverable via 'sd unlock' from a
                       key-holder. Dry-run by default; pass
                       --confirm-write to mutate. Requires SCP03.
  unlock               Transition the ISD from CARD_LOCKED back to
                       SECURED. Inverse of 'sd lock'. Dry-run by
                       default; pass --confirm-write to mutate.
                       Requires SCP03.
  terminate            IRREVERSIBLE: transition the ISD to
                       TERMINATED. The card cannot be recovered by
                       any operation after this. Dry-run by default;
                       gated behind a distinct --confirm-terminate-
                       card flag (NOT --confirm-write) so a single
                       careless invocation can't brick a card.
                       Requires SCP03.
  bootstrap-oce        Install an OCE public key (and optionally cert
                       chain + CA SKI) onto a card via SCP03. Day-1
                       provisioning step that enables SCP11a sessions.
                       Destructive; gated by --confirm-write.
  bootstrap-scp11a     Combined SCP11a-on-fresh-card flow. Opens ONE
                       SCP03 factory session and does both the OCE
                       public key install and the SCP11a SD key
                       install. Required on cards (e.g. retail
                       YubiKey 5.7.4) where the first PUT KEY under
                       factory SCP03 invalidates the factory keys —
                       running bootstrap-oce and bootstrap-scp11a-sd
                       as separate commands fails the second one.
                       Destructive; gated by --confirm-write.
  bootstrap-scp11a-sd  Install the card-side SCP11a SD ECDH key
                       (SK.SD.ECKA, KID=0x11/KVN=0x01 by default)
                       via SCP03. Two modes: 'oncard' uses Yubico's
                       GENERATE KEY extension so the private key
                       never leaves the SE; 'import' uses GP PUT KEY
                       to install a host-generated or supplied
                       keypair. Destructive; gated by --confirm-write.

Use "scpctl sd <subcommand> -h" for per-command flags.
`)
}
