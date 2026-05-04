package main

import (
	"context"
	"fmt"
	"strings"
)

// cmdTest runs probe + the SCP smoke commands in sequence and emits
// a final PASS/FAIL/SKIP summary. Each subcommand writes its own
// detailed output to env.out as it runs; the summary at the end
// rolls those outcomes into a single line per check.
//
// A failed subcommand does NOT abort the run — the tester wants the
// full picture. Process exit code is 1 iff any subcommand failed
// (mirroring `make` semantics: keep going, fail at the end).
//
// JSON mode is intentionally not supported here. The interesting
// data lives in the underlying subcommands' reports; piping their
// individual JSON output through `jq` gets you a clean machine
// representation. Trying to merge five reports into one
// command-specific JSON document is more work than it's worth and
// any consumer doing that lookup is better served by the
// individual commands.
func cmdTest(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("test", env)
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	trustRoots := fs.String("trust-roots", "",
		"Path to PEM bundle of trusted SCP11 card-cert root CAs. Forwarded to "+
			"scp11b-sd-read, scp11a-sd-read, scp11b-piv-verify. Mutually exclusive "+
			"with --lab-skip-scp11-trust.")
	labSkipTrust := fs.Bool("lab-skip-scp11-trust", false,
		"Skip SCP11 card certificate validation. Lab use only. Mutually exclusive with --trust-roots.")
	pin := fs.String("pin", "",
		"PIV PIN. If empty, the SCP11b PIV smoke check is skipped.")
	oceKeyPath := fs.String("oce-key", "",
		"Path to OCE private key PEM. If empty, scp11a-sd-read is skipped.")
	oceCertPath := fs.String("oce-cert", "",
		"Path to OCE cert chain PEM, leaf last. If empty, scp11a-sd-read is skipped.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	if *labSkipTrust && *trustRoots != "" {
		return &usageError{msg: "--trust-roots and --lab-skip-scp11-trust are mutually exclusive"}
	}
	trustConfigured := *labSkipTrust || *trustRoots != ""

	type outcome struct {
		name   string
		result Result
		detail string
	}
	var outcomes []outcome

	commonArgs := []string{}
	if *reader != "" {
		commonArgs = append(commonArgs, "--reader", *reader)
	}

	run := func(label string, fn func(context.Context, *runEnv, []string) error, args []string) {
		fmt.Fprintln(env.out)
		fmt.Fprintln(env.out, "==", label, "==")
		if err := fn(ctx, env, args); err != nil {
			outcomes = append(outcomes, outcome{label, ResultFail, short(err)})
		} else {
			outcomes = append(outcomes, outcome{label, ResultPass, ""})
		}
	}

	skip := func(label, reason string) {
		fmt.Fprintln(env.out)
		fmt.Fprintln(env.out, "==", label, "(skipped) ==", reason)
		outcomes = append(outcomes, outcome{label, ResultSkip, reason})
	}

	run("probe", cmdProbe, commonArgs)
	run("scp03-sd-read", cmdSCP03SDRead, commonArgs)

	scp11bArgs := append([]string(nil), commonArgs...)
	if *labSkipTrust {
		scp11bArgs = append(scp11bArgs, "--lab-skip-scp11-trust")
	}
	if *trustRoots != "" {
		scp11bArgs = append(scp11bArgs, "--trust-roots", *trustRoots)
	}
	if trustConfigured {
		run("scp11b-sd-read", cmdSCP11bSDRead, scp11bArgs)
	} else {
		skip("scp11b-sd-read", "no trust configured; pass --trust-roots <pem> or --lab-skip-scp11-trust")
	}

	switch {
	case *oceKeyPath == "" || *oceCertPath == "":
		skip("scp11a-sd-read", "no --oce-key/--oce-cert supplied")
	case !trustConfigured:
		skip("scp11a-sd-read", "no trust configured; pass --trust-roots <pem> or --lab-skip-scp11-trust")
	default:
		scp11aArgs := append([]string(nil), scp11bArgs...)
		scp11aArgs = append(scp11aArgs, "--oce-key", *oceKeyPath, "--oce-cert", *oceCertPath)
		run("scp11a-sd-read", cmdSCP11aSDRead, scp11aArgs)
	}

	switch {
	case *pin == "":
		skip("scp11b-piv-verify", "no --pin supplied")
	case !trustConfigured:
		skip("scp11b-piv-verify", "no trust configured; pass --trust-roots <pem> or --lab-skip-scp11-trust")
	default:
		pivArgs := append([]string(nil), scp11bArgs...)
		pivArgs = append(pivArgs, "--pin", *pin)
		run("scp11b-piv-verify", cmdSCP11bPIVVerify, pivArgs)
	}

	skip("restore-yubikey-factory", "destructive; not implemented in this CLI version")

	// Summary.
	fmt.Fprintln(env.out)
	fmt.Fprintln(env.out, "== summary ==")
	anyFail := false
	for _, o := range outcomes {
		if o.detail == "" {
			fmt.Fprintf(env.out, "  %-32s %s\n", o.name, o.result)
		} else {
			fmt.Fprintf(env.out, "  %-32s %s — %s\n", o.name, o.result, o.detail)
		}
		if o.result == ResultFail {
			anyFail = true
		}
	}
	if anyFail {
		return fmt.Errorf("test reported failures")
	}
	return nil
}

// short returns the first line of an error message, trimmed.
func short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
