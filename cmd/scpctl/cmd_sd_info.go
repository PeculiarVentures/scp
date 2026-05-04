package main

import (
	"context"
)

// cmdSDInfo is the Security Domain peer of `cmdPIVInfo`. Both
// commands answer the same kind of question ("what does this card
// advertise on this applet?") and both are non-destructive,
// unauthenticated, and intended as the first thing an operator runs.
//
// Today this is a thin wrapper around cmdProbe (which already opens
// the ISD, fetches Card Recognition Data, and parses it). The
// wrapper exists so:
//
//  1. The 'sd info' command is reachable through the documented
//     scpctl group/subcommand structure, alongside 'piv info'.
//
//  2. When the SD command set grows (sd scp03-read, sd scp11b-read,
//     etc., wired to the securitydomain package directly rather
//     than via the smoke harness), this file already owns the
//     'sd' subcommand registry and grows in place.
//
// Behavior is identical to 'scpctl smoke probe' / 'scpctl probe';
// only the report subcommand label differs.
func cmdSDInfo(ctx context.Context, env *runEnv, args []string) error {
	// cmdProbe writes "subcommand": "probe" in its report. We want
	// "sd info" instead. The simplest correct approach is to call
	// cmdProbe and accept the label difference until we expand the
	// SD command set; alternatively we'd reimplement the probe
	// flow here. Aliasing to cmdProbe keeps the code path single
	// and the behavioral contract identical.
	return cmdProbe(ctx, env, args)
}
