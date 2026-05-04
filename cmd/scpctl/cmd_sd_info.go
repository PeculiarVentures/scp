package main

import (
	"context"
)

// cmdSDInfo opens an unauthenticated Security Domain session and
// reports the card's identity. Two read-only GET DATA calls:
//
//   - tag 0x66 (Card Recognition Data): GP version, SCP advertisement,
//     card identification / config / chip OIDs.
//   - tag 0x00E0 (Key Information Template): list of installed key
//     references with KID, KVN, and component count.
//
// CRD is mandatory; KIT is best-effort because not every card
// implements GET DATA tag 0x00E0. KIT absence is reported as SKIP
// rather than FAIL.
//
// The peer command 'piv info' answers the same shape of question for
// the PIV applet. Both commands are non-destructive, unauthenticated,
// and the right thing to run before deciding what to authenticate as.
//
// 'sd info' shares its core implementation with the legacy 'scpctl
// probe' (and 'scpctl smoke probe') subcommand, with the additional
// KIT fetch turned on. The legacy command stays for backward
// compatibility with existing scripts that called 'scp-smoke probe'.
func cmdSDInfo(ctx context.Context, env *runEnv, args []string) error {
	return runProbe(ctx, env, args, probeOptions{
		flagSetName:  "sd info",
		reportLabel:  "sd info",
		fetchKeyInfo: true,
	})
}
