package main

import "context"

// cmdGPProbe is the gp-group form of the unauthenticated probe. Same
// underlying flow as cmdProbe (open ISD, fetch CRD via GET DATA tag
// 0x66, parse capabilities) — only the report label differs so an
// operator running 'gp probe' sees output tagged for the gp group
// rather than the historical top-level 'probe'.
//
// Functionally indistinguishable from cmdProbe today. The reason for
// a separate entry point is operator mental model and CLI surface
// stability: the gp group expects every gp-related discovery to live
// at 'scpctl gp <subcommand>', so 'gp probe' is the natural home
// even when the implementation is shared. A future release may make
// the top-level 'probe' an alias for 'gp probe'; the inverse would
// not be possible without breaking existing scripts.
//
// Scope:
//
//   - Unauthenticated SELECT + GET DATA tag 0x66 for Card
//     Recognition Data. CRD is the only GET DATA tag this command
//     issues; per-card identity tags (CIN 0x45, IIN 0x42) require
//     authentication and surface through 'gp install' / 'gp delete'
//     via --expected-card-id, not through probe.
//   - --sd-aid override and --discover-sd are honored on this
//     unauthenticated path so an operator can confirm a card
//     responds at a non-default ISD AID before opening an
//     authenticated session.
//   - Authenticated discovery (GET STATUS walk over registries)
//     is 'gp registry', not 'gp probe'.
func cmdGPProbe(ctx context.Context, env *runEnv, args []string) error {
	return runProbe(ctx, env, args, probeOptions{
		flagSetName:  "gp probe",
		reportLabel:  "gp probe",
		fetchKeyInfo: false,
	})
}
