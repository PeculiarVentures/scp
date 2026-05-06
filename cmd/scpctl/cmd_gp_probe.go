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
// What this command deliberately does NOT do in MVP:
//
//   - Per-card identity exposure (CIN tag 0x45, IIN tag 0x42). These
//     are separate GET DATA calls beyond CRD and are reserved for
//     Appendix B alongside the --expected-card-id flag they exist
//     to support.
//   - SCP03 authenticated probing. The unauthenticated path is the
//     full main-body scope; authenticated discovery is gp registry.
//   - --sd-aid override. The default ISD AID covers every card we
//     can validate against today; override support lands when a
//     real-world card requires it.
func cmdGPProbe(ctx context.Context, env *runEnv, args []string) error {
	return runProbe(ctx, env, args, probeOptions{
		flagSetName:  "gp probe",
		reportLabel:  "gp probe",
		fetchKeyInfo: false,
	})
}
