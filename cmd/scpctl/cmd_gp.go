package main

import (
	"fmt"
	"io"
)

// gpUsage prints the help banner for the gp command group. The
// dispatch table itself (gpCommands) lives in main.go alongside
// the other group dispatches; this file holds only the help text
// so it stays close to the command-specific files in cmd_gp_*.go
// rather than crowding main.go.
//
// The gp group's role and its boundary against the sd group:
//
//   - sd is the YubiKey-flavored Security Domain operator surface:
//     identity, reset, lock/unlock/terminate, OCE/SCP11a bootstraps.
//     Audience: people running PeculiarVentures-issued YubiKey-shaped
//     workflows.
//
//   - gp is the generic GlobalPlatform card-content management
//     operator surface: discovery, registry walks, CAP file
//     inspection on arbitrary GP cards. Audience: people running
//     applet-management workflows on JCOP, third-party Java Cards,
//     and other GP-conformant tokens.
//
// The two groups share the underlying securitydomain.Session API
// (registry walks reuse the existing GetStatus path) but have
// different entry points so operators with different mental
// models reach the right tool.
func gpUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl gp - Generic GlobalPlatform card-content management

Usage:
  scpctl gp <subcommand> [flags]

Subcommands:
  probe       Use the existing default ISD probe path: SELECT
              with empty AID, GET DATA tag 0x66 for Card
              Recognition Data. Reports GP version and supported
              SCPs. Read-only. Functionally equivalent to
              'scpctl probe' under a gp-tagged report label.
              This MVP does not yet support alternate SD AID
              probing or non-default SELECT, so cards that
              require either (for example SafeNet/Fusion with a
              custom ISD AID) will still fail with SW=6A82.
  registry    Open an authenticated SCP03 session and walk the GP
              registry across three scopes (ISD, Applications,
              LoadFiles+Modules) via GET STATUS. Output uses the
              same JSON registry shape as 'sd info --full' so
              scripts can switch between the two unchanged. Per-
              scope failure policy: 6A88 (no entries) is PASS,
              6982/6A86/6D00 (auth required, unsupported P2 form,
              unsupported INS) is SKIP per scope, OpenSCP03 itself
              failing is FAIL.
  cap         CAP file utilities (host-only):
                inspect <path>  Print package AID and version,
                                applet inventory, and component
                                manifest from a CAP file on disk.

What is NOT in this group today (deferred to future work):
  - 'gp install' / 'gp delete' for destructive applet content
    management. Gated on the AES-CMAC key diversification work,
    a Java Card SDK build of an Echo applet fixture, real JCOP
    cards for validation, and the SCP03+GP combined simulator.
  - SafeNet/Fusion exploratory probing.

Use "scpctl gp <subcommand> -h" for per-command flags.
`)
}
