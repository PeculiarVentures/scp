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

Maturity: spec-implemented per GP Card Specification v2.3.1.
'gp probe' is hardware-verified against retail YubiKey 5.7+ and
a wide range of non-YubiKey cards (SafeNet eToken Fusion,
SafeNet Token JC, ML840, Oberthur, GoldKey, Feitian, Treasury
Gemalto). 'gp registry', 'gp install', 'gp delete', and
'gp cap inspect' are mock-validated against a YubiKey-shaped
GP simulator; not yet hardware-verified end to end against
real cards. Production use of the not-yet-verified subcommands
requires operator-side acceptance testing on the target card.

Usage:
  scpctl gp <subcommand> [flags]

Subcommands:
  probe       Unauthenticated GP card probe: SELECT the SD, GET
              DATA tag 0x66 for Card Recognition Data, plus the
              GP §H.6 / §H.4 identification reads (CPLC, IIN,
              CIN, KDD, SSC, Card Capabilities). Reports GP
              version and supported SCPs. Read-only. Supports
              --sd-aid for cards with a non-default ISD and
              --discover-sd to walk a curated AID list. Functionally
              equivalent to 'scpctl probe' under a gp-tagged report
              label.
  registry    Open an authenticated SCP03 session and walk the GP
              registry across three scopes (ISD, Applications,
              LoadFiles+Modules) via GET STATUS. Output uses the
              same JSON registry shape as 'sd info --full' so
              scripts can switch between the two unchanged. Per-
              scope failure policy: 6A88 (no entries) is PASS,
              6982/6A86/6D00 (auth required, unsupported P2 form,
              unsupported INS) is SKIP per scope, OpenSCP03 itself
              failing is FAIL. Supports --sd-aid for cards with a
              non-default ISD. Requires explicit SCP03 key choice:
              --scp03-keys-default, --scp03-key with --scp03-kvn,
              or --scp03-{enc,mac,dek} with --scp03-kvn.
  cap         CAP file utilities (host-only):
                inspect <path>  Print package AID and version,
                                applet inventory, and component
                                manifest from a CAP file on disk.
  install     Install an applet onto a card under SCP03. Parses
              the CAP, builds the load image (Debug+Descriptor
              excluded by default), opens an authenticated
              session, and chains INSTALL [for load] -> LOAD ->
              INSTALL [for install]. Destructive; gated behind
              --confirm-write. Without that flag the command is
              read-only: it parses the CAP, prints the load
              image SHA-256/SHA-1, and reports what it would
              send. Failure mid-chain surfaces a precise stage
              + cleanup recipe.
  delete      Remove a registered AID from the card. With
              --related the delete cascades to applets
              instantiated from the named load file. Destructive;
              gated behind --confirm-write. SW=6A88 is reported
              as FAIL with a hint that the object may already
              be absent.

What is NOT in this group today (deferred to future work):
  - Exploratory AID probing beyond the discovery candidate
    list (e.g. brute-force with 6A87 fallthrough heuristics for
    cards whose AID isn't in any documentation).
  - Vendor-specific INSTALL parameter generators (CIN/IIN
    binding, NFC LCM bits, JC platform-specific TLVs).
    Operators can pass these as raw bytes via --install-params
    / --load-params on 'gp install' if they have the spec.

Use "scpctl gp <subcommand> -h" for per-command flags.
`)
}
