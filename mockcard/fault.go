package mockcard

import (
	"github.com/PeculiarVentures/scp/apdu"
)

// Fault is an APDU-level rule that overrides the mock's default
// response. Used by tests to exercise card-side error paths
// without polluting the production-shaped GP state model.
//
// Faults register on SCP03Card via AddFault. The mock evaluates
// faults in registration order before any GP/SCP handler; the
// first match returns its Response and short-circuits dispatch.
// Faults marked Once unregister themselves after firing, so a
// "fail next INSTALL" rule does not affect a retry.
//
// Match runs after SM unwrap, so it sees the post-decrypt
// command. Use the helper constructors (FailINS, FailLoadAtSeq,
// etc.) for the common cases rather than open-coding Match.
type Fault struct {
	// Match returns true for commands this fault should fire on.
	Match func(cmd *apdu.Command) bool
	// Response is what the mock returns when Match is true.
	Response *apdu.Response
	// Once, if true, removes the fault after it fires once. The
	// retry path then sees the mock's default behavior, which is
	// the typical "force one failure, then check recovery"
	// pattern.
	Once bool

	fired bool
}

// FailINS returns a one-shot fault that rejects the next APDU
// matching (ins, p1, p2) with the supplied SW. P1 and P2 may be
// 0xFF as wildcards in the helper, but the helper does not
// implement wildcards; supply the exact bytes you want to match.
// For wildcard or layered patterns, build the Fault directly.
func FailINS(ins, p1, p2 byte, sw uint16) *Fault {
	return &Fault{
		Match: func(cmd *apdu.Command) bool {
			return cmd.INS == ins && cmd.P1 == p1 && cmd.P2 == p2
		},
		Response: mkSW(sw),
		Once:     true,
	}
}

// FailInstallForLoad returns a one-shot fault that rejects the
// next INSTALL [for load] (INS=0xE6, P1=0x02) with the supplied
// SW. Convenience for the common stage-1 failure recovery test.
func FailInstallForLoad(sw uint16) *Fault {
	return FailINS(0xE6, 0x02, 0x00, sw)
}

// FailInstallForInstall returns a one-shot fault that rejects
// FailInstallForInstall returns a one-shot fault that rejects
// the next INSTALL [for install] APDU with the supplied SW.
// Matches any P1 with the install bit (0x04) set per GP Card
// Spec v2.3.1 §11.5.2.1 table 11-49 — that catches both 0x04
// (install only) and 0x0C (combined install + make-selectable,
// the production default since the gp install P1 fix). Test
// fixtures stay portable across the two encodings without
// having to know which one the host code uses.
func FailInstallForInstall(sw uint16) *Fault {
	return &Fault{
		Match: func(cmd *apdu.Command) bool {
			return cmd.INS == 0xE6 && cmd.P1&0x04 != 0 && cmd.P2 == 0x00
		},
		Response: mkSW(sw),
		Once:     true,
	}
}

// FailLoadAtSeq returns a one-shot fault that rejects the LOAD
// block with the given sequence number with the supplied SW.
// LOAD's last-block flag in P1 high bit is masked out before
// match so a fault on seq=0 fires regardless of whether seq=0
// is the only block (P1=0x80) or one of many (P1=0x00).
func FailLoadAtSeq(seq int, sw uint16) *Fault {
	target := byte(seq)
	return &Fault{
		Match: func(cmd *apdu.Command) bool {
			return cmd.INS == 0xE8 && cmd.P2 == target
		},
		Response: mkSW(sw),
		Once:     true,
	}
}
