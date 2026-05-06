package gp

import "time"

// TraceEvent is a single APDU exchange or operational milestone
// recorded during a GP session. Trace events are written to a
// TraceSink by the gp/cmd-scpctl orchestration layer; the gp
// package itself does not record events because the pure builders
// in this package never transmit anything.
//
// Phase classifies what part of the operation produced the event.
// Stable values used by this codebase:
//
//	"scp03_handshake"   INITIALIZE UPDATE / EXTERNAL AUTHENTICATE
//	"scp11_handshake"   PERFORM SECURITY OPERATION / mutual auth
//	"select"            applet or SD SELECT
//	"registry"          GET STATUS walks
//	"cap_inspect"       host-side CAP parsing milestones (no APDUs)
//
// Future destructive-path work (Appendix B) introduces "install"
// and "delete" phases for INSTALL [for load|install] and DELETE
// command flows, plus "dry_run" for the host-side preview path
// that bootstrap-oce already uses. The trace event shape does
// not change to accommodate them; only the Phase string set
// grows.
type TraceEvent struct {
	// Timestamp of the event, populated by the sink at Record time
	// when zero. Allowing the caller to set it preserves the option
	// of replaying a captured trace through a sink without losing
	// the original timing.
	Timestamp time.Time

	// Phase classifies the operation; see the type doc for stable
	// values.
	Phase string

	// CommandName is the human-readable label, for example
	// "INITIALIZE UPDATE", "GET STATUS (Applications)", or
	// "INSTALL [for load]". Used for matching in trace tests; not a
	// stable identifier across releases.
	CommandName string

	// PlainAPDU is the GP-layer command APDU before secure-channel
	// wrapping. May be empty when the wrap layer constructed it
	// directly without surfacing a plaintext form.
	PlainAPDU []byte

	// WrappedAPDU is the on-wire bytes after secure-channel
	// wrapping. Populated by transports that observe wire bytes;
	// nil for events recorded above the wrap layer.
	WrappedAPDU []byte

	// Response is the response APDU body (without SW). Empty when
	// the card returned only an SW.
	Response []byte

	// SW is the response status word.
	SW uint16

	// SWMeaning is a short interpretation of SW for human-readable
	// trace output. For example "9000 success",
	// "6310 more data available", "6A86 incorrect P1 or P2".
	SWMeaning string

	// Notes carries free-form annotations from the orchestration
	// layer: load-block index, retry count, fallback decisions,
	// continuation hints. Always safe to log; never holds key
	// material.
	Notes []string
}

// TraceSink receives TraceEvents during a GP session. Implementations
// must be safe for concurrent use because GP orchestration may
// interleave events from multiple goroutines (notably during long
// LOAD sequences when transport metrics share the sink with the GP
// layer).
//
// Sinks are responsible for any redaction beyond what the gp package
// already enforces. The gp package never writes static keys, session
// keys, PINs, or management keys into TraceEvents; sinks should
// nonetheless treat trace files as sensitive because they carry the
// card identifier and registry shape.
type TraceSink interface {
	Record(event TraceEvent)
}

// NopTraceSink discards every event. Used as the default sink so
// orchestration code can call Record unconditionally without nil
// checks.
type NopTraceSink struct{}

// Record implements TraceSink.
func (NopTraceSink) Record(TraceEvent) {}
