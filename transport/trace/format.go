// Package trace provides record/replay decorators for
// transport.Transport. A Recorder wraps any underlying transport and
// captures the APDU exchanges to a JSON file; a Replayer serves
// recorded exchanges back as a transport for tests.
//
// See DESIGN.md in the package directory for the full design notes,
// including the rationale for strict matching and the determinism
// contract that callers are responsible for.
package trace

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PeculiarVentures/scp/cardrecognition"
)

// SchemaVersion is the on-disk format identifier. Any breaking
// change to field semantics bumps this value; additive optional
// fields do not.
const SchemaVersion = "scp-trace/v1"

// File is the on-disk shape of a trace.
type File struct {
	Schema      string                    `json:"schema"`
	CapturedAt  time.Time                 `json:"captured_at"`
	Profile     string                    `json:"profile,omitempty"`
	Reader      string                    `json:"reader,omitempty"`
	CardATR     HexBytes                  `json:"card_atr,omitempty"`
	CardInfo    *cardrecognition.CardInfo `json:"card_info,omitempty"`
	Notes       string                    `json:"notes,omitempty"`
	Determinism Determinism               `json:"determinism"`
	Exchanges   []Exchange                `json:"exchanges"`
}

// Determinism records the caller-supplied randomness that was used
// when the trace was captured. Replay tests must wire the same
// values back through the SCP config; otherwise the first
// command-bytes comparison will fail.
//
// A nil HostChallenge means the recording did not pin one
// (i.e. SCP03 was driven with random challenge). Such traces are
// not replay-safe; the recorder writes them anyway because the
// recording itself is still useful as evidence.
type Determinism struct {
	HostChallenge    HexBytes `json:"host_challenge_hex,omitempty"`
	OCEEphemeralSeed HexBytes `json:"oce_ephemeral_seed_hex,omitempty"`
}

// Kind distinguishes which transport method was called for an
// exchange. Replay matches on the same kind that recording captured;
// calling TransmitRaw against an exchange recorded via Transmit (or
// vice-versa) is a mismatch.
type Kind string

const (
	KindTransmit    Kind = "Transmit"
	KindTransmitRaw Kind = "TransmitRaw"
)

// Exchange is a single APDU command/response pair (or a command
// that errored before producing a response).
//
// CLA/INS/P1/P2 are derived from CommandHex and exist purely for
// diff readability when reviewing checked-in fixtures. They are
// recomputed on read; the replayer ignores them.
type Exchange struct {
	I           int      `json:"i"`
	Kind        Kind     `json:"kind"`
	CLA         HexBytes `json:"cla,omitempty"`
	INS         HexBytes `json:"ins,omitempty"`
	P1          HexBytes `json:"p1,omitempty"`
	P2          HexBytes `json:"p2,omitempty"`
	CommandHex  HexBytes `json:"command_hex"`
	ResponseHex HexBytes `json:"response_hex,omitempty"`
	SW          HexBytes `json:"sw,omitempty"`
	DurationNS  int64    `json:"duration_ns,omitempty"`
	Error       string   `json:"error,omitempty"`
	Annotation  string   `json:"annotation,omitempty"`
}

// HexBytes is a byte slice that marshals to/from a lowercase hex
// string in JSON. Empty slices emit as "" (and omitempty drops the
// field entirely).
type HexBytes []byte

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

// UnmarshalJSON implements json.Unmarshaler. It accepts both
// lowercase and uppercase hex.
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return fmt.Errorf("trace: invalid hex %q: %w", s, err)
	}
	*h = b
	return nil
}

// Validate checks structural invariants of a parsed trace file.
// It is intentionally cheap — it does not verify that responses
// look well-formed or that exchanges form a coherent SCP flow.
// Those are the SCP layer's concerns, not the trace format's.
func (f *File) Validate() error {
	if f.Schema != SchemaVersion {
		return fmt.Errorf("trace: schema %q is not supported (want %q)", f.Schema, SchemaVersion)
	}
	for i, ex := range f.Exchanges {
		if ex.I != i {
			return fmt.Errorf("trace: exchange %d has out-of-order index %d", i, ex.I)
		}
		switch ex.Kind {
		case KindTransmit, KindTransmitRaw:
		default:
			return fmt.Errorf("trace: exchange %d has unknown kind %q", i, ex.Kind)
		}
		if len(ex.CommandHex) == 0 {
			return fmt.Errorf("trace: exchange %d has empty command", i)
		}
		if ex.Error == "" && len(ex.ResponseHex) < 2 {
			return fmt.Errorf("trace: exchange %d has no error and response < 2 bytes", i)
		}
	}
	return nil
}
