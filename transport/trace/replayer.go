package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// Replayer is a transport.Transport backed by a recorded trace.
// Each Transmit/TransmitRaw call is matched byte-exact against the
// next exchange in the trace. Mismatches return a MismatchError.
type Replayer struct {
	file File

	mu  sync.Mutex
	pos int
}

// NewReplayer reads a trace from path.
func NewReplayer(path string) (*Replayer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewReplayerFromBytes(data)
}

// NewReplayerFromBytes parses a trace from in-memory bytes.
func NewReplayerFromBytes(data []byte) (*Replayer, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("trace: parse: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &Replayer{file: f}, nil
}

// HostChallenge returns the host challenge the trace was captured
// with, or nil if none was pinned.
func (r *Replayer) HostChallenge() []byte {
	return append([]byte(nil), r.file.Determinism.HostChallenge...)
}

// OCEEphemeralSeed returns the OCE ephemeral seed the trace was
// captured with, or nil if none was pinned.
func (r *Replayer) OCEEphemeralSeed() []byte {
	return append([]byte(nil), r.file.Determinism.OCEEphemeralSeed...)
}

// Profile returns the profile metadata from the trace header.
func (r *Replayer) Profile() string { return r.file.Profile }

// MismatchError is returned when a replayed call diverges from the
// recorded trace. It carries enough context to make the failure
// diagnosable from a CI log.
type MismatchError struct {
	Index           int
	ExpectedKind    Kind
	ActualKind      Kind
	ExpectedCommand []byte
	ActualCommand   []byte
	Annotation      string
}

func (e *MismatchError) Error() string {
	if e.ExpectedKind != e.ActualKind {
		return fmt.Sprintf(
			"trace: exchange %d kind mismatch: trace=%s call=%s (annotation: %q)",
			e.Index, e.ExpectedKind, e.ActualKind, e.Annotation,
		)
	}
	return fmt.Sprintf(
		"trace: exchange %d command mismatch (annotation: %q)\n  expected: %x\n    actual: %x",
		e.Index, e.Annotation, e.ExpectedCommand, e.ActualCommand,
	)
}

// ErrExhausted is returned when a replayed call would consume past
// the end of the recorded trace.
var ErrExhausted = errors.New("trace: replayer exhausted")

// ErrUnconsumed is returned from Close when not all exchanges were
// consumed. Under-consumption is a regression signal — a flow that
// stopped halfway is rarely correct.
type ErrUnconsumed struct {
	Consumed, Total int
}

func (e *ErrUnconsumed) Error() string {
	return fmt.Sprintf("trace: %d/%d exchanges unconsumed at close", e.Total-e.Consumed, e.Total)
}

// Transmit returns the next recorded response if the call matches
// the next recorded exchange.
func (r *Replayer) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	cmdBytes, err := cmd.Encode()
	if err != nil {
		return nil, fmt.Errorf("trace: encode command for replay: %w", err)
	}
	respBytes, err := r.next(KindTransmit, cmdBytes)
	if err != nil {
		return nil, err
	}
	if respBytes == nil {
		// Recorded as an error exchange — replay the same error.
		return nil, r.recordedError()
	}
	return apdu.ParseResponse(respBytes)
}

// TransmitRaw returns the next recorded response bytes if the call
// matches the next recorded exchange.
func (r *Replayer) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	respBytes, err := r.next(KindTransmitRaw, raw)
	if err != nil {
		return nil, err
	}
	if respBytes == nil {
		return nil, r.recordedError()
	}
	return append([]byte(nil), respBytes...), nil
}

// Close returns ErrUnconsumed if the trace was not fully replayed.
func (r *Replayer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pos != len(r.file.Exchanges) {
		return &ErrUnconsumed{Consumed: r.pos, Total: len(r.file.Exchanges)}
	}
	return nil
}

// next advances the replay cursor, validating kind and command bytes.
// Returns the response bytes, or nil with err == nil if the recorded
// exchange was an error (caller fetches via recordedError).
func (r *Replayer) next(kind Kind, cmd []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pos >= len(r.file.Exchanges) {
		return nil, ErrExhausted
	}
	ex := r.file.Exchanges[r.pos]

	if ex.Kind != kind || !bytes.Equal(ex.CommandHex, cmd) {
		return nil, &MismatchError{
			Index:           r.pos,
			ExpectedKind:    ex.Kind,
			ActualKind:      kind,
			ExpectedCommand: append([]byte(nil), ex.CommandHex...),
			ActualCommand:   append([]byte(nil), cmd...),
			Annotation:      ex.Annotation,
		}
	}
	r.pos++

	if ex.Error != "" {
		return nil, nil
	}
	return ex.ResponseHex, nil
}

// recordedError reconstitutes the previous exchange's error. We do
// not preserve typed errors across a JSON round-trip; the test sees
// a plain string-equal error from the trace. That is sufficient for
// regression testing of error paths and avoids the maze of
// transport-error-type mapping.
func (r *Replayer) recordedError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pos == 0 {
		return errors.New("trace: recordedError called before any exchange")
	}
	return errors.New(r.file.Exchanges[r.pos-1].Error)
}

// Compile-time assertion: Replayer is a Transport.
var _ transport.Transport = (*Replayer)(nil)
