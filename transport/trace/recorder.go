package trace

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/PeculiarVentures/scp/aid"
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cardrecognition"
	"github.com/PeculiarVentures/scp/transport"
)

// RecorderConfig configures a new Recorder. Profile, Reader, and
// Notes are descriptive metadata written to the trace header.
//
// Determinism captures the caller-supplied randomness that the test
// pinned (host challenge, OCE ephemeral seed). The recorder does
// not introspect the wire to derive these; the caller must supply
// them so the trace header is accurate. If the test did not pin
// randomness, leave Determinism zero — the trace will still record
// successfully but will not be replay-safe.
type RecorderConfig struct {
	Profile     string
	Reader      string
	CardATR     []byte
	Notes       string
	Determinism Determinism
}

// Recorder is a transport.Transport that records every exchange to
// an in-memory File and flushes it to a writer on Close.
//
// Recording errors do not cause Transmit/TransmitRaw to fail; the
// underlying transport's behavior is preserved exactly. Errors
// surface from Flush.
type Recorder struct {
	inner transport.Transport
	cfg   RecorderConfig

	mu   sync.Mutex
	file File
}

// NewRecorder wraps inner. Exchanges are accumulated in memory until
// Flush is called.
func NewRecorder(inner transport.Transport, cfg RecorderConfig) *Recorder {
	return &Recorder{
		inner: inner,
		cfg:   cfg,
		file: File{
			Schema:      SchemaVersion,
			CapturedAt:  time.Now().UTC(),
			Profile:     cfg.Profile,
			Reader:      cfg.Reader,
			CardATR:     append([]byte(nil), cfg.CardATR...),
			Notes:       cfg.Notes,
			Determinism: cfg.Determinism,
			Exchanges:   nil,
		},
	}
}

// Transmit forwards to the inner transport and records the exchange.
func (r *Recorder) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	cmdBytes, encErr := cmd.Encode()
	start := time.Now()
	resp, err := r.inner.Transmit(ctx, cmd)
	dur := time.Since(start)

	r.mu.Lock()
	defer r.mu.Unlock()

	ex := Exchange{
		I:          len(r.file.Exchanges),
		Kind:       KindTransmit,
		DurationNS: dur.Nanoseconds(),
	}
	if encErr != nil {
		// We couldn't even produce the wire bytes. Record that as
		// an error exchange with what we know — the apdu fields will
		// be empty, which is honest.
		ex.Error = "command encode: " + encErr.Error()
	} else {
		ex.CommandHex = cmdBytes
		fillHeaderFields(&ex, cmdBytes)
		annotateAID(&ex, cmdBytes)
	}
	if err != nil {
		ex.Error = err.Error()
	} else if resp != nil {
		respBytes := encodeResponse(resp)
		ex.ResponseHex = respBytes
		ex.SW = HexBytes{resp.SW1, resp.SW2}
	}
	r.file.Exchanges = append(r.file.Exchanges, ex)

	return resp, err
}

// TransmitRaw forwards to the inner transport and records the exchange.
func (r *Recorder) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	start := time.Now()
	respBytes, err := r.inner.TransmitRaw(ctx, raw)
	dur := time.Since(start)

	r.mu.Lock()
	defer r.mu.Unlock()

	ex := Exchange{
		I:          len(r.file.Exchanges),
		Kind:       KindTransmitRaw,
		CommandHex: append([]byte(nil), raw...),
		DurationNS: dur.Nanoseconds(),
	}
	fillHeaderFields(&ex, raw)
	annotateAID(&ex, raw)
	if err != nil {
		ex.Error = err.Error()
	} else {
		ex.ResponseHex = append([]byte(nil), respBytes...)
		if n := len(respBytes); n >= 2 {
			ex.SW = respBytes[n-2:]
		}
	}
	r.file.Exchanges = append(r.file.Exchanges, ex)

	return respBytes, err
}

// Close closes the inner transport. It does NOT flush — call Flush
// separately to write the recording. Splitting the two means a test
// can decide not to write a recording (e.g. if the test failed for
// reasons unrelated to the protocol).
func (r *Recorder) Close() error {
	return r.inner.Close()
}

// Flush writes the accumulated trace as indented JSON to w.
func (r *Recorder) Flush(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&r.file)
}

// FlushFile writes the trace to path, creating or truncating the
// file. The directory must exist.
func (r *Recorder) FlushFile(path string) (retErr error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()
	return r.Flush(f)
}

// Snapshot returns a copy of the current trace state. Useful for
// tests that want to inspect what was recorded without writing to
// disk.
func (r *Recorder) Snapshot() File {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.file
	out.Exchanges = append([]Exchange(nil), r.file.Exchanges...)
	return out
}

// CaptureCRD probes Card Recognition Data (GET DATA tag 0x66) on the
// inner transport and stores the parsed result in the trace header.
// This is the spec-defined way for a card to publish its claimed GP
// version, supported SCP version, and identification OIDs (GP Card
// Spec §H.2/H.3); putting it in the trace header makes a checked-in
// trace self-describing — anyone reading it can see what kind of
// card produced it without external metadata.
//
// The probe goes through the inner transport directly, bypassing the
// recorder's record path. It does NOT show up as an exchange in the
// trace; an exchange is what the test code did, and the test code
// did not request CRD. If you want CRD-as-an-exchange, call
// cardrecognition.Probe through the recorder yourself.
//
// Call CaptureCRD after SELECTing the applet whose CRD you want
// (typically the ISD). Calling before any SELECT may return CRD
// from whatever applet the OS happened to leave selected, or fail.
//
// CaptureCRD is independent of the recording itself — a probe error
// is returned to the caller without affecting the trace's other
// state, and successful probes do not interact with subsequent
// Transmit / TransmitRaw calls.
func (r *Recorder) CaptureCRD(ctx context.Context) error {
	info, err := cardrecognition.Probe(ctx, r.inner)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.file.CardInfo = info
	r.mu.Unlock()
	return nil
}

// fillHeaderFields populates CLA/INS/P1/P2 from the wire bytes.
// These fields are derived; they exist for review readability and
// are not consulted on replay.
func fillHeaderFields(ex *Exchange, cmd []byte) {
	if len(cmd) < 4 {
		return
	}
	ex.CLA = HexBytes{cmd[0]}
	ex.INS = HexBytes{cmd[1]}
	ex.P1 = HexBytes{cmd[2]}
	ex.P2 = HexBytes{cmd[3]}
}

// annotateAID populates ex.AIDName when the command is SELECT-by-AID
// (INS=0xA4, P1=0x04) and the data field matches a registered AID.
//
// Best-effort: a malformed APDU, an AID not in the registry, or a
// non-SELECT command all leave AIDName empty. Callers reading the
// JSON should treat AIDName as a hint, not authoritative metadata
// about what the card actually selected.
func annotateAID(ex *Exchange, cmd []byte) {
	aidBytes := extractSelectAID(cmd)
	if len(aidBytes) == 0 {
		return
	}
	if entry := aid.Lookup(aidBytes); entry != nil {
		ex.AIDName = entry.Name
	}
}

// extractSelectAID returns the AID bytes from a SELECT-by-AID APDU,
// or nil if cmd is not a SELECT-by-AID or is malformed. Handles both
// short and extended length encodings per ISO 7816-4 §5.1.
//
// Wire shapes accepted:
//
//	short:    00 A4 04 .. Lc <AID> [Le]
//	extended: 00 A4 04 .. 00 LcHi LcLo <AID> [LeHi LeLo]
//
// We don't bother validating CLA — proprietary CLAs (0x80, 0x84) are
// fine for SELECT in practice, and the lookup is best-effort anyway.
func extractSelectAID(cmd []byte) []byte {
	if len(cmd) < 6 || cmd[1] != 0xA4 || cmd[2] != 0x04 {
		return nil
	}
	if cmd[4] != 0x00 {
		// Short form: byte 4 is Lc.
		lc := int(cmd[4])
		if lc == 0 || 5+lc > len(cmd) {
			return nil
		}
		return cmd[5 : 5+lc]
	}
	// Extended form: bytes 5-6 are Lc.
	if len(cmd) < 8 {
		return nil
	}
	lc := int(cmd[5])<<8 | int(cmd[6])
	if lc == 0 || 7+lc > len(cmd) {
		return nil
	}
	return cmd[7 : 7+lc]
}

// encodeResponse serializes a *apdu.Response back to wire bytes.
// apdu.Response has no Encode() method (responses are normally
// produced by ParseResponse, not serialized), so we do it locally.
func encodeResponse(resp *apdu.Response) []byte {
	out := make([]byte, 0, len(resp.Data)+2)
	out = append(out, resp.Data...)
	out = append(out, resp.SW1, resp.SW2)
	return out
}

// Compile-time assertion: Recorder is a Transport.
var _ transport.Transport = (*Recorder)(nil)
