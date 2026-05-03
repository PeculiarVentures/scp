// Package pcsc provides a PC/SC (winscard / pcsclite) transport for
// the SCP protocol engine. It connects to a smart-card reader via
// the platform's PC/SC service and exposes the SCP transport.Transport
// interface so a Session can be opened on top.
//
// # Platform requirements
//
// PC/SC is built into Windows and macOS. On Linux, install pcsclite:
//
//	# Debian/Ubuntu
//	apt install pcscd libpcsclite-dev
//	systemctl enable --now pcscd
//
//	# Fedora/RHEL
//	dnf install pcsc-lite pcsc-lite-devel
//	systemctl enable --now pcscd
//
// CGO is required (this package wraps github.com/ebfe/scard which
// links against winscard / pcsclite).
//
// # Module layout
//
// This subpackage has its own go.mod so the main scp module stays
// CGO-free for consumers that bring their own transport. To use:
//
//	go get github.com/PeculiarVentures/scp/transport/pcsc
//
// # Quick start
//
//	t, err := pcsc.OpenFirstReader()        // any connected reader
//	if err != nil { return err }
//	defer t.Close()
//
//	// Or pick a specific one:
//	// t, err := pcsc.OpenReader("Yubico YubiKey OTP+FIDO+CCID 00 00")
//
//	sess, err := session.Open(ctx, t, &session.Config{...})
package pcsc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ebfe/scard"

	"github.com/PeculiarVentures/scp/apdu"
)

// Transport is a PC/SC-backed implementation of the SCP transport
// interface. It owns a card connection and an scard.Context, both of
// which are released by Close().
//
// Transport is NOT safe for concurrent use. The SCP session layer
// already serializes Transmit calls per session; do not share a
// Transport across goroutines.
type Transport struct {
	mu       sync.Mutex
	scCtx    *scard.Context
	card     *scard.Card
	closed   bool
	readerID string
}

// OpenReader connects to a specific reader by name and returns a
// Transport. The reader name comes from ListReaders or from the
// platform's PC/SC management UI.
//
// Empty/no card in the reader is reported via *scard.Error; callers
// can match on the standard sentinels to give a friendly message.
func OpenReader(name string) (*Transport, error) {
	if name == "" {
		return nil, errors.New("pcsc: reader name is empty")
	}
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("pcsc: establish context: %w", err)
	}
	card, err := ctx.Connect(name, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		_ = ctx.Release()
		return nil, fmt.Errorf("pcsc: connect to reader %q: %w", name, err)
	}
	return &Transport{scCtx: ctx, card: card, readerID: name}, nil
}

// OpenFirstReader connects to the first reader the platform reports.
// Convenient for single-reader setups (one YubiKey plugged in).
//
// Errors:
//
//   - no readers found
//   - reader is empty (no card inserted)
//
// Both come back wrapped so callers can discriminate via errors.Is
// against ErrNoReaders / ErrNoCard.
func OpenFirstReader() (*Transport, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("pcsc: establish context: %w", err)
	}
	readers, err := ctx.ListReaders()
	if err != nil {
		_ = ctx.Release()
		return nil, fmt.Errorf("pcsc: list readers: %w", err)
	}
	if len(readers) == 0 {
		_ = ctx.Release()
		return nil, ErrNoReaders
	}
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		_ = ctx.Release()
		// Common case: reader is present but empty.
		if isNoCardError(err) {
			return nil, fmt.Errorf("%w: reader %q", ErrNoCard, readers[0])
		}
		return nil, fmt.Errorf("pcsc: connect to %q: %w", readers[0], err)
	}
	return &Transport{scCtx: ctx, card: card, readerID: readers[0]}, nil
}

// ListReaders returns the names of all readers the platform sees,
// for diagnostics or reader-picker UIs. Does not connect to anything.
func ListReaders() ([]string, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("pcsc: establish context: %w", err)
	}
	defer func() { _ = ctx.Release() }()
	readers, err := ctx.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("pcsc: list readers: %w", err)
	}
	return readers, nil
}

// ReaderName returns the name of the reader this Transport is
// connected to.
func (t *Transport) ReaderName() string { return t.readerID }

// Transmit implements transport.Transport. The command is encoded
// (short or extended APDU per the Command's ExtendedLength flag) and
// sent via SCardTransmit; the response is parsed back into apdu.Response.
//
// A context deadline applies as a best-effort upper bound: pcsclite's
// SCardTransmit doesn't natively accept a timeout, so we honor ctx by
// rejecting the call up front if the context is already done. For
// real timeout behavior, configure the underlying reader.
func (t *Transport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, fmt.Errorf("pcsc: encode APDU: %w", err)
	}
	respBytes, err := t.transmitRaw(encoded)
	if err != nil {
		return nil, err
	}
	if len(respBytes) < 2 {
		return nil, fmt.Errorf("pcsc: response too short (%d bytes)", len(respBytes))
	}
	return &apdu.Response{
		Data: respBytes[:len(respBytes)-2],
		SW1:  respBytes[len(respBytes)-2],
		SW2:  respBytes[len(respBytes)-1],
	}, nil
}

// TransmitRaw implements transport.Transport. It sends pre-encoded
// APDU bytes verbatim and returns the raw response (data || SW1 SW2).
func (t *Transport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t.transmitRaw(raw)
}

func (t *Transport) transmitRaw(raw []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.card == nil {
		return nil, errors.New("pcsc: transport is closed")
	}
	resp, err := t.card.Transmit(raw)
	if err != nil {
		return nil, fmt.Errorf("pcsc: SCardTransmit: %w", err)
	}
	return resp, nil
}

// Close disconnects the card and releases the PC/SC context. Safe to
// call multiple times; subsequent calls return nil.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	var firstErr error
	if t.card != nil {
		if err := t.card.Disconnect(scard.LeaveCard); err != nil {
			firstErr = fmt.Errorf("pcsc: disconnect card: %w", err)
		}
		t.card = nil
	}
	if t.scCtx != nil {
		if err := t.scCtx.Release(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("pcsc: release context: %w", err)
		}
		t.scCtx = nil
	}
	return firstErr
}

// WaitForCard blocks until a card is detected in the named reader,
// or until ctx is done. Useful for "plug in your YubiKey now" UX.
func WaitForCard(ctx context.Context, readerName string) error {
	scCtx, err := scard.EstablishContext()
	if err != nil {
		return fmt.Errorf("pcsc: establish context: %w", err)
	}
	defer func() { _ = scCtx.Release() }()

	readerStates := []scard.ReaderState{
		{Reader: readerName, CurrentState: scard.StateUnaware},
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Poll with a short timeout so ctx cancellation is responsive.
		err := scCtx.GetStatusChange(readerStates, 500*time.Millisecond)
		if err == nil {
			if readerStates[0].EventState&scard.StatePresent != 0 {
				return nil
			}
			readerStates[0].CurrentState = readerStates[0].EventState
			continue
		}
		if isTimeoutError(err) {
			continue
		}
		return fmt.Errorf("pcsc: waiting for card: %w", err)
	}
}

// Sentinel errors callers can match on.
var (
	// ErrNoReaders is returned when ListReaders returns an empty list.
	ErrNoReaders = errors.New("pcsc: no readers connected")

	// ErrNoCard is returned when a reader is present but has no card
	// inserted.
	ErrNoCard = errors.New("pcsc: no card in reader")
)

func isNoCardError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// pcsclite reports "no smart card inserted" / "absent"; winscard
	// uses different strings. Match conservatively on common substrings.
	return strings.Contains(s, "no smart card") ||
		strings.Contains(s, "absent") ||
		strings.Contains(s, "REMOVED")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "TIMEOUT")
}
