// Package transport defines the interface between the SCP protocol
// engine (SCP03 and SCP11) and the physical card communication layer.
// The seam exists so the spec-driven session logic can stay independent
// of the underlying transport (PC/SC, NFC, gRPC relay, USB HID, SPI,
// in-memory mock, etc.).
//
// Implementers provide a concrete Transport for their environment.
// The session layer wraps it with secure messaging transparently
// once the handshake completes.
package transport

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
)

// Caps applied to GET RESPONSE chaining and collected-response sizes
// in TransmitWithChaining and TransmitCollectAll. They exist to keep
// a misbehaving or hostile card from looping the host indefinitely
// or returning unbounded data.
//
// MaxGetResponseIterations is the maximum number of GET RESPONSE
// APDUs the host will issue for a single command, regardless of
// how many SW=61xx continuations the card requests.
//
// MaxCollectedResponseBytes is the maximum number of response
// data bytes accumulated across chained iterations. Reached either
// limit returns an error from the chaining helper.
const (
	MaxGetResponseIterations  = 256
	MaxCollectedResponseBytes = 1 << 20
)

// TrustBoundary describes whether the host running the program
// is in the same trust boundary as the card. The value is consulted
// by callers (notably the scpctl piv surface) before allowing raw
// APDU operations: raw mode is only safe when the host between the
// operator and the card is fully trusted, and the transport is the
// component that knows whether that's true.
//
// Adding this to the Transport interface (rather than asking the
// caller to figure it out) means a future relay or browser-mediated
// transport cannot quietly become "raw-acceptable" by accident; it
// has to declare its boundary explicitly, and the default value
// (TrustBoundaryUnknown) fails closed against raw-mode gates.
type TrustBoundary string

const (
	// TrustBoundaryLocalPCSC means the transport is direct local
	// PC/SC against a card plugged into the host. The kernel, the
	// PC/SC daemon, the binary, and the card are all in scope of
	// the same operator. Raw APDUs are acceptable here because no
	// untrusted party sits between the host and the card.
	TrustBoundaryLocalPCSC TrustBoundary = "local-pcsc"

	// TrustBoundaryRelay means the transport relays APDUs across
	// a network or process boundary the operator does not control
	// end to end (gRPC card relay, browser-mediated session, etc.).
	// Raw APDUs are NOT acceptable here; SCP11b (or another
	// authenticated key-agreement layer) is required to keep PIN/
	// management-key/PIV traffic confidential and integrity-
	// protected through the relay.
	TrustBoundaryRelay TrustBoundary = "relay"

	// TrustBoundaryUnknown is the default for transports that
	// cannot or do not classify themselves (mocks, future custom
	// transports that haven't opted in). Treated as not-local for
	// raw-mode gating purposes: a transport whose boundary is
	// unknown cannot be assumed to be safe for raw destructive
	// operations. Tests that need to exercise raw paths against
	// the mock use a wrapper that explicitly overrides the
	// boundary; production code paths never reach
	// TrustBoundaryUnknown.
	TrustBoundaryUnknown TrustBoundary = "unknown"
)

// Transport is the low-level card communication interface. Implementations
// send raw APDU bytes to the card and return raw response bytes.
// The SCP session layer (SCP03 or SCP11) wraps this to add encryption and MAC.
type Transport interface {
	// Transmit sends a command APDU and returns the response.
	// Implementations handle the physical layer: PC/SC SCardTransmit,
	// NFC IsoDep.transceive, gRPC relay, etc.
	Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error)

	// TransmitRaw sends pre-encoded APDU bytes and returns raw response
	// bytes. Used for cases where the caller has already serialized
	// the command (e.g., replaying stored APDUs).
	TransmitRaw(ctx context.Context, raw []byte) ([]byte, error)

	// Close releases the underlying card connection.
	Close() error

	// TrustBoundary reports the host-to-card trust posture of
	// this transport. Callers gating raw-mode operations consult
	// this; see TrustBoundary's doc for the full rationale.
	// Implementations should return a stable value for the
	// lifetime of the transport.
	TrustBoundary() TrustBoundary
}

// TransmitWithChaining sends a command that may exceed 255 bytes by
// splitting it into chained APDUs. Only the final response is returned.
// Intermediate responses must be 9000 (success).
func TransmitWithChaining(ctx context.Context, t Transport, cmd *apdu.Command) (*apdu.Response, error) {
	cmds, err := apdu.ChainCommands(cmd)
	if err != nil {
		return nil, err
	}

	for i, c := range cmds {
		resp, err := t.Transmit(ctx, c)
		if err != nil {
			return nil, err
		}
		// Intermediate chained commands should return 9000.
		if i < len(cmds)-1 {
			if !resp.IsSuccess() {
				return resp, resp.Error()
			}
		} else {
			return resp, nil
		}
	}
	// Unreachable, but the compiler wants it.
	return nil, nil
}

// TransmitCollectAll sends a command and handles two ISO 7816-4 /
// GP-spec "data delivery" status-word patterns:
//
//   - SW=6Cxx ("wrong Le; correct length is xx"). Retry the SAME
//     command with Le=xx as the card hinted. Hint byte 0x00 means
//     256 (max short-form Le).
//   - SW=61xx ("more data available"). Walk the GET RESPONSE chain
//     until a non-61xx terminator. Concatenated body is returned.
//
// 6Cxx and 61xx can compose; the helper handles that by performing
// the Le-corrected retry first, then falling through to the 61xx
// chain loop on the retry's response.
//
// Also applies the MaxGetResponseIterations and
// MaxCollectedResponseBytes safety bounds against runaway cards.
func TransmitCollectAll(ctx context.Context, t Transport, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// 6Cxx Le-retry: the card is telling us the request had the
	// wrong Le. Retry the SAME command with the corrected Le. Per
	// ISO 7816-4 §5.3.4 the hint byte 0x00 means 256, not zero.
	// This is a one-shot retry; if the card answers the retry with
	// 6Cxx again it is misbehaving, and we fall through to surface
	// that SW rather than looping.
	if resp.SW1 == 0x6C {
		retry := *cmd
		if resp.SW2 == 0x00 {
			retry.Le = 256
		} else {
			retry.Le = int(resp.SW2)
		}
		resp, err = t.Transmit(ctx, &retry)
		if err != nil {
			return nil, fmt.Errorf("6Cxx Le-retry: %w", err)
		}
	}

	var allData []byte
	allData = append(allData, resp.Data...)

	for i := 0; resp.IsMoreData(); i++ {
		if i >= MaxGetResponseIterations {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d iterations", MaxGetResponseIterations)
		}
		if len(allData) >= MaxCollectedResponseBytes {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", MaxCollectedResponseBytes)
		}
		getResp := apdu.NewGetResponse(resp.SW2)
		resp, err = t.Transmit(ctx, getResp)
		if err != nil {
			return nil, err
		}
		allData = append(allData, resp.Data...)
		// Recheck after the append — earlier this only checked before
		// the call, so a card returning a final fat chunk could push
		// the buffer past the cap by up to 256 bytes (or however large
		// the chunk is). Verify on both sides of the append.
		if len(allData) > MaxCollectedResponseBytes {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", MaxCollectedResponseBytes)
		}
	}

	return &apdu.Response{
		Data: allData,
		SW1:  resp.SW1,
		SW2:  resp.SW2,
	}, nil
}

// DrainGetResponse extends an initial response by issuing GET RESPONSE
// over the raw transport for as long as the card returns SW=61xx
// ("more data follows"). The accumulated data plus the final SW
// is returned as a single Response.
//
// Used by SCP03 and SCP11 Session.Transmit to assemble the full
// secure-messaging-protected payload before invoking R-MAC
// verification. The card has computed the MAC over the entire
// encrypted response; verifying a partial chunk fails MAC by
// construction and (per GP §4.8) terminates the channel.
//
// Why this needs to be a transport-level helper rather than an
// apdu.TransmitWithChaining call from the Session: GET RESPONSE
// is a transport continuation, not an application-layer command.
// Sending GET RESPONSE through the secure channel would re-wrap
// it (incrementing the C-MAC chain on a continuation that the
// card doesn't see as a wrapped command) and fail the next real
// wrapped command. The drain runs on the underlying transport,
// bypasses the channel layer, and returns the assembled bytes
// for the channel to verify in one shot.
//
// initial is the response that may carry SW=61xx. If initial's
// SW1 is not 0x61, DrainGetResponse returns it unchanged with no
// extra round trips. The same MaxGetResponseIterations and
// MaxCollectedResponseBytes caps apply as TransmitCollectAll.
func DrainGetResponse(ctx context.Context, t Transport, initial *apdu.Response) (*apdu.Response, error) {
	if initial == nil {
		return nil, fmt.Errorf("DrainGetResponse: nil initial response")
	}
	if !initial.IsMoreData() {
		return initial, nil
	}

	allData := append([]byte(nil), initial.Data...)
	resp := initial
	for i := 0; resp.IsMoreData(); i++ {
		if i >= MaxGetResponseIterations {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d iterations", MaxGetResponseIterations)
		}
		if len(allData) >= MaxCollectedResponseBytes {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", MaxCollectedResponseBytes)
		}
		next, err := t.Transmit(ctx, apdu.NewGetResponse(resp.SW2))
		if err != nil {
			return nil, fmt.Errorf("GET RESPONSE step %d: %w", i+1, err)
		}
		allData = append(allData, next.Data...)
		if len(allData) > MaxCollectedResponseBytes {
			return nil, fmt.Errorf("GET RESPONSE exceeded %d bytes", MaxCollectedResponseBytes)
		}
		resp = next
	}
	return &apdu.Response{
		Data: allData,
		SW1:  resp.SW1,
		SW2:  resp.SW2,
	}, nil
}
