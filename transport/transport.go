// Package transport defines the interface between the SCP11 protocol
// engine and the physical card communication layer. This follows the
// architecture: decouple the fixed,
// spec-driven SCP session logic from the transport implementation
// (PC/SC, NFC, gRPC relay, USB HID, SPI, etc.).
//
// Implementers provide a concrete Transport for their environment.
// The SCP11 session wraps it with secure messaging transparently.
package transport

import (
	"context"

	"github.com/PeculiarVentures/scp/apdu"
)

// Transport is the low-level card communication interface. Implementations
// send raw APDU bytes to the card and return raw response bytes.
// The SCP11 session layer wraps this to add encryption and MAC.
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

// TransmitCollectAll sends a command and handles GET RESPONSE chaining
// (status 61xx) to collect the full response data.
func TransmitCollectAll(ctx context.Context, t Transport, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := t.Transmit(ctx, cmd)
	if err != nil {
		return nil, err
	}

	var allData []byte
	allData = append(allData, resp.Data...)

	for resp.IsMoreData() {
		getResp := apdu.NewGetResponse(resp.SW2)
		resp, err = t.Transmit(ctx, getResp)
		if err != nil {
			return nil, err
		}
		allData = append(allData, resp.Data...)
	}

	return &apdu.Response{
		Data: allData,
		SW1:  resp.SW1,
		SW2:  resp.SW2,
	}, nil
}
