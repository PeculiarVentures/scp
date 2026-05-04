// Package apdu provides ISO 7816-4 command and response APDU types
// used for smart card communication. It supports both short length
// encoding (Lc/Le ≤ 255) and extended length encoding (Lc/Le ≤ 65535)
// per ISO 7816-4 §5.1, as well as command chaining for transports
// that do not support extended length.
package apdu

import (
	"context"
	"errors"
	"fmt"
)

// Command represents an ISO 7816-4 Command APDU.
type Command struct {
	CLA  byte   // Class byte. SCP11 secure messaging sets bit 3 (0x04).
	INS  byte   // Instruction byte
	P1   byte   // Parameter 1
	P2   byte   // Parameter 2
	Data []byte // Command data field (may be nil)
	Le   int    // Expected response length. -1 = absent, 0 = max (256 short / 65536 extended).

	// ExtendedLength enables ISO 7816-4 extended length encoding,
	// which supports Lc up to 65535 bytes and Le up to 65536 bytes.
	// When false, Encode uses short encoding (Lc ≤ 255) and returns
	// an error if Data exceeds 255 bytes.
	//
	// YubiKey 5 series (firmware 5.7+) supports extended length APDUs
	// over CCID. This avoids command chaining overhead, which matters
	// for large payloads like post-quantum certificates (~5KB).
	ExtendedLength bool
}

// Response represents an ISO 7816-4 Response APDU.
type Response struct {
	Data []byte // Response data field
	SW1  byte   // Status byte 1
	SW2  byte   // Status byte 2
}

// StatusWord returns the two status bytes as a single uint16.
func (r *Response) StatusWord() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// IsSuccess returns true if the status word indicates normal completion.
func (r *Response) IsSuccess() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

// IsMoreData returns true if the card has more data available (61xx).
func (r *Response) IsMoreData() bool {
	return r.SW1 == 0x61
}

// Error returns a descriptive error for non-success responses.
func (r *Response) Error() error {
	if r.IsSuccess() {
		return nil
	}
	return fmt.Errorf("card returned SW=%04X (%s)", r.StatusWord(), swDescription(r.StatusWord()))
}

// Encode serializes a Command into wire bytes.
//
// Short encoding (default): Lc and Le are single bytes, max 255/256.
// Extended encoding (ExtendedLength=true): Lc and Le use 3-byte
// encoding per ISO 7816-4 §5.1, supporting up to 65535/65536.
//
// For short encoding with payloads exceeding 255 bytes, use
// ChainCommands to split into multiple APDUs, or set ExtendedLength.
func (c *Command) Encode() ([]byte, error) {
	if c.ExtendedLength {
		return c.encodeExtended()
	}
	return c.encodeShort()
}

func (c *Command) encodeShort() ([]byte, error) {
	buf := []byte{c.CLA, c.INS, c.P1, c.P2}

	if len(c.Data) > 0 {
		if len(c.Data) > 255 {
			return nil, errors.New("data exceeds 255 bytes; use ExtendedLength or ChainCommands")
		}
		buf = append(buf, byte(len(c.Data)))
		buf = append(buf, c.Data...)
	}

	if c.Le >= 0 {
		if c.Le > 256 {
			return nil, errors.New("Le exceeds 256 for short encoding; use ExtendedLength")
		}
		if c.Le == 256 {
			buf = append(buf, 0x00)
		} else {
			buf = append(buf, byte(c.Le))
		}
	}

	return buf, nil
}

// encodeExtended uses ISO 7816-4 extended length encoding.
//
// Format with data:
//
//	CLA INS P1 P2 | 0x00 Lc_hi Lc_lo | Data | [Le_hi Le_lo]
//
// Format without data:
//
//	CLA INS P1 P2 | 0x00 Le_hi Le_lo
//
// Le=0 encodes as 0x0000 (meaning 65536, "return everything").
func (c *Command) encodeExtended() ([]byte, error) {
	buf := []byte{c.CLA, c.INS, c.P1, c.P2}

	if len(c.Data) > 0 {
		if len(c.Data) > 65535 {
			return nil, errors.New("data exceeds 65535 bytes")
		}
		lc := len(c.Data)
		buf = append(buf, 0x00, byte(lc>>8), byte(lc))
		buf = append(buf, c.Data...)
	}

	if c.Le >= 0 {
		if len(c.Data) == 0 {
			// Case 2E: no data, just Le. Prefix with 0x00.
			buf = append(buf, 0x00)
		}
		if c.Le > 65536 {
			return nil, errors.New("Le exceeds 65536")
		}
		if c.Le == 65536 || c.Le == 0 {
			buf = append(buf, 0x00, 0x00)
		} else {
			buf = append(buf, byte(c.Le>>8), byte(c.Le))
		}
	}

	return buf, nil
}

// ParseResponse parses raw bytes from a card into a Response.
func ParseResponse(raw []byte) (*Response, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(raw))
	}
	return &Response{
		Data: raw[:len(raw)-2],
		SW1:  raw[len(raw)-2],
		SW2:  raw[len(raw)-1],
	}, nil
}

// ChainCommands splits a large-payload command into chained APDUs,
// each carrying at most 255 bytes. All but the last command have
// CLA bit 5 set (0x10) to indicate chaining.
func ChainCommands(cmd *Command) ([]*Command, error) {
	if len(cmd.Data) <= 255 {
		return []*Command{cmd}, nil
	}

	var cmds []*Command
	data := cmd.Data
	for len(data) > 255 {
		chunk := data[:255]
		data = data[255:]
		cmds = append(cmds, &Command{
			CLA:  cmd.CLA | 0x10, // chaining bit
			INS:  cmd.INS,
			P1:   cmd.P1,
			P2:   cmd.P2,
			Data: chunk,
			Le:   -1,
		})
	}
	// Final chunk: original CLA, no chaining bit, includes Le.
	cmds = append(cmds, &Command{
		CLA:  cmd.CLA,
		INS:  cmd.INS,
		P1:   cmd.P1,
		P2:   cmd.P2,
		Data: data,
		Le:   cmd.Le,
	})
	return cmds, nil
}

// NewSelect builds a SELECT command for the given AID.
func NewSelect(aid []byte) *Command {
	return &Command{
		CLA:  0x00,
		INS:  0xA4,
		P1:   0x04, // Select by DF name
		P2:   0x00, // First or only occurrence
		Data: aid,
		Le:   0, // Return FCI
	}
}

// NewGetData builds a GET DATA command for a given tag.
func NewGetData(cla byte, tag uint16) *Command {
	return &Command{
		CLA:  cla,
		INS:  0xCA,
		P1:   byte(tag >> 8),
		P2:   byte(tag),
		Data: nil,
		Le:   0, // Return everything
	}
}

// NewGetResponse builds a GET RESPONSE command to retrieve remaining data.
func NewGetResponse(remaining byte) *Command {
	return &Command{
		CLA:  0x00,
		INS:  0xC0,
		P1:   0x00,
		P2:   0x00,
		Data: nil,
		Le:   int(remaining),
	}
}

// Transmitter is the minimum interface needed to drive a single
// command/response exchange. Any session, channel, or raw transport
// that exposes Transmit(ctx, *Command) -> *Response satisfies it.
//
// Lives here, in apdu, so transport-shaped helpers (response
// chaining, retry-on-6CXX) can be written once and re-used by every
// caller without forcing import cycles between higher-level session
// packages.
type Transmitter interface {
	Transmit(ctx context.Context, cmd *Command) (*Response, error)
}

// MaxResponseChainSteps caps how many GET RESPONSE iterations
// TransmitWithChaining will issue before giving up. The bound exists
// to defend the host from a card (real or hostile) that returns
// SW=61xx forever. Real PIV applets never need more than a handful
// of steps even for the largest responses; 64 is comfortably above
// any plausible payload.
const MaxResponseChainSteps = 64

// TransmitWithChaining issues cmd via tx and transparently follows
// any GET RESPONSE chain the card emits with SW1 == 0x61. The
// returned response carries the full concatenated body and the final
// status word.
//
// This mirrors Yubico yubikit's ResponseChainingProcessor: SW=61xx
// is a "more data available" signal, not a terminal error. Callers
// that surface 61xx as failure see the symptom Ryan hit on retail
// YubiKey 5.7.4 PIV ATTEST: "ATTEST: SW=6100 (more data available)"
// where ykman's equivalent succeeded because its transport layer
// chains automatically.
//
// On any wire error or after MaxResponseChainSteps iterations, the
// helper returns an error rather than partial data presented as
// success.
func TransmitWithChaining(ctx context.Context, tx Transmitter, cmd *Command) (*Response, error) {
	resp, err := tx.Transmit(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if resp.SW1 != 0x61 {
		// Common case: no chaining needed. Avoid the buffer copy.
		return resp, nil
	}
	body := append([]byte(nil), resp.Data...)
	for steps := 0; resp.SW1 == 0x61; steps++ {
		if steps >= MaxResponseChainSteps {
			return nil, fmt.Errorf(
				"GET RESPONSE chain exceeded %d steps; aborting",
				MaxResponseChainSteps)
		}
		// SW2 is the card's hint for Le on the next GET RESPONSE.
		// 0x00 means "an unspecified amount, request the max" —
		// passed through unchanged because Le=0 already encodes
		// "ask for max" at the wire level.
		resp, err = tx.Transmit(ctx, NewGetResponse(resp.SW2))
		if err != nil {
			return nil, fmt.Errorf("GET RESPONSE step %d: %w", steps+1, err)
		}
		body = append(body, resp.Data...)
	}
	resp.Data = body
	return resp, nil
}

func swDescription(sw uint16) string {
	switch sw {
	case 0x9000:
		return "success"
	case 0x6982:
		return "security status not satisfied"
	case 0x6985:
		return "conditions of use not satisfied"
	case 0x6A80:
		return "incorrect parameters in data field"
	case 0x6A82:
		return "file or application not found"
	case 0x6A86:
		return "incorrect P1-P2"
	case 0x6A88:
		return "referenced data not found"
	case 0x6D00:
		return "instruction not supported"
	case 0x6E00:
		return "class not supported"
	default:
		if sw>>8 == 0x61 {
			return fmt.Sprintf("%d bytes remaining", sw&0xFF)
		}
		if sw>>8 == 0x6C {
			return fmt.Sprintf("wrong Le; correct Le=%d", sw&0xFF)
		}
		return "unknown status"
	}
}
