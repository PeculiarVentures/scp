package securitydomain

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// kitStubTransport answers SELECT (any AID) with success and GET DATA
// tag 0x00E0 with a caller-supplied Key Information Template. Every
// other command returns SW=6A88 (reference data not found). Used by
// reset tests that need to control which keys the card reports as
// "installed" before the brute-force loop runs.
type kitStubTransport struct {
	kitDER []byte
	closed bool
}

func (s *kitStubTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch {
	case cmd.INS == 0xA4 && cmd.P1 == 0x04:
		// SELECT by AID. Accept any AID; we don't care about state
		// for this stub, only that OpenUnauthenticated's SELECT
		// succeeds.
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	case cmd.INS == 0xCA && cmd.P1 == 0x00 && cmd.P2 == 0xE0:
		// GET DATA, tag 0x00E0 — Key Information Template.
		return &apdu.Response{
			Data: append([]byte(nil), s.kitDER...),
			SW1:  0x90, SW2: 0x00,
		}, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil
}

func (s *kitStubTransport) Close() error {
	s.closed = true
	return nil
}

func (s *kitStubTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	// Reset path doesn't use TransmitRaw, but we have to satisfy
	// the interface. If a future test does need this, encode/decode
	// through the high-level Transmit above.
	return nil, nil
}

func (s *kitStubTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryLocalPCSC
}

// mockcardWithKIT returns a transport that serves the given key
// inventory via GET DATA E0. The first return is unused today but
// reserved so future tests that need richer mocking can extend
// without changing the signature.
//
// The KIT is encoded as E0 { C0 { KID, KVN, padding } ... } per the
// shape parseKeyInformation accepts (see commands.go). Each C0 entry
// gets two bytes of trailing padding so the parser's
// "len(child.Value) < 2" guard is satisfied with room to spare.
func mockcardWithKIT(t *testing.T, keys []KeyInfo) (struct{}, transport.Transport) {
	t.Helper()
	var children []tlv.Node
	for _, k := range keys {
		children = append(children, tlv.Node{
			Tag: tagKeyInfoTemplate,
			// Two header bytes (KID, KVN) plus a 2-byte AES-128
			// component descriptor — same shape as mockcard's
			// syntheticKeyInfo.
			Value: []byte{k.Reference.ID, k.Reference.Version, 0x88, 0x10},
		})
	}
	// Encode E0 { C0 ... C0 ... }.
	container := tlv.Node{Tag: tagKeyInformation}
	for i := range children {
		// tlv.Node.Encode includes header + value; we want to
		// concatenate the children's wire bytes inside E0.
		container.Value = append(container.Value, children[i].Encode()...)
	}
	return struct{}{}, &kitStubTransport{kitDER: container.Encode()}
}
