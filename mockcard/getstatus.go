package mockcard

import (
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// MockRegistryEntry is a synthetic GP registry row returned in GET
// STATUS responses. It encodes to a 0xE3 template per GP §11.4.2.2.
//
// Fields beyond AID are optional; leave them at the zero value to
// omit the corresponding TLV from the response. Privileges encode as
// a 4-byte tag-0x9F70 value (lifecycle byte concatenated with the
// 3-byte privilege mask), the modern GP encoding.
type MockRegistryEntry struct {
	AID             []byte  // mandatory, encoded under tag 0x4F
	Lifecycle       byte    // raw GP lifecycle byte
	Privileges      [3]byte // GP Table 6-1 privilege mask
	AssociatedSDAID []byte  // optional, tag 0xCC
	Version         []byte  // optional, tag 0xCE (Load Files)
	Modules         [][]byte
}

// encode returns the 0xE3 template for this entry. The
// includeModules flag controls whether 0x84 module entries are
// included — they are only emitted under the
// LoadFiles+Modules scope (P1=0x10).
func (e *MockRegistryEntry) encode(includeModules bool) *tlv.Node {
	var children []*tlv.Node
	children = append(children, tlv.Build(0x4F, append([]byte(nil), e.AID...)))

	// Modern combined encoding: lifecycle byte + 3-byte privilege mask.
	combined := append([]byte{e.Lifecycle}, e.Privileges[0], e.Privileges[1], e.Privileges[2])
	children = append(children, tlv.Build(0x9F70, combined))

	if len(e.AssociatedSDAID) > 0 {
		children = append(children, tlv.Build(0xCC, append([]byte(nil), e.AssociatedSDAID...)))
	}
	if len(e.Version) > 0 {
		children = append(children, tlv.Build(0xCE, append([]byte(nil), e.Version...)))
	}
	if includeModules {
		for _, m := range e.Modules {
			children = append(children, tlv.Build(0x84, append([]byte(nil), m...)))
		}
	}
	return tlv.BuildConstructed(0xE3, children...)
}

// GET STATUS scope selectors (P1 byte) per GP §11.4.2.
const (
	statusScopeISD                 byte = 0x80
	statusScopeApplications        byte = 0x40
	statusScopeLoadFiles           byte = 0x20
	statusScopeLoadFilesAndModules byte = 0x10
)

// doGetStatus is the GP §11.4.2 GET STATUS handler. P2 must be 0x02
// (TLV format, first call) — the mock does not signal multi-segment
// responses, so continuation (P2=0x03) is not needed and is rejected.
//
// P1 selects the registry slice to return:
//
//	0x80  RegistryISD
//	0x40  RegistryApps (also returns SSDs in real GP; the mock
//	      doesn't distinguish — callers can put SSDs into the
//	      Apps slice with the SecurityDomain privilege bit set)
//	0x20  RegistryLoadFiles, modules omitted
//	0x10  RegistryLoadFiles, modules included
//
// Empty slices return SW=6A88 (referenced data not found), matching
// the real-card behavior the production parser relies on.
func (c *Card) doGetStatus(cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.P2 != 0x02 {
		return mkSW(0x6A86), nil // incorrect P1/P2
	}

	var (
		entries        []MockRegistryEntry
		includeModules bool
	)
	switch cmd.P1 {
	case statusScopeISD:
		entries = c.RegistryISD
	case statusScopeApplications:
		entries = c.RegistryApps
	case statusScopeLoadFiles:
		entries = c.RegistryLoadFiles
	case statusScopeLoadFilesAndModules:
		entries = c.RegistryLoadFiles
		includeModules = true
	default:
		return mkSW(0x6A86), nil
	}

	if len(entries) == 0 {
		return mkSW(0x6A88), nil // referenced data not found
	}

	var nodes []*tlv.Node
	for i := range entries {
		nodes = append(nodes, entries[i].encode(includeModules))
	}
	var body []byte
	for _, n := range nodes {
		body = append(body, n.Encode()...)
	}
	return &apdu.Response{Data: body, SW1: 0x90, SW2: 0x00}, nil
}
