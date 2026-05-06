package mockcard

import (
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// SCP03Card is a GlobalPlatform card mock that speaks SCP03
// (handshake + secure messaging) AND handles the GP card-content
// management command set (INSTALL, LOAD, DELETE, GET STATUS, SET
// STATUS). It composes scp03.MockCard's protocol layer with
// GPState's command handlers via scp03.MockCard.PlainHandler.
//
// This mock is intended for end-to-end testing of 'scpctl gp
// install' / 'gp delete' flows that need both an authenticated
// SCP03 session and a registry that round-trips applet
// installation. Tests that need only the SCP03 protocol layer
// should use scp03.MockCard directly; tests that need only the
// GP registry without authentication should use mockcard.Card
// (SCP11) or extend GPState with a no-op auth wrapper.
//
// Fault injection: tests register *Fault entries via AddFault to
// exercise card-side error paths (mid-LOAD failure, INSTALL
// rejection, etc.). Faults are evaluated before the GP dispatch
// in registration order; the first match short-circuits.
//
// Lifetime / mutation:
//   - Tests typically configure SCP03 keys via NewSCP03Card,
//     then optionally seed RegistryISD / RegistryApps /
//     RegistryLoadFiles before issuing APDUs.
//   - The GP registry mutates as a side effect of INSTALL/DELETE
//     APDUs; tests can inspect the embedded GPState's slices to
//     verify the post-test state.
type SCP03Card struct {
	// Embedded protocol mock provides Transport(), session
	// management, and SCP03 secure messaging.
	*scp03.MockCard

	// Embedded GP state provides the registry slices and the
	// INSTALL/LOAD/DELETE/GET STATUS handlers. Promoted fields
	// (RegistryISD, etc.) are accessed directly by tests.
	*GPState

	// faults registered by AddFault, evaluated in order.
	faults []*Fault
}

// NewSCP03Card creates a combined SCP03+GP mock configured with
// the given static SCP03 keys. The registries start empty; tests
// seed them via the promoted fields if a particular GET STATUS
// outcome is required.
func NewSCP03Card(keys scp03.StaticKeys) *SCP03Card {
	mc := scp03.NewMockCard(keys)
	gp := NewGPState()

	c := &SCP03Card{
		MockCard: mc,
		GPState:  gp,
	}

	// Plug GP dispatch into the SCP03 mock's plain-command path.
	// The hook is invoked after SM unwrap; faults are checked
	// before GP dispatch so a fault on INS=0xE6/P1=0x02 fires
	// without touching loadCtx.
	mc.PlainHandler = func(cmd *apdu.Command) (*apdu.Response, bool) {
		if resp, ok := c.checkFaults(cmd); ok {
			return resp, true
		}
		return gp.HandleGPCommand(cmd)
	}

	return c
}

// AddFault registers a fault to fire on a matching APDU. Faults
// are checked in registration order; the first match short-
// circuits dispatch. Returns the card so tests can chain calls.
func (c *SCP03Card) AddFault(f *Fault) *SCP03Card {
	c.faults = append(c.faults, f)
	return c
}

// checkFaults walks the fault list in registration order. The
// first match returns its response and, if Once, the fault is
// flagged fired so subsequent calls fall through to default
// dispatch.
func (c *SCP03Card) checkFaults(cmd *apdu.Command) (*apdu.Response, bool) {
	for _, f := range c.faults {
		if f.fired {
			continue
		}
		if f.Match != nil && f.Match(cmd) {
			if f.Once {
				f.fired = true
			}
			return f.Response, true
		}
	}
	return nil, false
}

// Transport returns a transport.Transport backed by this mock.
// Delegates to the embedded scp03.MockCard's transport so SCP03
// handshake and SM proceed normally.
func (c *SCP03Card) Transport() transport.Transport {
	return c.MockCard.Transport()
}
