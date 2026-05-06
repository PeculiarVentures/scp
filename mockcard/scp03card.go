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
	// The hook is invoked after SM unwrap; if HandleGPCommand
	// recognizes the INS it returns the response and short-
	// circuits; otherwise the SCP03 mock's built-in switch
	// handles it (SELECT, GET DATA, PUT KEY, etc.).
	mc.PlainHandler = func(cmd *apdu.Command) (*apdu.Response, bool) {
		return gp.HandleGPCommand(cmd)
	}

	return c
}

// Transport returns a transport.Transport backed by this mock.
// Delegates to the embedded scp03.MockCard's transport so SCP03
// handshake and SM proceed normally.
func (c *SCP03Card) Transport() transport.Transport {
	return c.MockCard.Transport()
}
