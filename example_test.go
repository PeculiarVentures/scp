package scp_test

import (
	"context"
	"fmt"

	scp "github.com/PeculiarVentures/scp"
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/yubikey"
)

// ExampleSession_Transmit shows code written against the abstract
// scp.Session interface. Once the handshake completes, the same
// caller code works whether the session was opened with scp03.Open
// or scp11.Open — the protocol underneath is transparent.
//
// This is the right seam to write reusable infrastructure against:
// authorization layers, audit logging, command dispatchers, and
// integration tests typically take a scp.Session rather than a
// concrete *scp03.Session or *scp11.Session.
func ExampleSession_Transmit() {
	ctx := context.Background()

	// Either scp03.Open or scp11.Open returns something that
	// implements scp.Session; this example uses SCP03 against the
	// in-tree mock card to keep itself self-contained.
	card := scp03.NewMockCard(scp03.DefaultKeys)
	concrete, err := scp03.Open(ctx, card.Transport(), yubikey.FactorySCP03Config())
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer concrete.Close()

	var sess scp.Session = concrete

	// GET DATA tag 0x66 (Card Recognition Data) over the wrapped channel.
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xCA, P1: 0x00, P2: 0x66,
	})
	if err != nil {
		fmt.Println("transmit:", err)
		return
	}
	fmt.Printf("protocol=%s sw=%04X first_byte=%02X\n",
		sess.Protocol(), resp.StatusWord(), resp.Data[0])
	// Output: protocol=SCP03 sw=9000 first_byte=66
}
