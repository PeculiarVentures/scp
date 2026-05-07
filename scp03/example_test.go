package scp03_test

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/yubikey"
)

// Example demonstrates opening an SCP03 session against a YubiKey
// in factory state and transmitting a single APDU through the
// resulting authenticated, encrypted channel.
//
// yubikey.FactorySCP03Config holds publicly-known default keys (KVN 0xFF,
// AES-128 with the well-known 40 41 42 ... 4F key material). Real
// deployments rotate to caller-controlled keys before going to
// production; see scp03.Config and securitydomain.Session.PutSCP03Key
// for the rotated-key path.
//
// In production, transport would be a transport/pcsc Transport
// against a real reader. This example uses scp03.NewMockCard so the
// example runs end-to-end without hardware.
func Example() {
	ctx := context.Background()
	card := scp03.NewMockCard(scp03.DefaultKeys)

	sess, err := scp03.Open(ctx, card.Transport(), yubikey.FactorySCP03Config())
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer sess.Close()

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
