// Command cardrelay-client connects to a CardRelay gRPC server,
// opens a card session, and runs a small smoke test (SELECT the
// PIV applet, read FCI). Demonstrates that the client side of the
// transport package implements transport.Transport correctly: any
// scp-aware code that takes a transport can run against a remote
// card, not just a locally-attached one.
//
// Usage:
//
//	cardrelay-client [-target host:port] [-reader "YubiKey"]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	scpgrpc "github.com/PeculiarVentures/scp/transport/grpc"
)

func main() {
	target := flag.String("target", "localhost:7777",
		"CardRelay server address (host:port or unix:///path).")
	reader := flag.String("reader", "",
		"Reader substring hint. Empty = server default.")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := scpgrpc.Dial(ctx, scpgrpc.DialOptions{
		Target: *target,
		Reader: *reader,
	})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// SELECT PIV (AID A0 00 00 03 08 00 00 10 00 01 00).
	selectPIV := &apdu.Command{
		CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00,
		Data: []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00},
		Le:   -1,
	}
	resp, err := client.Transmit(ctx, selectPIV)
	if err != nil {
		log.Fatalf("SELECT PIV: %v", err)
	}
	if resp.SW1 != 0x90 || resp.SW2 != 0x00 {
		log.Fatalf("SELECT PIV: SW=%02X%02X (card refused)", resp.SW1, resp.SW2)
	}

	fmt.Printf("SELECT PIV ok, FCI %d bytes:\n%s\n",
		len(resp.Data), hexDump(resp.Data))
	fmt.Println("Round-trip through CardRelay succeeded.")
}

// hexDump renders bytes as space-separated hex, 16 per line.
func hexDump(b []byte) string {
	const perLine = 16
	out := ""
	for i := 0; i < len(b); i += perLine {
		end := i + perLine
		if end > len(b) {
			end = len(b)
		}
		for _, x := range b[i:end] {
			out += fmt.Sprintf("%02X ", x)
		}
		out += "\n"
	}
	return out
}
