// Example: open an SCP11b session against the first connected
// PC/SC reader (typically a YubiKey 5.7+) and send a SELECT.
//
// Build:
//
//	cd transport/pcsc/example
//	go build -o scp-pcsc-demo
//
// Run with no card to list readers, with a card to handshake.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport/pcsc"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "list" {
		readers, err := pcsc.ListReaders()
		if err != nil {
			log.Fatalf("list readers: %v", err)
		}
		if len(readers) == 0 {
			fmt.Println("no readers connected")
			return
		}
		for _, r := range readers {
			fmt.Println(r)
		}
		return
	}

	tr, err := pcsc.OpenFirstReader()
	if err != nil {
		switch {
		case errors.Is(err, pcsc.ErrNoReaders):
			log.Fatalf("plug in a reader and try again")
		case errors.Is(err, pcsc.ErrNoCard):
			log.Fatalf("insert a card into the reader and try again")
		default:
			log.Fatalf("open reader: %v", err)
		}
	}
	defer tr.Close()

	fmt.Printf("connected to: %s\n", tr.ReaderName())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// SCP11b against the Issuer Security Domain.
	// CAUTION: InsecureSkipCardAuthentication is for the demo only —
	// production code MUST configure CardTrustPolicy or
	// CardTrustAnchors. See "Certificate Trust Validation" in the
	// main README.
	cfg := scp11.YubiKeyDefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true

	sess, err := scp11.Open(ctx, tr, cfg)
	if err != nil {
		log.Fatalf("scp11.Open: %v", err)
	}
	defer sess.Close()

	fmt.Printf("handshake complete — protocol: %s\n", sess.Protocol())
}
