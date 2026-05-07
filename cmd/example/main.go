// Command example demonstrates both SCP03 and SCP11b sessions using
// mock cards, showing the unified Session interface.
//
// Run with: go run ./cmd/example
package main

import (
	"context"
	"log"

	scp "github.com/PeculiarVentures/scp"
	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/yubikey"
)

func main() {
	log.SetFlags(0)
	ctx := context.Background()

	// --- SCP03: Symmetric key protocol ---
	log.Println("=== SCP03 (symmetric keys) ===")
	scp03Card := scp03.NewMockCard(scp03.DefaultKeys)
	scp03Sess, err := scp03.Open(ctx, scp03Card.Transport(), &scp03.Config{
		Keys: scp03.DefaultKeys,
	})
	if err != nil {
		log.Fatalf("SCP03 Open: %v", err)
	}
	runDemo(ctx, scp03Sess)

	// --- SCP11b: Asymmetric key protocol ---
	log.Println("\n=== SCP11b (ECDH key agreement) ===")
	scp11Card, err := mockcard.New()
	if err != nil {
		log.Fatalf("create SCP11 card: %v", err)
	}
	cfg := yubikey.SCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true // mock card self-signed key
	scp11Sess, err := scp11.Open(ctx, scp11Card.Transport(), cfg)
	if err != nil {
		log.Fatalf("SCP11 Open: %v", err)
	}
	runDemo(ctx, scp11Sess)
}

// runDemo sends commands through any scp.Session — works identically
// regardless of whether the session uses SCP03 or SCP11.
func runDemo(ctx context.Context, sess scp.Session) {
	defer sess.Close()

	log.Printf("Protocol: %s", sess.Protocol())
	// Note: this example does not log session keys. Live session
	// material (S-ENC, S-MAC, etc.) lets anyone who sees the bytes
	// decrypt the entire session and forge commands. Examples
	// become production code; do not log them. The session's
	// derived material is accessible only via the deliberately
	// awkward InsecureExportSessionKeysForTestOnly() method.

	// Echo command — data goes through encrypt + MAC + verify + decrypt.
	payload := []byte("Hello, secure channel!")
	resp, err := sess.Transmit(ctx, &apdu.Command{
		CLA: 0x80, INS: 0xFD, P1: 0x00, P2: 0x00,
		Data: payload, Le: -1,
	})
	if err != nil {
		log.Fatalf("Transmit: %v", err)
	}
	log.Printf("Echo:     %q → %q (SW=%04X)", payload, resp.Data, resp.StatusWord())
}
