package scp11_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/trust"
	"github.com/PeculiarVentures/scp/yubikey"
)

// ExampleOpen_scp11b demonstrates opening an SCP11b session — the
// card-to-host authenticated variant — and transmitting one APDU
// over the resulting encrypted channel. SCP11b authenticates the
// card to the host but not the host to the card; OCE-gated writes
// (key rotation, full reset) are refused under SCP11b. See
// ExampleOpen_scp11a for the mutual-authentication variant required
// for those operations.
//
// In production, CardTrustPolicy.Roots would carry the pinned issuer
// of the card's certificate (a Yubico Secure Domain root, a vendor
// PKI root, etc.). This example sets InsecureSkipCardAuthentication
// purely so the example can run end-to-end against the in-tree mock
// card; never set this flag in production code.
func ExampleOpen_scp11b() {
	ctx := context.Background()
	card, err := mockcard.New()
	if err != nil {
		fmt.Println("new mock card:", err)
		return
	}

	cfg := yubikey.SCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true // example-only; do not use in production

	sess, err := scp11.Open(ctx, card.Transport(), cfg)
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
	fmt.Printf("protocol=%s sw=%04X\n", sess.Protocol(), resp.StatusWord())
	// Output: protocol=SCP11b sw=9000
}

// ExampleOpen_scp11a sketches the configuration required for SCP11a,
// the mutual-authentication variant. SCP11a requires the off-card
// entity (OCE) to present a certificate chain whose root the card
// trusts (typically installed during a one-time bootstrap; see
// scpctl smoke bootstrap-oce). After a successful handshake,
// Session.OCEAuthenticated() reports true and the session can drive
// OCE-gated operations through securitydomain.OpenWithSession.
//
// This example is illustrative — it shows the field shape of a
// production-shaped Config. A runnable end-to-end SCP11a example
// would also need to provision a card with a matching OCE root
// out of band, which would dilute the API-shape point. Production
// code loads OCEPrivateKey and OCECertificates from PEM/PKCS#8
// files (or a key-management agent) and CardTrustPolicy.Roots from
// a pinned issuer bundle.
func ExampleOpen_scp11a() {
	// In production, load these from disk or a key-management agent.
	var ocePriv *ecdsa.PrivateKey    // PEM-decoded P-256 private key
	var oceChain []*x509.Certificate // OCE cert chain, leaf-LAST
	var trustRoots *x509.CertPool    // pinned issuer of the card's SCP11 cert

	cfg := &scp11.Config{
		Variant:         scp11.SCP11a,
		OCEPrivateKey:   ocePriv,
		OCECertificates: oceChain,
		OCEKeyReference: scp11.KeyRef{KID: 0x10, KVN: 0x03},
		CardTrustPolicy: &trust.Policy{Roots: trustRoots},
	}
	_ = cfg

	// Real code:
	//   sess, err := scp11.Open(ctx, transport, cfg)
	//   ...
	//   sd, err := securitydomain.OpenWithSession(sess, transport, sess.SessionDEK())
	//
	// OCEAuthenticated() is the gate the securitydomain package checks
	// before allowing OCE-gated operations like PutSCP03Key.
}
