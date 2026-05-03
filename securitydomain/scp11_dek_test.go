package securitydomain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/session"
)

// TestOpenSCP11_PopulatesSessionDEK confirms that an SCP11
// Security Domain session captures the DEK derived during key
// agreement. Earlier this was discarded entirely, so PUT KEY
// operations failed with "SCP03 session required" against an
// SCP11-authenticated session — even though the SCP11 KDF
// produces a usable DEK.
//
// Test goes via SCP11a so the underlying session is OCE-
// authenticated and PUT KEY-class operations are not blocked by
// the host-side OCE-required gate.
func TestOpenSCP11_PopulatesSessionDEK(t *testing.T) {
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	card.Variant = 1 // SCP11a

	oceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate OCE key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test OCE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &oceKey.PublicKey, oceKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	oceCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	cfg := session.DefaultSCP11aConfig()
	cfg.InsecureSkipCardAuthentication = true
	cfg.OCEPrivateKey = oceKey
	cfg.OCECertificates = []*x509.Certificate{oceCert}
	cfg.OCEKeyReference = session.KeyRef{KID: 0x10, KVN: 0x03}

	sd, err := OpenSCP11(context.Background(), card.Transport(), cfg)
	if err != nil {
		t.Fatalf("OpenSCP11: %v", err)
	}
	defer sd.Close()

	if len(sd.dek) == 0 {
		t.Fatal("OpenSCP11 should populate s.dek from SessionDEK(); got empty")
	}
	switch len(sd.dek) {
	case 16, 24, 32:
		// ok
	default:
		t.Errorf("derived DEK has unexpected length %d", len(sd.dek))
	}
}
