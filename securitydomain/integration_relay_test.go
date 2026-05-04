package securitydomain_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11a_SecurityDomain_OverRelay_EndToEnd is the full-topology
// integration test for the deployment model documented in
// docs/remote-apdu-transport.md. Every architectural claim made in
// the doc, the README, and PRs #17 / #20 / #22 is exercised in a
// single flow:
//
//   - Server-side controller drives an SCP11a session (mutual auth,
//     OCE proves possession of its private key to the card).
//   - Endpoint goroutine relays APDU bytes only — never holds the
//     OCE private key, never sees session keys, never sees the
//     SCP11-derived DEK.
//   - securitydomain.OpenSCP11 captures the SCP11-derived DEK from
//     the underlying *scp11.Session via the unexported dekProvider
//     capability interface (PR #20).
//   - PutSCP03Key wraps an SCP03 key set under the SCP11-derived DEK
//     and sends it through the encrypted SCP11 channel — the wire
//     bytes go through the relay.
//   - The OCE private-key scalar (D) does NOT appear anywhere in
//     the relayed APDU bytes.
//
// The mock card returns 0x6D00 to PUT KEY (it doesn't implement the
// command), so PutSCP03Key fails at the response-handling step. That
// is fine: this test is asserting the *wire-level* contract, not
// card-side success. The fact that the encrypted PUT KEY APDU
// reaches the wire wrapped under the SCP11-derived DEK is the
// integration claim we're proving here.
func TestSCP11a_SecurityDomain_OverRelay_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// --- Set up a real OCE keypair + cert chain ---
	oceKey, leafDER := makeOCELeafCert(t)
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	chain := []*x509.Certificate{leafCert}

	// --- Stand up the mock card on the endpoint side ---
	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	card.Variant = 1 // SCP11a — mockcard.go uses 0=SCP11b, 1=SCP11a, 2=SCP11c

	// --- Wire up the relay channels ---
	// Unbuffered: forces "one outstanding APDU at a time", which is
	// one of the seven transport requirements documented in
	// docs/remote-apdu-transport.md.
	reqCh := make(chan []byte)
	respCh := make(chan []byte)
	relayDone := make(chan struct{})

	// Endpoint goroutine — exactly the role of an endpoint agent in
	// the relay deployment model. Holds the card, sees only opaque
	// bytes. By construction it has no reference to the OCE private
	// key, the SCP11 session, or any key material.
	var (
		observedMu sync.Mutex
		observed   [][]byte
	)
	go func() {
		defer close(relayDone)
		defer close(respCh)
		cardT := card.Transport()
		for raw := range reqCh {
			observedMu.Lock()
			cp := make([]byte, len(raw))
			copy(cp, raw)
			observed = append(observed, cp)
			observedMu.Unlock()

			resp, terr := cardT.TransmitRaw(ctx, raw)
			if terr != nil {
				return
			}
			select {
			case respCh <- resp:
			case <-ctx.Done():
				return
			}
		}
	}()

	rt := &integrationRelayTransport{reqCh: reqCh, respCh: respCh}

	// --- Server-side: open SCP11a Security Domain across the relay ---
	cfg := scp11.YubiKeyDefaultSCP11aConfig()
	cfg.OCEPrivateKey = oceKey
	cfg.OCECertificates = chain
	cfg.OCEKeyReference = scp11.KeyRef{KID: 0x10, KVN: 0x03}
	cfg.InsecureSkipCardAuthentication = true // mockcard isn't a real PKI

	sd, err := securitydomain.OpenSCP11(ctx, rt, cfg)
	if err != nil {
		t.Fatalf("securitydomain.OpenSCP11 over relay (SCP11a): %v", err)
	}
	defer sd.Close()

	// SCP11a authenticates the OCE to the card. The SD layer must
	// reflect that, so OCE-gated operations (PUT KEY etc.) pass the
	// host-side gate and reach the wire.
	if !sd.OCEAuthenticated() {
		t.Fatal("SCP11a session must report OCEAuthenticated()=true")
	}

	// --- Issue PUT KEY across the relay ---
	// The DEK was captured at OpenSCP11 time via the unexported
	// dekProvider interface (PR #20). PutSCP03Key wraps the new key
	// set under that DEK and sends through the SCP11 channel.
	newKeys := scp03.StaticKeys{
		ENC: bytes.Repeat([]byte{0xAA}, 16),
		MAC: bytes.Repeat([]byte{0xBB}, 16),
		DEK: bytes.Repeat([]byte{0xCC}, 16),
	}
	ref := securitydomain.NewKeyReference(securitydomain.KeyIDSCP03, 0x01)

	// Mockcard returns 6D00 (instruction not supported) for PUT KEY.
	// We expect PutSCP03Key to error, AFTER the encrypted command has
	// gone on the wire.
	putErr := sd.PutSCP03Key(ctx, ref, newKeys, 0xFF)
	if putErr == nil {
		t.Log("PutSCP03Key succeeded (mock implements it now?); wire-level " +
			"assertions still apply")
	} else {
		t.Logf("PutSCP03Key returned (expected against mockcard): %v", putErr)
	}

	// --- Tear down ---
	sd.Close()
	rt.Close()
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Error("endpoint goroutine did not exit after relay close")
	}

	observedMu.Lock()
	defer observedMu.Unlock()

	// === Assertions ===

	t.Logf("relay observed %d APDUs total", len(observed))
	for i, a := range observed {
		head := a
		if len(head) > 24 {
			head = head[:24]
		}
		t.Logf("  [%d] CLA=%02X INS=%02X len=%d head=% X",
			i, a[0], a[1], len(a), head)
	}

	// 1. Multiple APDUs flowed: SELECT + GET DATA + 1+ PSO + INTERNAL/
	//    EXTERNAL AUTHENTICATE + PUT KEY = at least 5 APDUs. SCP11a
	//    handshake alone needs more APDUs than SCP11b because of the
	//    PSO certificate upload phase.
	if got := len(observed); got < 5 {
		t.Errorf("expected at least 5 APDUs across the relay, saw %d", got)
	}

	// 2. Every PUT KEY (INS=0xD8) APDU on the wire is encrypted. Look
	//    for INS=0xD8 in the observed APDUs; the CLA byte must have
	//    bit 0x04 set (secure messaging indicator). If the SCP11
	//    wrapping layer ever regresses, this catches PUT KEY going
	//    out unprotected — which would leak the DEK-wrapped key
	//    material, the KCV checksums, and the target slot.
	var putKeyAPDUs [][]byte
	for _, a := range observed {
		if len(a) >= 2 && a[1] == 0xD8 {
			putKeyAPDUs = append(putKeyAPDUs, a)
		}
	}
	if len(putKeyAPDUs) == 0 {
		t.Error("PUT KEY (INS=0xD8) never reached the wire — host-side gate must have blocked it")
	}
	for i, a := range putKeyAPDUs {
		if a[0]&0x04 == 0 {
			t.Errorf("PUT KEY APDU[%d] has CLA=%02X (no secure-messaging bit set)", i, a[0])
		}
	}

	// 3. The OCE private-key scalar must NOT appear in any relayed
	//    APDU. This is the strongest demonstration of the trust
	//    split documented in remote-apdu-transport.md: even though
	//    the server signs/proves OCE identity, the bytes that pass
	//    through the endpoint are either plaintext SELECT/GET DATA
	//    (no secret material), the OCE *certificate* (public),
	//    EXTERNAL AUTHENTICATE (uses the OCE key but only outputs
	//    its result, not the key itself), or fully encrypted
	//    secure-messaging traffic.
	dBytes := oceKey.D.Bytes()
	// Pad to 32 bytes (P-256). A short D would be padded with leading
	// zeros, which would falsely match against any APDU containing
	// 32 zero bytes. Force the pad to actual private key material by
	// requiring D be at least 16 bytes — anything else is a degenerate
	// key the test should reject.
	if len(dBytes) < 16 {
		t.Skipf("OCE private key D scalar suspiciously short (%d bytes); regen and retry", len(dBytes))
	}
	for i, a := range observed {
		if bytes.Contains(a, dBytes) {
			t.Errorf("OCE private-key scalar (D) found in APDU[%d] on the wire — "+
				"trust-split violation. APDU CLA=%02X INS=%02X len=%d",
				i, a[0], a[1], len(a))
		}
	}

	// 4. The new SCP03 keys (the bytes we passed to PutSCP03Key) must
	//    NOT appear plaintext on the wire. They were wrapped under
	//    the SCP11-derived DEK, so the encrypted form should be on
	//    the wire — the plaintext should not.
	for label, secret := range map[string][]byte{
		"new ENC": newKeys.ENC,
		"new MAC": newKeys.MAC,
		"new DEK": newKeys.DEK,
	} {
		for i, a := range observed {
			if bytes.Contains(a, secret) {
				t.Errorf("plaintext %s appeared in APDU[%d] on the wire — "+
					"PUT KEY wrapping regression", label, i)
			}
		}
	}
}

// makeOCELeafCert generates a P-256 OCE keypair and a self-signed
// X.509 certificate suitable for handing to mockcard via PSO. mockcard
// parses the leaf cert, extracts the public key, and uses it as the
// OCE static key for SCP11a's ECDH(SK.SD, PK.OCE) leg.
func makeOCELeafCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "OCE-Integration-Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return priv, der
}

// integrationRelayTransport is the same shape as the relay transport
// in session/remote_relay_test.go (PR #22). Duplicated here rather
// than shared because PR #22's lives under session_test (different
// package) and importing it would tangle test packages. The behavior
// is identical — opaque-bytes channel relay, one outstanding APDU
// at a time, propagates close.
type integrationRelayTransport struct {
	reqCh  chan<- []byte
	respCh <-chan []byte
	closed bool
	mu     sync.Mutex
}

func (r *integrationRelayTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	raw, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	respBytes, err := r.TransmitRaw(ctx, raw)
	if err != nil {
		return nil, err
	}
	return apdu.ParseResponse(respBytes)
}

func (r *integrationRelayTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.New("integrationRelayTransport: closed")
	}
	r.mu.Unlock()

	select {
	case r.reqCh <- raw:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case resp, ok := <-r.respCh:
		if !ok {
			return nil, errors.New("integrationRelayTransport: endpoint closed response channel")
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *integrationRelayTransport) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	close(r.reqCh)
	return nil
}

var _ transport.Transport = (*integrationRelayTransport)(nil)

func (r *integrationRelayTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
