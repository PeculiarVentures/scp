package mockcard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/session"
	"github.com/PeculiarVentures/scp/tlv"
	"github.com/PeculiarVentures/scp/transport"
)

// recordingTransport wraps an underlying transport and captures the
// raw bytes of every command APDU sent through it. Used to verify
// wire-format properties of session.Open() and Transmit().
type recordingTransport struct {
	inner transport.Transport
	sent  [][]byte
}

func (r *recordingTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	encoded, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	r.sent = append(r.sent, encoded)
	return r.inner.Transmit(ctx, cmd)
}

func (r *recordingTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	r.sent = append(r.sent, raw)
	return r.inner.TransmitRaw(ctx, raw)
}

func (r *recordingTransport) Close() error { return r.inner.Close() }

// extractOCEEphemeralPubkey finds an AUTHENTICATE APDU (INS=0x88
// INTERNAL_AUTHENTICATE or 0x82 MUTUAL_AUTHENTICATE) in a list of
// recorded CAPDUs and returns the OCE ephemeral public key bytes
// from its 5F49 TLV. SCP11 AUTHENTICATE embeds the host's ephemeral
// pubkey at this exact tag per GP §7.6.2.3, so capturing this value
// lets a test verify the host actually put the expected ephemeral
// on the wire.
func extractOCEEphemeralPubkey(sent [][]byte) []byte {
	for _, capdu := range sent {
		if len(capdu) < 5 {
			continue
		}
		ins := capdu[1]
		if ins != 0x82 && ins != 0x88 {
			continue
		}
		lc := int(capdu[4])
		if lc == 0 || len(capdu) < 5+lc {
			continue
		}
		data := capdu[5 : 5+lc]
		nodes, err := tlv.Decode(data)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			if n.Tag == 0x5F49 {
				return n.Value
			}
		}
	}
	return nil
}

// TestSCP11_InsecureTestOnlyEphemeralKey_ProducesExpectedOCEPubkey
// confirms the InsecureTestOnlyEphemeralKey seam actually puts the
// expected OCE ephemeral public key on the wire — not just that the
// session opens. Earlier this test only sanity-checked that the fixed
// scalar derives Samsung's published public point in isolation, which
// proved nothing about whether session.Open() routed the override
// through to the AUTHENTICATE APDU.
//
// This version drives session.Open through a recording transport,
// finds the AUTHENTICATE APDU, parses its 5F49 (EPK.OCE) TLV, and
// asserts byte-exact equality with Samsung's published EPK_OCE_ECKA_P256
// uncompressed point.
//
// Vector source: Samsung OpenSCP-Java
// src/test/java/com/samsung/openscp/testdata/Scp11TestData.java
func TestSCP11_InsecureTestOnlyEphemeralKey_ProducesExpectedOCEPubkey(t *testing.T) {
	scalar, _ := hex.DecodeString("B69D2D4A2544B5938ED3C4F6319810837E4DBBEFF115BD9955607E8CDBBBACE5")
	fixedKey, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("parse ephemeral key: %v", err)
	}

	wantEPK, _ := hex.DecodeString(
		"0470B0BD7863E90E32DA5401188354D1F41999442FDFDCBA7472B7F1E5DBBF8A32" +
			"F92D9D4F9D55C60D57D39BD6D7973306CEA55F7A86884096651A9CCAC8239C92")

	card, err := New()
	if err != nil {
		t.Fatalf("New mock card: %v", err)
	}
	rec := &recordingTransport{inner: card.Transport()}

	sess, err := session.Open(context.Background(), rec, &session.Config{
		Variant:                        session.SCP11b,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
		InsecureTestOnlyEphemeralKey:   fixedKey,
	})
	if err != nil {
		t.Fatalf("session.Open: %v", err)
	}
	defer sess.Close()

	gotEPK := extractOCEEphemeralPubkey(rec.sent)
	if gotEPK == nil {
		t.Fatal("could not find 5F49 OCE ephemeral pubkey in any recorded APDU")
	}
	if !bytes.Equal(gotEPK, wantEPK) {
		t.Errorf("OCE ephemeral pubkey on wire does not match Samsung's vector:\n  got  %X\n  want %X",
			gotEPK, wantEPK)
	}
}

// TestSCP11_EphemeralKey_NilProducesFreshHostKey confirms that with
// InsecureTestOnlyEphemeralKey nil, two successive opens against fresh
// mock cards produce DIFFERENT host ephemeral public keys.
//
// Earlier the test compared SENC across two sessions, but the mock
// card's own ephemeral key is also random — so SENC could differ even
// if the host accidentally reused the same ephemeral. This version
// captures the host's 5F49 EPK.OCE bytes directly, isolating host-side
// randomness from card-side randomness.
func TestSCP11_EphemeralKey_NilProducesFreshHostKey(t *testing.T) {
	openAndExtract := func() []byte {
		t.Helper()
		card, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rec := &recordingTransport{inner: card.Transport()}
		sess, err := session.Open(context.Background(), rec, &session.Config{
			Variant:                        session.SCP11b,
			SelectAID:                      session.AIDSecurityDomain,
			KeyID:                          0x13,
			KeyVersion:                     0x01,
			InsecureSkipCardAuthentication: true,
			// InsecureTestOnlyEphemeralKey intentionally nil
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer sess.Close()
		return extractOCEEphemeralPubkey(rec.sent)
	}

	a := openAndExtract()
	b := openAndExtract()
	if a == nil || b == nil {
		t.Fatal("missing OCE ephemeral pubkey in recorded APDUs")
	}
	if bytes.Equal(a, b) {
		t.Errorf("two opens produced the SAME host ephemeral pubkey (randomness broken):\n  %X", a)
	}
}

// TestSCP11_InsecureTestOnlyEphemeralKey_RejectsNonP256 confirms the
// curve check at Open time: passing a non-P-256 ECDH key (e.g. P-384)
// must fail before any APDU is constructed, rather than producing a
// malformed EPK.OCE on the wire that the card would reject anyway.
func TestSCP11_InsecureTestOnlyEphemeralKey_RejectsNonP256(t *testing.T) {
	p384k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}

	card, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = session.Open(context.Background(), card.Transport(), &session.Config{
		Variant:                        session.SCP11b,
		SelectAID:                      session.AIDSecurityDomain,
		KeyID:                          0x13,
		KeyVersion:                     0x01,
		InsecureSkipCardAuthentication: true,
		InsecureTestOnlyEphemeralKey:   p384k,
	})
	if err == nil {
		t.Fatal("Open with P-384 ephemeral key should fail (P-256 only)")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should mention P-256 curve requirement, got: %v", err)
	}
}
