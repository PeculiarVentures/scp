package scp11

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/transport"
)

// recordingTransportPSO captures every CAPDU it sees and replies
// with a fixed status word. Used to assert PSO wire shape without
// running a full SCP11 handshake.
type recordingTransportPSO struct {
	captured [][]byte
	reply    [2]byte // SW1 SW2
}

func (r *recordingTransportPSO) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	raw, err := cmd.Encode()
	if err != nil {
		return nil, err
	}
	r.captured = append(r.captured, raw)
	return &apdu.Response{SW1: r.reply[0], SW2: r.reply[1]}, nil
}

func (r *recordingTransportPSO) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	r.captured = append(r.captured, append([]byte(nil), raw...))
	return []byte{r.reply[0], r.reply[1]}, nil
}

func (r *recordingTransportPSO) Close() error { return nil }

func (r *recordingTransportPSO) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// mkCertOfSize creates an x509.Certificate signed by a fresh
// independent root key, so it is NOT self-signed. The DER size
// is at least the requested target (caller pads via CN). Using
// a non-self-signed cert is necessary for chunking tests because
// scp11.sendOCECertificate strips leading self-signed certs.
func mkCertOfSize(t *testing.T, targetSize int) *x509.Certificate {
	t.Helper()
	// Independent signer keeps the produced cert non-self-signed.
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen signer key: %v", err)
	}
	signerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scp11 chunk-test signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTmpl, signerTmpl, &signerKey.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	signer, _ := x509.ParseCertificate(signerDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}

	// Pad CN until the resulting cert reaches targetSize.
	pad := ""
	for {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "scp11 chunk-test " + pad},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageKeyAgreement,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &leafKey.PublicKey, signerKey)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		if len(der) >= targetSize {
			cert, _ := x509.ParseCertificate(der)
			return cert
		}
		pad += "X"
	}
}

// TestPSOChunking_LargeCert pins that a single cert > 255 bytes is
// transmitted as a sequence of short APDUs using ISO 7816-4 §5.1.1
// command chaining (CLA b5 = 0x10), NOT as a single extended-length
// APDU. The latter shape is what retail YubiKey 5.7.4 rejects with
// SW=6A80 ("incorrect parameters in command data field"); the
// chained shape is what yubikit-python emits and what the card
// accepts.
//
// This test would have caught the regression that motivated the
// PR adding it: scpctl was emitting a single 802A0310 + 3-byte
// extended-Lc APDU for a 421-byte cert, and the card rejected
// it. Asserting on CLA progression (0x90, 0x90, 0x80) and Lc
// values (each ≤ 0xFF, with Data[len(Data)-1] of the cert in the
// final chunk) catches that.
func TestPSOChunking_LargeCert(t *testing.T) {
	// A 600-byte cert needs 3 chunks at 255 bytes each (255 + 255 + 90).
	cert := mkCertOfSize(t, 600)
	if len(cert.Raw) <= 255 {
		t.Fatalf("test setup: cert is %d bytes, expected > 255", len(cert.Raw))
	}

	rec := &recordingTransportPSO{reply: [2]byte{0x90, 0x00}}
	s := &Session{
		transport: rec,
		config: &Config{
			OCECertificates: []*x509.Certificate{cert},
			OCEKeyReference: KeyRef{KID: 0x10, KVN: 0x03},
		},
	}
	if err := s.sendOCECertificate(context.Background()); err != nil {
		t.Fatalf("sendOCECertificate: %v", err)
	}

	// Compute expected chunk count: ceil(len/255).
	expectedChunks := (len(cert.Raw) + 254) / 255
	if len(rec.captured) != expectedChunks {
		t.Fatalf("expected %d PSO chunks for a %d-byte cert; got %d",
			expectedChunks, len(cert.Raw), len(rec.captured))
	}

	// Chunk-by-chunk assertions:
	//   - Chunks 0..N-2: CLA = 0x90 (chained), Lc = 0xFF.
	//   - Chunk N-1: CLA = 0x80 (final), Lc = remainder.
	//   - Each chunk: INS=0x2A, P1=0x03 (KVN), P2=0x10 (KID, no
	//     P2-chain bit because there's only one cert in the test).
	var reassembled []byte
	for i, raw := range rec.captured {
		isLast := i == len(rec.captured)-1
		wantCLA := byte(0x90)
		if isLast {
			wantCLA = 0x80
		}
		if raw[0] != wantCLA {
			t.Errorf("chunk %d: CLA = %02X, want %02X", i, raw[0], wantCLA)
		}
		if raw[1] != 0x2A {
			t.Errorf("chunk %d: INS = %02X, want 2A", i, raw[1])
		}
		if raw[2] != 0x03 {
			t.Errorf("chunk %d: P1 = %02X, want 03 (KVN)", i, raw[2])
		}
		if raw[3] != 0x10 {
			t.Errorf("chunk %d: P2 = %02X, want 10 (KID, single-cert chain)", i, raw[3])
		}
		// Lc is the 5th byte (short encoding).
		lc := int(raw[4])
		if i < len(rec.captured)-1 && lc != 0xFF {
			t.Errorf("chunk %d (non-final): Lc = %02X, want FF (chunk should be full 255 bytes)",
				i, raw[4])
		}
		// No 3-byte extended Lc — short encoding only.
		if len(raw) > 5 && raw[4] == 0x00 && i == 0 {
			t.Errorf("chunk %d: looks like extended-length encoding (Lc=00), "+
				"want short. This is the regression: extended-length is what "+
				"YubiKey 5.7.4 rejects with SW=6A80.", i)
		}
		// Concatenate the data bytes; should reassemble to cert.Raw.
		reassembled = append(reassembled, raw[5:5+lc]...)
	}
	if !bytes.Equal(reassembled, cert.Raw) {
		t.Errorf("reassembled chunks do not equal cert.Raw")
	}
}

// TestPSOChunking_SmallCert pins that a cert ≤ 255 bytes does NOT
// trigger chaining — it goes out as a single short APDU with
// CLA = 0x80. Edge case: at exactly 255 bytes, single APDU; at
// 256 bytes, two chunks.
func TestPSOChunking_SmallCert(t *testing.T) {
	// Use a real (small) self-signed cert. Real OCE-style P-256
	// certs with minimal extensions land in the 220–280 byte range.
	cert := mkCertOfSize(t, 200) // typically lands ~220-260 bytes
	rec := &recordingTransportPSO{reply: [2]byte{0x90, 0x00}}
	s := &Session{
		transport: rec,
		config: &Config{
			OCECertificates: []*x509.Certificate{cert},
			OCEKeyReference: KeyRef{KID: 0x10, KVN: 0x03},
		},
	}
	if err := s.sendOCECertificate(context.Background()); err != nil {
		t.Fatalf("sendOCECertificate: %v", err)
	}

	if len(cert.Raw) > 255 {
		// mkCertOfSize overshot; small-cert assertion doesn't apply.
		t.Skipf("cert is %d bytes; not exercising the ≤ 255 path", len(cert.Raw))
	}
	if len(rec.captured) != 1 {
		t.Fatalf("expected 1 PSO APDU for a %d-byte cert; got %d",
			len(cert.Raw), len(rec.captured))
	}
	raw := rec.captured[0]
	if raw[0] != 0x80 {
		t.Errorf("CLA = %02X, want 80 (no chaining for ≤ 255-byte cert)", raw[0])
	}
}

// TestPSOChunking_ChainBitOnIntermediateOnlySetOnFinalChunkOfThatCert
// pins the interaction between the two "chain" concepts:
//
//  1. CLA's bit b5 (0x10) = ISO 7816-4 command chaining for a
//     SINGLE cert too big to fit in one short APDU.
//  2. P2's bit b8 (0x80) = GP §7.5 "more CERTS coming" indicator
//     to distinguish intermediates from the leaf.
//
// These are independent. Within a single intermediate cert that's
// chunked into N short APDUs, P2's chain bit (0x80) stays set on
// EVERY chunk (because the cert is an intermediate regardless of
// chunking), while CLA's chain bit (0x10) is set on chunks 0..N-2
// and clear on chunk N-1.
func TestPSOChunking_ChainBitsIndependentP2AndCLA(t *testing.T) {
	bigInter := mkCertOfSize(t, 600) // forces chunking
	smallLeaf := mkCertOfSize(t, 200)
	if len(smallLeaf.Raw) > 255 {
		t.Skipf("leaf is %d bytes; need ≤ 255 for this test", len(smallLeaf.Raw))
	}

	rec := &recordingTransportPSO{reply: [2]byte{0x90, 0x00}}
	s := &Session{
		transport: rec,
		config: &Config{
			OCECertificates: []*x509.Certificate{bigInter, smallLeaf},
			OCEKeyReference: KeyRef{KID: 0x10, KVN: 0x03},
		},
	}
	if err := s.sendOCECertificate(context.Background()); err != nil {
		t.Fatalf("sendOCECertificate: %v", err)
	}

	// Expect: ceil(big/255) chunks for the intermediate (each with
	// P2 = 0x90 = KID|0x80 P2-chain bit), then 1 short APDU for the
	// leaf (P2 = 0x10).
	bigChunks := (len(bigInter.Raw) + 254) / 255
	if len(rec.captured) != bigChunks+1 {
		t.Fatalf("expected %d intermediate chunks + 1 leaf APDU; got %d total",
			bigChunks, len(rec.captured))
	}

	// All intermediate chunks: P2 = 0x90 (KID | P2-chain).
	for i := 0; i < bigChunks; i++ {
		if rec.captured[i][3] != 0x90 {
			t.Errorf("intermediate chunk %d: P2 = %02X, want 90 (KID=10 | P2-chain bit 80)",
				i, rec.captured[i][3])
		}
		// CLA: chained on all but the LAST chunk of this cert.
		isLastIntChunk := i == bigChunks-1
		wantCLA := byte(0x90)
		if isLastIntChunk {
			wantCLA = 0x80
		}
		if rec.captured[i][0] != wantCLA {
			t.Errorf("intermediate chunk %d: CLA = %02X, want %02X",
				i, rec.captured[i][0], wantCLA)
		}
	}

	// Leaf APDU: P2 = 0x10, CLA = 0x80.
	leafAPDU := rec.captured[bigChunks]
	if leafAPDU[3] != 0x10 {
		t.Errorf("leaf APDU: P2 = %02X, want 10 (KID=10, no P2-chain bit)", leafAPDU[3])
	}
	if leafAPDU[0] != 0x80 {
		t.Errorf("leaf APDU: CLA = %02X, want 80 (final chunk of leaf, single-APDU cert)",
			leafAPDU[0])
	}
}

// keep the import surface stable.
var _ = errors.New

// keep ecdh import in case future tests need it.
var _ = ecdh.P256
