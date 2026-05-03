package scp03

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
)

type transcriptStep struct {
	name        string
	wantCAPDU   []byte
	returnRAPDU []byte
}

type transcriptTransport struct {
	t     *testing.T
	steps []transcriptStep
	next  int
}

func newTranscriptTransport(t *testing.T, steps []transcriptStep) *transcriptTransport {
	t.Helper()
	return &transcriptTransport{t: t, steps: steps}
}

func (tt *transcriptTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	tt.t.Helper()
	if tt.next >= len(tt.steps) {
		return nil, fmt.Errorf("unexpected extra CAPDU: %X", mustEncodeCommand(tt.t, cmd))
	}

	step := tt.steps[tt.next]
	tt.next++

	gotCAPDU := mustEncodeCommand(tt.t, cmd)
	if !bytes.Equal(gotCAPDU, step.wantCAPDU) {
		return nil, fmt.Errorf("%s CAPDU mismatch\n  got:  %X\n  want: %X", step.name, gotCAPDU, step.wantCAPDU)
	}

	return apdu.ParseResponse(step.returnRAPDU)
}

func (tt *transcriptTransport) TransmitRaw(_ context.Context, raw []byte) ([]byte, error) {
	tt.t.Helper()
	if tt.next >= len(tt.steps) {
		return nil, fmt.Errorf("unexpected extra raw CAPDU: %X", raw)
	}

	step := tt.steps[tt.next]
	tt.next++

	if !bytes.Equal(raw, step.wantCAPDU) {
		return nil, fmt.Errorf("%s raw CAPDU mismatch\n  got:  %X\n  want: %X", step.name, raw, step.wantCAPDU)
	}
	return append([]byte(nil), step.returnRAPDU...), nil
}

func (tt *transcriptTransport) Close() error { return nil }

func (tt *transcriptTransport) expectConsumedAll() {
	tt.t.Helper()
	if tt.next != len(tt.steps) {
		tt.t.Fatalf("only consumed %d/%d transcript steps", tt.next, len(tt.steps))
	}
}

func mustEncodeCommand(t *testing.T, cmd *apdu.Command) []byte {
	t.Helper()
	raw, err := cmd.Encode()
	if err != nil {
		t.Fatalf("encode command: %v", err)
	}
	return raw
}

var samsungAES128Keys = StaticKeys{
	ENC: hx("1D72CD9283FD55162722C6BEAA4DC187"),
	MAC: hx("F4932BA02FFC3098D172790099D28382"),
	DEK: hx("B4BDC610C3F6793708FF1132E2C5BF60"),
}

func hx(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestSCP03_GlobalPlatformPro_JCOP4_MACOnlyTranscript imports the JCOP4
// SCP03 transcript from GlobalPlatformPro:
//
//	nextgen/src/test/resources/scp03-auth-jcop4.dump
//
// This is a real-card transcript using default AES-128 keys, fixed host
// challenge 0102030405060708, and MAC-only security level.
func TestSCP03_GlobalPlatformPro_JCOP4_MACOnlyTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("8050000008010203040506070800"),
			returnRAPDU: hx("00003244342976208448010370734ECDCA19E446A30BC253BCE97DB9910004369000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("8482010010A5E66CD1A836E3A47CD3B3F7B689AE8F"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          DefaultKeys,
		KeyVersion:    0x00,
		HostChallenge: hx("0102030405060708"),
		SecurityLevel: channel.LevelCMAC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()
	tt.expectConsumedAll()
}

// TestSCP03_SamsungOpenSCP_AES128_S8_FullTranscript imports the AES-128/S8
// SCP03 transcript from Samsung OpenSCP-Java:
//
//	src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S8ModeEmulation.java
//
// This test should fail if EXTERNAL AUTHENTICATE is encrypted. Per the
// transcript, the command data is hostCryptogram || C-MAC, with Lc=0x10.
func TestSCP03_SamsungOpenSCP_AES128_S8_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030000806F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003709CE033FA78E6B10DDC2DBE8974C8B0DE00082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("8482330010B08D6CE26B6CB3CCB411CF0296EB7B1D"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES128Keys,
		KeyVersion:    0x30,
		HostChallenge: hx("06F85B77251BF794"),
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()
	tt.expectConsumedAll()
}

// TestSCP03_SamsungOpenSCP_AES128_S16_FullTranscript imports the AES-128/S16
// SCP03 transcript from Samsung OpenSCP-Java:
//
//	src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S16ModeEmulation.java
//
// It is intentionally a red test for implementations that hard-code S8 mode.
func TestSCP03_SamsungOpenSCP_AES128_S16_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030001006F85B77251BF79406F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003710617A2C34D50B562F7DECFC3DBF58A649EF733B7486D813C92E4CA61E5102F9100082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("84823300201C6A43582F842A90D81CA4E970754664D8C0C6C340E007C5C6EBCDF4F7C065BE"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES128Keys,
		KeyVersion:    0x30,
		HostChallenge: hx("06F85B77251BF79406F85B77251BF794"),
		SecurityLevel: channel.LevelFull,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()
	tt.expectConsumedAll()
}

