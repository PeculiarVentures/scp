// External-vector transcripts for SCP03.
//
// Sources and provenance live in testvectors/README.md. The relevant
// upstream commits at the time of last verification (2026-05-03):
//
//   - Samsung/OpenSCP-Java       @ b9876fc36a5b18fb90ce03d0894f39edb08a905b
//     License: Apache-2.0
//     Per-test references identify the specific upstream Java fixture
//     each transcript was extracted from.
//
//   - martinpaljak/GlobalPlatformPro @ 6d6c154dd55b3dc5406d980345d44c8e4ed01a72
//     License: LGPL-3.0-or-later
//     Real-card JCOP4 dumps for SCP03 INITIALIZE UPDATE and EXTERNAL
//     AUTHENTICATE.
//
// All upstream CAPDU / RAPDU bytes here are preserved verbatim. They
// are known-answer inputs, not values for the local mock card to
// derive. When updating provenance, update both this header AND the
// corresponding "Verified at" SHA in testvectors/README.md.

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
	"github.com/PeculiarVentures/scp/transport"
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

var samsungAES192Keys = StaticKeys{
	ENC: hx("1D72CD9283FD55162722C6BEAA4DC1877F4C0CD0ECC15E05"),
	MAC: hx("F4932BA02FFC3098D172790099D2838236F2E61068D56F44"),
	DEK: hx("B4BDC610C3F6793708FF1132E2C5BF60523AEAC06B32F204"),
}

var samsungAES256Keys = StaticKeys{
	ENC: hx("1D72CD9283FD55162722C6BEAA4DC1877F4C0CD0ECC15E052AAC39A99AF9AD72"),
	MAC: hx("F4932BA02FFC3098D172790099D2838236F2E61068D56F4401CC0374C25AF8CB"),
	DEK: hx("B4BDC610C3F6793708FF1132E2C5BF60523AEAC06B32F204B851B6CC007C8D3C"),
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
//	nextgen/src/test/resources/scp03-init-update-jcop4.dump
//	nextgen/src/test/resources/scp03-auth-jcop4.dump
//
// This is a real-card transcript using default AES-128 keys, fixed host
// challenge 0102030405060708, and MAC-only security level. See
// testvectors/README.md for the verified upstream SHA.
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

// TestSCP03_SamsungOpenSCP_AES192_S8_FullTranscript imports the AES-192/S8
// SCP03 transcript from Samsung OpenSCP-Java:
//
//	src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes192S8ModeEmulation.java
//	src/test/java/com/samsung/openscp/testdata/InputTestData.java (static keys)
//
// This exercises AES-192 KDF, channel encryption, and CMAC end-to-end.
// Without it, AES-192 support was a property of the type system
// (StaticKeys accepts 24-byte slices) without actual proof the protocol
// path worked.
func TestSCP03_SamsungOpenSCP_AES192_S8_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030000806F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003709CE033FA78E6B10D6E7C64F962A822A400082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("848233001063B6CEFAC0EC098333860788C65220BA"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES192Keys,
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

// TestSCP03_SamsungOpenSCP_AES256_S8_FullTranscript imports the AES-256/S8
// SCP03 transcript from Samsung OpenSCP-Java:
//
//	src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes256S8ModeEmulation.java
//
// As with the AES-192 case, this is a byte-exact known-answer test that
// proves the AES-256 path through KDF, AES-CBC, and AES-CMAC actually
// works, not just that the parser accepts a 32-byte key.
func TestSCP03_SamsungOpenSCP_AES256_S8_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030000806F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003709CE033FA78E6B10D8AFA7267CB63740E00082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("848233001050E003735F92228269A094FFC07429FD"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES256Keys,
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

// TestSCP03_SamsungOpenSCP_AES192_S16_FullTranscript imports the AES-192/S16
// SCP03 transcript from Samsung OpenSCP-Java. S16 mode uses 16-byte
// challenges and 16-byte cryptograms/MACs, so this exercises the full
// non-truncated path on top of AES-192 KDF.
func TestSCP03_SamsungOpenSCP_AES192_S16_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030001006F85B77251BF79406F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003710617A2C34D50B562F7DECFC3DBF58A64A378671D41E7F6E3F5254CA9D4C481A400082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("848233002099033B5BB5246C859B9748E497EDAE8D9EBB7BD196CE4E3EBFC92343D69478AB"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES192Keys,
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

// TestSCP03_SamsungOpenSCP_AES256_S16_FullTranscript imports the AES-256/S16
// transcript. Together with the four other Samsung transcripts above, this
// closes out the SCP03 matrix: every (key size, S parameter) combination
// — AES-128/192/256 × S8/S16 — has at least one byte-exact known-answer
// test through it.
func TestSCP03_SamsungOpenSCP_AES256_S16_FullTranscript(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		{
			name:        "INITIALIZE UPDATE",
			wantCAPDU:   hx("805030001006F85B77251BF79406F85B77251BF79400"),
			returnRAPDU: hx("A1A012430585513120853003710617A2C34D50B562F7DECFC3DBF58A6499D2966CF09C9201FDE8343E93FB18B400082A9000"),
		},
		{
			name:        "EXTERNAL AUTHENTICATE",
			wantCAPDU:   hx("848233002071D1A091C5D24AF177B00E69B1A32B4E30A5168CF8C86B19730DF915EF82D8A7"),
			returnRAPDU: hx("9000"),
		},
	})

	sess, err := Open(context.Background(), tt, &Config{
		Keys:          samsungAES256Keys,
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

// TestSCP03_NoSELECT_WhenSelectAIDNil confirms that SelectAID = nil
// causes Open to skip the initial SELECT entirely. The use case is
// callers that have already SELECTed the target applet through some
// other path (test harness, manual setup, applet-aware transport).
func TestSCP03_NoSELECT_WhenSelectAIDNil(t *testing.T) {
	tt := newTranscriptTransport(t, []transcriptStep{
		// No SELECT step expected — the very first APDU is INITIALIZE UPDATE.
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
		// SelectAID intentionally nil — caller has already selected.
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer sess.Close()
	tt.expectConsumedAll()
}

func (tt *transcriptTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
