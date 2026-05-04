package cardrecognition_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cardrecognition"
	"github.com/PeculiarVentures/scp/transport"
)

// TestParse_NokiaSCP02 parses the real CRD blob from a Nokia 6131
// NFC phone, captured in 2009 and frequently used as a worked example
// of GP §H.2 structure. SCP version is 02, `i` parameter is 0x55,
// GP version 2.1.1.
//
// Bytes are exactly as published; this is the "do we agree with the
// rest of the world about what these bytes mean" test.
func TestParse_NokiaSCP02(t *testing.T) {
	// 66 4C
	//   73 4A
	//     06 07 2A864886FC6B 01            -- GP RID
	//     60 0C 06 0A 2A864886FC6B 02 02 01 01     -- GP 2.1.1
	//     63 09 06 07 2A864886FC6B 03       -- card ID scheme
	//     64 0B 06 09 2A864886FC6B 04 02 55 -- SCP02 i=0x55
	//     65 0B 06 09 2B8510864864020103    -- card config
	//     66 0C 06 0A 2B060104012A026E0102  -- card / chip
	//
	// Assembled piece-by-piece so the byte counts are easy to audit
	// against the GP §H.2 layout.
	raw := concat(
		// outer tag + length
		mustHex(t, "664C"),
		// inner OID list, length 0x4A = 74 bytes
		mustHex(t, "734A"),
		// 06 07 2A864886FC6B 01 — GP RID (9 bytes total)
		mustHex(t, "06072A864886FC6B01"),
		// 60 0C 06 0A 2A864886FC6B 02 02 01 01 — GP 2.1.1 (14 bytes)
		mustHex(t, "600C060A2A864886FC6B02020101"),
		// 63 09 06 07 2A864886FC6B 03 — card ID (11 bytes)
		mustHex(t, "630906072A864886FC6B03"),
		// 64 0B 06 09 2A864886FC6B 04 02 55 — SCP02 i=0x55 (13 bytes)
		mustHex(t, "640B06092A864886FC6B040255"),
		// 65 0B 06 09 2B8510864864020103 — card config (13 bytes)
		mustHex(t, "650B06092B8510864864020103"),
		// 66 0C 06 0A 2B060104012A026E0102 — card / chip (14 bytes)
		mustHex(t, "660C060A2B060104012A026E0102"),
	)
	// Sanity-check the reassembly: outer 0x66 length byte should be 0x4C = 76,
	// and the body length (everything after the outer tag+length) should be 76.
	if len(raw) != 78 {
		t.Fatalf("test fixture has length %d, want 78 (2-byte outer header + 76-byte body)", len(raw))
	}

	info, err := cardrecognition.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// GP version 2.1.1 → arcs after `1.2.840.114283.2` should be {2,1,1}.
	if got, want := info.GPVersion, []int{2, 1, 1}; !intsEqual(got, want) {
		t.Errorf("GPVersion = %v, want %v", got, want)
	}
	if info.SCPVersion != 0x02 {
		t.Errorf("SCPVersion = 0x%02X, want 0x02", info.SCPVersion)
	}
	if info.SCPParameter != 0x55 {
		t.Errorf("SCPParameter = 0x%02X, want 0x55", info.SCPParameter)
	}
	if len(info.CardIdentificationOID) == 0 {
		t.Error("CardIdentificationOID is empty; expected populated")
	}
	if len(info.CardConfigDetailsOID) == 0 {
		t.Error("CardConfigDetailsOID is empty; expected populated")
	}
	if len(info.CardChipDetailsOID) == 0 {
		t.Error("CardChipDetailsOID is empty; expected populated")
	}
	if len(info.Raw) != len(raw) {
		t.Errorf("Raw length = %d, want %d", len(info.Raw), len(raw))
	}
}

// TestParse_SyntheticSCP03 builds a CRD that advertises SCP03 with
// `i` = 0x65 (pseudo-random challenge + R-MAC + R-ENC, common on
// modern cards including YubiKey) and GP version 2.3.1. This is the
// case that matters for our actual target cards.
func TestParse_SyntheticSCP03(t *testing.T) {
	raw := buildCRD(t,
		// GP RID marker
		mustHex(t, "06072A864886FC6B01"),
		// GP 2.3.1: OID 1.2.840.114283.2.2.3.1 (10-byte value)
		wrap(t, 0x60, mustHex(t, "060A2A864886FC6B02020301")),
		// SCP03 i=0x65: OID 1.2.840.114283.4.3.65 (9-byte value)
		wrap(t, 0x64, mustHex(t, "06092A864886FC6B040365")),
	)

	info, err := cardrecognition.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := info.GPVersion, []int{2, 3, 1}; !intsEqual(got, want) {
		t.Errorf("GPVersion = %v, want %v", got, want)
	}
	if info.SCPVersion != 0x03 {
		t.Errorf("SCPVersion = 0x%02X, want 0x03", info.SCPVersion)
	}
	if info.SCPParameter != 0x65 {
		t.Errorf("SCPParameter = 0x%02X, want 0x65", info.SCPParameter)
	}
}

// TestParse_SyntheticSCP11 verifies that an SCP11 CRD with a 2-byte
// `i` parameter parses correctly. GP Card Spec v2.3 Amendment F (SCP11
// v1.3 §6.2) widens the i-parameter from one byte to one-or-two bytes,
// and real YubiKey 5 firmware ≥5.7.2 emits the 2-byte form. Before this
// test, the parser rejected the OID outright as "arcs out of byte range".
//
// The OID under tag 0x64 is 1.2.840.114283.4.17.3462, where:
//   - Arc 17 (= 0x11) identifies SCP11 (GP encodes versions in BCD-ish
//     form: SCP02→0x02, SCP03→0x03, SCP10→0x10, SCP11→0x11).
//   - Arc 3462 (= 0x0D86) is the variant-flags bitmap packed into a
//     single OID arc whose integer value exceeds 0xFF.
//
// 3462 in ASN.1 OID base-128 encoding takes two bytes: 27*128 + 6,
// encoded as 0x9B 0x06 (0x80|27 continuation, then terminator 0x06).
// The full inner OID (tag-0x06 contents) is therefore 10 bytes:
//
//	2A 86 48 86 FC 6B   -- 1.2.840.114283 (GP RID)
//	04                  -- card recognition data sub-tree
//	11                  -- SCP version byte (SCP11)
//	9B 06               -- i-parameter packed into one arc (= 3462)
func TestParse_SyntheticSCP11(t *testing.T) {
	raw := buildCRD(t,
		// GP RID marker
		mustHex(t, "06072A864886FC6B01"),
		// GP 2.3.1
		wrap(t, 0x60, mustHex(t, "060A2A864886FC6B02020301")),
		// SCP11 i=0x0D86: tag 0x06 + length 0x0A + 10 bytes of OID.
		wrap(t, 0x64, mustHex(t, "060A2A864886FC6B04119B06")),
	)

	info, err := cardrecognition.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SCPVersion != 0x11 {
		t.Errorf("SCPVersion = 0x%02X, want 0x11", info.SCPVersion)
	}
	if info.SCPParameter != 0x0D86 {
		t.Errorf("SCPParameter = 0x%04X, want 0x0D86", info.SCPParameter)
	}
}

// TestParse_RejectsSCPIParameterTooLarge confirms the 16-bit ceiling on
// the SCP i-parameter. GP SCP11 v1.3 §6.2 caps the i-parameter at two
// bytes; anything larger is malformed CRD, not a future encoding we
// should silently accept.
//
// OID 1.2.840.114283.4.17.65536 — last arc is 0x10000, just past the
// 16-bit boundary. ASN.1 base-128 encodes 65536 as 0x84 0x80 0x00.
func TestParse_RejectsSCPIParameterTooLarge(t *testing.T) {
	raw := buildCRD(t,
		mustHex(t, "06072A864886FC6B01"),
		// 06 0B 2A864886FC6B 04 11 84 80 00 — 11-byte OID content,
		// last arc is 65536 which exceeds the 16-bit limit.
		wrap(t, 0x64, mustHex(t, "060B2A864886FC6B0411848000")),
	)
	_, err := cardrecognition.Parse(raw)
	if !errors.Is(err, cardrecognition.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
	if !strings.Contains(err.Error(), "i-parameter") {
		t.Errorf("error should mention i-parameter; got: %v", err)
	}
}

// TestParse_RejectsSCPOIDWrongShape covers the tightened length check.
// A 6-arc OID (missing the i-parameter, or one extra/missing arc
// elsewhere) is no longer accepted with last-two-arcs heuristics; it's
// reported as malformed because GP §H.2 fixes the shape at exactly
// seven arcs.
func TestParse_RejectsSCPOIDWrongShape(t *testing.T) {
	raw := buildCRD(t,
		mustHex(t, "06072A864886FC6B01"),
		// OID 1.2.840.114283.4.3 — only six arcs, no i-parameter.
		// 06 07 2A864886FC6B 04 03  (7-byte OID content).
		wrap(t, 0x64, mustHex(t, "06072A864886FC6B0403")),
	)
	_, err := cardrecognition.Parse(raw)
	if !errors.Is(err, cardrecognition.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
	if !strings.Contains(err.Error(), "unexpected shape") {
		t.Errorf("error should mention shape; got: %v", err)
	}
}


// that's already unwrapped from the outer tag 0x66. Real callers
// using Probe will get unwrapped value bytes from apdu.Response.Data.
func TestParse_AcceptsValueWithoutOuterTag(t *testing.T) {
	full := buildCRD(t,
		mustHex(t, "06072A864886FC6B01"),
		wrap(t, 0x64, mustHex(t, "06092A864886FC6B040365")),
	)

	// Strip the outer tag + length (tag 0x66 + 1-byte length).
	if full[0] != 0x66 {
		t.Fatalf("test fixture doesn't start with 0x66")
	}
	inner := full[2:]

	info, err := cardrecognition.Parse(inner)
	if err != nil {
		t.Fatalf("Parse(inner): %v", err)
	}
	if info.SCPVersion != 0x03 {
		t.Errorf("SCPVersion = 0x%02X, want 0x03", info.SCPVersion)
	}
}

// TestParse_RejectsNonGPMarker ensures Parse refuses CRD-shaped data
// whose marker OID isn't under the GlobalPlatform RID. Otherwise we'd
// silently accept an arbitrary tag-0x66 blob from a non-GP applet.
func TestParse_RejectsNonGPMarker(t *testing.T) {
	// OID 1.2.840.10045.2.1 (ecPublicKey) — emphatically not GP.
	raw := buildCRD(t,
		mustHex(t, "0607 2A 86 48 CE 3D 02 01"),
	)
	_, err := cardrecognition.Parse(raw)
	if !errors.Is(err, cardrecognition.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
	if !strings.Contains(err.Error(), "GP RID") {
		t.Errorf("error should mention GP RID; got: %v", err)
	}
}

func TestParse_RejectsEmpty(t *testing.T) {
	_, err := cardrecognition.Parse(nil)
	if !errors.Is(err, cardrecognition.ErrEmpty) {
		t.Errorf("expected ErrEmpty, got %v", err)
	}
}

func TestParse_RejectsTruncated(t *testing.T) {
	// 66 4C  but body is 4 bytes of nonsense
	_, err := cardrecognition.Parse(mustHex(t, "664CDEADBEEF"))
	if !errors.Is(err, cardrecognition.ErrMalformed) {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestParse_RejectsMissingOIDList(t *testing.T) {
	// Wrap nothing — outer 0x66 contains no 0x73 list.
	raw := mustHex(t, "660400000000")
	_, err := cardrecognition.Parse(raw)
	if !errors.Is(err, cardrecognition.ErrMalformed) {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

// TestProbe_HappyPath wires Parse end-to-end through a fake transport
// that returns a known CRD blob in response to GET DATA tag 0x66.
func TestProbe_HappyPath(t *testing.T) {
	expected := buildCRD(t,
		mustHex(t, "06072A864886FC6B01"),
		wrap(t, 0x60, mustHex(t, "060A2A864886FC6B02020301")),
		wrap(t, 0x64, mustHex(t, "06092A864886FC6B040365")),
	)
	// Strip the outer 66 LL — Probe expects what GET DATA returns,
	// which is the CRD with the outer tag preserved (the card returns
	// tag 0x66 in its reply data field per GP §11.3).
	tr := &probeTransport{response: expected}

	info, err := cardrecognition.Probe(context.Background(), tr)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if info.SCPVersion != 0x03 {
		t.Errorf("SCPVersion = 0x%02X, want 0x03", info.SCPVersion)
	}
	if got, want := info.GPVersion, []int{2, 3, 1}; !intsEqual(got, want) {
		t.Errorf("GPVersion = %v, want %v", got, want)
	}
	// Confirm the right APDU went out.
	if tr.lastCmd == nil {
		t.Fatal("transport saw no command")
	}
	if tr.lastCmd.CLA != 0x80 || tr.lastCmd.INS != 0xCA ||
		tr.lastCmd.P1 != 0x00 || tr.lastCmd.P2 != 0x66 {
		t.Errorf("Probe sent CLA=%02X INS=%02X P1=%02X P2=%02X, want 80 CA 00 66",
			tr.lastCmd.CLA, tr.lastCmd.INS, tr.lastCmd.P1, tr.lastCmd.P2)
	}
}

// TestProbe_PropagatesCardError verifies a non-9000 SW comes back as
// an informative error.
func TestProbe_PropagatesCardError(t *testing.T) {
	tr := &probeTransport{sw: 0x6A88}
	_, err := cardrecognition.Probe(context.Background(), tr)
	if err == nil {
		t.Fatal("expected error from card returning 6A88")
	}
	if !strings.Contains(err.Error(), "6A88") {
		t.Errorf("error should include status word; got: %v", err)
	}
}

// --- helpers ---

type probeTransport struct {
	response []byte // bytes returned in apdu.Response.Data on success
	sw       uint16 // override status word; default 0x9000 if response is set
	lastCmd  *apdu.Command
}

func (p *probeTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	p.lastCmd = cmd
	resp := &apdu.Response{Data: p.response, SW1: 0x90, SW2: 0x00}
	if p.sw != 0 {
		resp.SW1 = byte(p.sw >> 8)
		resp.SW2 = byte(p.sw)
	}
	return resp, nil
}

func (p *probeTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (p *probeTransport) Close() error { return nil }

var _ transport.Transport = (*probeTransport)(nil)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// wrap encloses contents inside a single-byte-length TLV with the
// given tag. Test helper; only handles length < 128.
func wrap(t *testing.T, tag byte, contents []byte) []byte {
	t.Helper()
	if len(contents) >= 128 {
		t.Fatalf("wrap: contents too long (%d bytes); test helper only handles short form", len(contents))
	}
	return append([]byte{tag, byte(len(contents))}, contents...)
}

// buildCRD assembles a complete CRD blob: outer 0x66 wrapping an
// inner 0x73 OID list whose children are the supplied elements.
func buildCRD(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	body := concat(elements...)
	list := wrap(t, 0x73, body)
	return wrap(t, 0x66, list)
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (p *probeTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
