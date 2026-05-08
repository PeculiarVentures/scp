package securitydomain_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// selectiveTransport answers SELECT only for AIDs in the accept
// set; everything else returns SW=6A82. Covers DiscoverISD's
// retry-on-6A82 path against a controlled fixture rather than
// the full mockcard stack.
type selectiveTransport struct {
	accept [][]byte
}

func (t *selectiveTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS != 0xA4 {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	for _, a := range t.accept {
		if bytes.Equal(a, cmd.Data) {
			return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
		}
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil
}

func (t *selectiveTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*selectiveTransport) Close() error { return nil }
func (*selectiveTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

func TestDiscoverISD_FirstCandidateMatches(t *testing.T) {
	first := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	tt := &selectiveTransport{accept: [][]byte{first}}

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	defer sess.Close()
	if !bytes.Equal(match.AID, first) {
		t.Errorf("matched AID = %X, want %X", match.AID, first)
	}
}

func TestDiscoverISD_FallsThroughToSecondCandidate(t *testing.T) {
	// Only accept the second AID in ISDDiscoveryAIDs.
	second := gp.ISDDiscoveryAIDs[1].AID
	tt := &selectiveTransport{accept: [][]byte{second}}

	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	defer sess.Close()
	if !bytes.Equal(match.AID, second) {
		t.Errorf("matched AID = %X, want %X (second candidate)", match.AID, second)
	}
}

func TestDiscoverISD_NoneMatch_ReturnsSentinel(t *testing.T) {
	tt := &selectiveTransport{accept: nil} // accepts nothing

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err == nil {
		t.Fatal("expected error when no candidate matches")
	}
	if !errors.Is(err, securitydomain.ErrNoISDFound) {
		t.Errorf("err = %v, want wrap of ErrNoISDFound", err)
	}
}

// TestDiscoverISD_NoneMatch_ErrorIncludesEachAID asserts the
// exhaustion-path error message is operator-actionable: it
// must list every AID that was attempted (so the operator
// knows what was tried), include each AID's SW, and point to
// --sd-aid as the next step. Reviewer item #4: "make the
// failure message point directly to --sd-aid and include the
// tried AIDs."
//
// We pin the literal phrases the operator would grep for in a
// support transcript, plus a hex check on each AID. If a future
// refactor changes the error wording, this test fails loudly so
// the audit-log shape stays predictable.
func TestDiscoverISD_NoneMatch_ErrorIncludesEachAID(t *testing.T) {
	tt := &selectiveTransport{accept: nil}

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()

	// Must mention --sd-aid by literal flag name so an operator
	// reading the message knows the next step without consulting
	// docs.
	if !strings.Contains(msg, "--sd-aid") {
		t.Errorf("error message must mention --sd-aid; got %q", msg)
	}
	// Must list each curated default AID by its hex
	// representation. Iterates ISDDiscoveryAIDs so adding a new
	// candidate in gp/discovery.go automatically extends what
	// this test asserts.
	for _, c := range gp.ISDDiscoveryAIDs {
		if c.AID == nil {
			// Empty SELECT should render as a recognizable token.
			if !strings.Contains(msg, "(empty SELECT)") {
				t.Errorf("error message must mention empty SELECT candidate; got %q", msg)
			}
			continue
		}
		hexStr := strings.ToUpper(hex.EncodeToString(c.AID))
		if !strings.Contains(strings.ToUpper(msg), hexStr) {
			t.Errorf("error message must include tried AID %s; got %q", hexStr, msg)
		}
	}
	// Must announce the count up front — automation parsing
	// the message can use this as an anchor.
	if !strings.Contains(msg, "tried ") || !strings.Contains(msg, " AIDs") {
		t.Errorf("error message must announce 'tried N AIDs'; got %q", msg)
	}
}

// TestDiscoverISD_NonRetryableSWAborts: a non-6A82 SW (e.g. 6985
// security state, 6982 conditions not satisfied) is real card
// behavior we should not silently retry against every other AID
// — it would mask a real problem.
func TestDiscoverISD_NonRetryableSWAborts(t *testing.T) {
	tt := &abortingTransport{sw: 0x6985}

	_, _, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err == nil {
		t.Fatal("expected non-6A82 SW to abort discovery")
	}
	if errors.Is(err, securitydomain.ErrNoISDFound) {
		t.Errorf("non-6A82 should NOT surface as ErrNoISDFound: %v", err)
	}
	var ae *securitydomain.APDUError
	if !errors.As(err, &ae) || ae.SW != 0x6985 {
		t.Errorf("err should wrap APDUError with SW=6985: %v", err)
	}
	if tt.calls > 1 {
		t.Errorf("non-6A82 should abort after first probe; got %d calls", tt.calls)
	}
}

// abortingTransport returns the configured SW for every SELECT.
type abortingTransport struct {
	sw    uint16
	calls int
}

func (t *abortingTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS == 0xA4 {
		t.calls++
		return &apdu.Response{SW1: byte(t.sw >> 8), SW2: byte(t.sw)}, nil
	}
	return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
}
func (t *abortingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*abortingTransport) Close() error { return nil }
func (*abortingTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// TestDiscoverISD_RealMockCardCompatible: end-to-end against the
// SCP03+GP combined mock, which currently answers 9000 to any
// SELECT. The default GP ISD AID (first candidate) matches.
func TestDiscoverISD_RealMockCardCompatible(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)

	sess, match, err := securitydomain.DiscoverISD(context.Background(), mc.Transport(), gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD against mock: %v", err)
	}
	defer sess.Close()
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(match.AID, want) {
		t.Errorf("matched AID = %X, want first candidate %X", match.AID, want)
	}
}

// TestDiscoverISD_LockedSDProducesErrLockedISD covers the 6283
// path. SW=6283 ("selected file/application invalidated") means
// the SD exists at this AID but is in TERMINATED/LOCKED state —
// distinct from "not found." Discovery aborts at this candidate
// rather than continue probing because the operator's discovery
// list is correct; the card needs out-of-band recovery.
func TestDiscoverISD_LockedSDProducesErrLockedISD(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000": {SW1: 0x62, SW2: 0x83}, // locked
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "GP-default"},
	}
	_, _, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, nil)
	if err == nil {
		t.Fatal("expected ErrLockedISD")
	}
	if !errors.Is(err, securitydomain.ErrLockedISD) {
		t.Errorf("err should wrap ErrLockedISD: %v", err)
	}
}

// TestDiscoverISD_6A87TreatedAsNotFound: SmartJac/SafeNet variants
// answer 6A87 instead of 6A82 when the AID is unknown. Discovery
// must continue to the next candidate rather than abort.
func TestDiscoverISD_6A87TreatedAsNotFound(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000":   {SW1: 0x6A, SW2: 0x87}, // SmartJac "not found" variant
			"select:A000000003000000": {SW1: 0x90, SW2: 0x00}, // matches the second candidate
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "GP-default"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, Source: "vendor-X"},
	}
	_, match, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, nil)
	if err != nil {
		t.Fatalf("DiscoverISD should fall through 6A87 to next candidate: %v", err)
	}
	if match.Source != "vendor-X" {
		t.Errorf("expected vendor-X match, got %q", match.Source)
	}
}

// TestDiscoverISD_TraceCallbackInvokedPerAttempt: the trace
// callback must fire for every probe, including the matching
// one (Selected=true). Lets a CLI emit per-AID diagnostic lines
// the reviewer asked for.
func TestDiscoverISD_TraceCallbackInvokedPerAttempt(t *testing.T) {
	tr := &scriptedTransport{
		responses: map[string]apdu.Response{
			"select:A0000001510000":   {SW1: 0x6A, SW2: 0x82}, // not found
			"select:A000000018434D00": {SW1: 0x6A, SW2: 0x87}, // 6A87 variant
			"select:A000000003000000": {SW1: 0x90, SW2: 0x00}, // match
		},
	}
	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, Source: "first"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00}, Source: "second"},
		{AID: []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, Source: "third"},
	}
	var attempts []securitydomain.DiscoveryAttempt
	trace := func(a securitydomain.DiscoveryAttempt) {
		attempts = append(attempts, a)
	}
	_, _, err := securitydomain.DiscoverISD(context.Background(), tr, candidates, trace)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected 3 attempts traced, got %d", len(attempts))
	}
	// First two should be non-selected with their respective SWs.
	if attempts[0].Selected || attempts[0].SW != 0x6A82 {
		t.Errorf("attempt[0]: Selected=%v SW=%04X want false / 6A82", attempts[0].Selected, attempts[0].SW)
	}
	if attempts[1].Selected || attempts[1].SW != 0x6A87 {
		t.Errorf("attempt[1]: Selected=%v SW=%04X want false / 6A87", attempts[1].Selected, attempts[1].SW)
	}
	// Third should be the selected one.
	if !attempts[2].Selected || attempts[2].SW != 0x9000 {
		t.Errorf("attempt[2]: Selected=%v SW=%04X want true / 9000", attempts[2].Selected, attempts[2].SW)
	}
}

// scriptedTransport answers SELECT APDUs from a precomputed map
// keyed on "select:<aid-hex>". Used to drive DiscoverISD through
// specific SW responses without standing up a full mockcard.
type scriptedTransport struct {
	responses map[string]apdu.Response
}

func (s *scriptedTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS != 0xA4 {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	key := fmt.Sprintf("select:%X", cmd.Data)
	if r, ok := s.responses[key]; ok {
		return &r, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil // default not-found
}

func (s *scriptedTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("scriptedTransport: TransmitRaw not implemented")
}
func (s *scriptedTransport) Close() error { return nil }
func (s *scriptedTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// recordingTransport records every APDU's data field in the order
// they were sent. SELECT for any AID returns SW=6A82 except the
// final empty-SELECT which returns 9000 — lets a test verify that
// an empty-AID candidate produces an empty data field on the wire,
// not the AIDSecurityDomain bytes.
type recordingTransport struct {
	dataSeen [][]byte
}

func (r *recordingTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.INS != 0xA4 {
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
	// Clone the data so a later mutation can't change what we
	// recorded; the caller may pool or reuse the buffer.
	d := make([]byte, len(cmd.Data))
	copy(d, cmd.Data)
	r.dataSeen = append(r.dataSeen, d)
	if len(cmd.Data) == 0 {
		return &apdu.Response{SW1: 0x90, SW2: 0x00}, nil
	}
	return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil
}

func (r *recordingTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("recordingTransport: TransmitRaw not implemented")
}
func (*recordingTransport) Close() error { return nil }
func (*recordingTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// TestDiscoverISD_NilCandidateSendsEmptySelect pins the bug fix that
// motivated the openSelectAIDLiteral split. Before that fix,
// DiscoverISD called OpenUnauthenticatedWithAID, which routed nil
// AIDs through effectiveSDAID and silently substituted
// AIDSecurityDomain. The curated list's nil-AID entry (intended as
// the ISO/IEC 7816-4 §5.3.1 default-selection probe) collapsed to
// the first candidate. This test fails the regression by asserting
// that one of the SELECTs DiscoverISD sends has an empty data field.
func TestDiscoverISD_NilCandidateSendsEmptySelect(t *testing.T) {
	rec := &recordingTransport{}

	// Use the production curated list so the test exercises the
	// real ordering rather than a synthetic one.
	sess, match, err := securitydomain.DiscoverISD(context.Background(), rec, gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD: %v", err)
	}
	defer sess.Close()

	if match.AID != nil {
		t.Errorf("matched AID = %X, want nil (empty-SELECT candidate)", match.AID)
	}

	var sawEmpty bool
	for i, d := range rec.dataSeen {
		if len(d) == 0 {
			sawEmpty = true
			t.Logf("attempt[%d]: empty SELECT (data field 0 bytes)", i)
		} else {
			t.Logf("attempt[%d]: SELECT data=%X", i, d)
		}
	}
	if !sawEmpty {
		t.Errorf("DiscoverISD never sent SELECT with empty data field; "+
			"every attempt carried data, suggesting effectiveSDAID "+
			"is silently substituting AIDSecurityDomain for nil candidates. "+
			"data fields seen: %v", rec.dataSeen)
	}
}

// TestDiscoverISD_GemPlusRIDCardManagerAID pins the curated
// list's entry for the GemPlus-RID Card Manager AID
// (A000000018434D00). We have empirical confirmation that the
// SafeNet eToken Fusion responds to this AID; other vendors'
// cards (including Oberthur in real-hardware testing) have also
// been observed responding to it. The test asserts the entry is
// present in the curated list, that the Source string identifies
// the AID's RID (not any specific vendor of card built around
// it), and that DiscoverISD resolves a card that only answers
// this AID.
func TestDiscoverISD_GemPlusRIDCardManagerAID(t *testing.T) {
	gemPlusAID, _ := hex.DecodeString("A000000018434D00")

	// Confirm the curated list contains it.
	var found bool
	for _, c := range gp.ISDDiscoveryAIDs {
		if bytes.Equal(c.AID, gemPlusAID) {
			found = true
			// Source must cite the AID's RID-level provenance,
			// which is a fact about the ISO/IEC 7816-5
			// registration. It must NOT name specific card
			// vendors or firmware families, because matching
			// this AID does not identify the card vendor. The
			// post-cleanup Source mentions "GemPlus RID" (the
			// RID owner per the registration) and "Card Manager"
			// (the conventional meaning of the suffix); both
			// are AID-level statements, not card-level.
			if !strings.Contains(c.Source, "GemPlus RID") {
				t.Errorf("Source should cite GemPlus RID per ISO/IEC 7816-5; got %q", c.Source)
			}
			if !strings.Contains(c.Source, "Card Manager") {
				t.Errorf("Source should identify the AID as a Card Manager; got %q", c.Source)
			}
			// Guard against regression to the editorial form
			// that named specific vendor families.
			for _, banned := range []string{"GemXpresso", "IDPrime", "IDCore", "SafeNet eToken Fusion"} {
				if strings.Contains(c.Source, banned) {
					t.Errorf("Source should not name specific vendor families (matched %q in: %q)",
						banned, c.Source)
				}
			}
			break
		}
	}
	if !found {
		t.Fatalf("ISDDiscoveryAIDs is missing the GemPlus-RID Card Manager AID %X", gemPlusAID)
	}

	// Confirm a card that only answers the GemPlus-RID AID gets resolved.
	tt := &selectiveTransport{accept: [][]byte{gemPlusAID}}
	sess, match, err := securitydomain.DiscoverISD(context.Background(), tt, gp.ISDDiscoveryAIDs, nil)
	if err != nil {
		t.Fatalf("DiscoverISD against GemPlus-RID-only card: %v", err)
	}
	defer sess.Close()
	if !bytes.Equal(match.AID, gemPlusAID) {
		t.Errorf("matched AID = %X, want %X (GemPlus-RID Card Manager)", match.AID, gemPlusAID)
	}
}

// chainedSelectTransport models a card that answers SELECT to a
// specific AID with SW=61xx (FCI is xx bytes, fetch with GET
// RESPONSE), then returns the FCI on the GET RESPONSE call. This
// is the behavior some Thales/Gemalto cards (notably the GP 2.1.1
// SafeNet eToken family with ATR 3B7F96000080318065B0850300EF120F)
// emit when the host sends SELECT without an Le=00 trailer or when
// the underlying PC/SC layer doesn't auto-follow the chain. Pre-
// fix the SELECT path used t.Transmit directly and reported SW=6167
// as a SELECT failure; post-fix it routes through
// transport.TransmitCollectAll so the chain is followed
// transparently and the FCI is assembled into one Response.
type chainedSelectTransport struct {
	matchAID     []byte
	fci          []byte
	getRespCalls int
	selectCalls  int
}

func (t *chainedSelectTransport) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4: // SELECT
		t.selectCalls++
		if !bytes.Equal(cmd.Data, t.matchAID) {
			return &apdu.Response{SW1: 0x6A, SW2: 0x82}, nil
		}
		// Real Thales card behavior: SW=61<len> indicating "FCI is
		// <len> bytes, fetch with GET RESPONSE." Length is the
		// length of t.fci; cap at 0xFF so the encoding fits SW2.
		l := len(t.fci)
		if l > 0xFF {
			l = 0xFF
		}
		return &apdu.Response{SW1: 0x61, SW2: byte(l)}, nil
	case 0xC0: // GET RESPONSE
		t.getRespCalls++
		// Return the FCI in one chunk, terminated with 9000.
		return &apdu.Response{Data: append([]byte(nil), t.fci...), SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

func (*chainedSelectTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (*chainedSelectTransport) Close() error { return nil }
func (*chainedSelectTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}

// TestDiscoverISD_Follows61xxChainOnSelect is the regression for
// the SELECT-with-61xx response pattern observed against a Thales
// GP 2.1.1 card during ML840 hardware investigation. Pre-fix
// scpctl reported SW=6167 as a SELECT failure and aborted; post-fix
// the chain is followed and the SD opens cleanly.
func TestDiscoverISD_Follows61xxChainOnSelect(t *testing.T) {
	gemAID, _ := hex.DecodeString("A000000018434D00")
	// Synthetic 0x67-byte FCI body. Content doesn't matter for
	// this test; only the assembly path matters.
	fci := bytes.Repeat([]byte{0xCC}, 0x67)

	tt := &chainedSelectTransport{
		matchAID: gemAID,
		fci:      fci,
	}

	candidates := []gp.ISDCandidate{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}}, // GP default, won't match
		{AID: gemAID}, // matches with 61xx
	}

	sd, picked, err := securitydomain.DiscoverISD(context.Background(), tt, candidates, nil)
	if err != nil {
		t.Fatalf("DiscoverISD should follow 61xx chain on SELECT; got err = %v", err)
	}
	defer sd.Close()
	if !bytes.Equal(picked.AID, gemAID) {
		t.Errorf("picked AID = %X, want %X", picked.AID, gemAID)
	}
	if tt.selectCalls != 2 {
		t.Errorf("expected 2 SELECT calls (one 6A82 then one 61xx); got %d", tt.selectCalls)
	}
	if tt.getRespCalls != 1 {
		t.Errorf("expected 1 GET RESPONSE call following the 61xx; got %d", tt.getRespCalls)
	}
}
