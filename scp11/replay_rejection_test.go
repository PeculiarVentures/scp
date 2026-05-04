package scp11_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSCP11_RelayReplayedResponse_Rejected demonstrates that an SCP11
// session running over a remote relay rejects a relay that returns a
// stale (replayed) response on a fresh request. This is the
// "duplicate / replayed response rejection" requirement from
// docs/remote-apdu-transport.md, exercised structurally rather than
// just documented.
//
// Threat model: an endpoint or message bus that records a successful
// post-handshake response and replays it on a subsequent request.
// SCP11 secure messaging defends against this by chaining R-MAC over
// an advancing encryption counter, so an old response's R-MAC will
// not validate against the current counter state.
//
// Topology:
//
//	server: scp11.Open()        replayingRelay
//	                               ├─ first Transmit:  pass through
//	                               ├─ capture response
//	                               └─ second Transmit: REPLAY captured response
//	                                                   instead of forwarding
//
// Expected behavior:
//
//  1. scp11.Open succeeds (handshake APDUs go through cleanly).
//  2. First sess.Transmit succeeds (secure-messaging round trip).
//  3. Second sess.Transmit fails with R-MAC verification error.
//  4. The session is no longer usable; further Transmits also fail.
//
// What this test catches if regressed:
//
//   - If R-MAC verification ever falls back to a constant counter,
//     the replayed response would be accepted as fresh.
//   - If the encryption counter doesn't advance after a successful
//     receive, the MAC chain becomes deterministic and replays land.
//   - If MAC verification is silently skipped on an error path
//     (e.g. a "best effort" mode), the replay would slip through.
func TestSCP11_RelayReplayedResponse_Rejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	card, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}

	reqCh := make(chan []byte)
	respCh := make(chan []byte)
	relayDone := make(chan struct{})

	go func() {
		defer close(relayDone)
		defer close(respCh)
		cardT := card.Transport()
		for raw := range reqCh {
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

	rt := &replayingRelayTransport{
		reqCh:  reqCh,
		respCh: respCh,
		tracer: func(req, resp []byte, replayed bool) {
			rTrim := req
			if len(rTrim) > 16 {
				rTrim = rTrim[:16]
			}
			pTrim := resp
			if len(pTrim) > 16 {
				pTrim = pTrim[:16]
			}
			t.Logf("relay: req=% X (len=%d) resp=% X (len=%d) replayed=%v",
				rTrim, len(req), pTrim, len(resp), replayed)
		},
	}

	// Open SCP11b — simpler than SCP11a here because the test is
	// about the secure-messaging counter, not OCE auth, and SCP11b
	// reaches a usable secure channel with less setup.
	cfg := scp11.DefaultSCP11bConfig()
	cfg.InsecureSkipCardAuthentication = true
	sess, err := scp11.Open(ctx, rt, cfg)
	if err != nil {
		t.Fatalf("scp11.Open: %v", err)
	}
	defer sess.Close()

	// First post-handshake Transmit: pass through normally. The relay
	// captures the response so it can replay it next time.
	//
	// Use mockcard's echo INS (0xFD), which returns SW=9000 with the
	// data echoed back. R-MAC and R-ENC are applied per GP SCP03
	// §6.2.4 only to 9000/62XX/63XX responses, so the replay-rejection
	// test exercises the path the spec actually authenticates. Error
	// status words (6Axx, 6Dxx, ...) are NOT R-MAC-protected per spec,
	// so a replay of an error response is undetectable at the
	// protocol layer — that's a known protocol-level limitation, not
	// a library bug.
	probe := &apdu.Command{CLA: 0x00, INS: 0xFD, P1: 0x00, P2: 0x00, Data: []byte{0xAA, 0xBB, 0xCC, 0xDD}}

	resp1, err := sess.Transmit(ctx, probe)
	if err != nil {
		// Mockcard may not implement GET DATA; what matters is that
		// the round trip COMPLETED (R-MAC verified). If err comes
		// from MAC failure, the test is invalid.
		if strings.Contains(err.Error(), "R-MAC") {
			t.Fatalf("first Transmit failed at MAC verification — relay setup wrong: %v", err)
		}
		// SW errors (6D00 etc.) come back as a non-nil response with
		// non-success SW; if Transmit itself returned an error, log
		// it but keep going — the secure channel itself is healthy
		// as long as the next step's setup is OK.
		t.Logf("first Transmit returned %v (non-MAC error tolerated)", err)
	}
	_ = resp1

	// Arm the replay: the next response from respCh will be replaced
	// with the captured prior response. The endpoint goroutine still
	// processes the request normally — but the relay swaps in the
	// stale bytes before they reach the server side.
	rt.armReplay()

	// Second Transmit: must fail at R-MAC verification. The library
	// expects a fresh response with R-MAC over the advanced counter;
	// the replayed bytes were MAC'd against the OLD counter.
	_, err = sess.Transmit(ctx, probe)
	if err == nil {
		t.Fatal("second Transmit (with replayed response) returned no error — replay was accepted")
	}
	if !strings.Contains(err.Error(), "R-MAC") &&
		!strings.Contains(err.Error(), "MAC verification") &&
		!strings.Contains(err.Error(), "tamper") {
		t.Errorf("second Transmit failed but not for MAC reasons: %v", err)
	} else {
		t.Logf("replay rejected (as required): %v", err)
	}

	// After a MAC failure, GP §4.8 requires the session to be torn
	// down and key material zeroed. scp11.Transmit's error path
	// calls s.Close(); a follow-up Transmit must fail at the
	// "secure channel not established" gate, not silently re-open
	// the channel or proceed with stale keys.
	_, followUpErr := sess.Transmit(ctx, probe)
	if followUpErr == nil {
		t.Error("follow-up Transmit after MAC failure should fail (session must be torn down)")
	}

	// Tear down. The session may already be unusable post-MAC-failure;
	// Close should still be safe to call.
	sess.Close()
	rt.Close()
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Error("endpoint did not exit after relay close")
	}
}

// replayingRelayTransport is the same shape as the relay from PR #22
// with one extra capability: armReplay() makes the next Transmit
// return the previously-observed response bytes instead of
// forwarding the fresh ones from the endpoint. The endpoint still
// processes the request (so the card state advances normally); only
// what the server sees is replaced.
//
// This models a realistic threat: a network attacker or a
// compromised endpoint that has recorded prior responses and
// replays them. It does not require the card to be malicious or
// even unusual — only the bus to be untrustworthy.
type replayingRelayTransport struct {
	reqCh  chan<- []byte
	respCh <-chan []byte

	mu          sync.Mutex
	closed      bool
	lastResp    []byte
	replayArmed bool
	tracer      func(req, resp []byte, replayed bool)
}

func (r *replayingRelayTransport) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
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

func (r *replayingRelayTransport) TransmitRaw(ctx context.Context, raw []byte) ([]byte, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, errors.New("replayingRelayTransport: closed")
	}
	armed := r.replayArmed
	// Copy the bytes — not just the slice header — because the
	// capture path later in this function reuses r.lastResp's
	// backing array via append(...[:0], fresh...). Without a copy,
	// stale and r.lastResp alias the same memory and the "stale"
	// bytes get clobbered before we return them. Diagnosed by
	// observing that the replay never actually changed what the
	// session saw — it kept getting the fresh response.
	var stale []byte
	if len(r.lastResp) > 0 {
		stale = append([]byte(nil), r.lastResp...)
	}
	r.mu.Unlock()

	// The endpoint still processes the request unconditionally;
	// the relay just decides whether to forward the fresh response
	// or substitute a stale one before returning to the caller.
	select {
	case r.reqCh <- raw:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var fresh []byte
	select {
	case resp, ok := <-r.respCh:
		if !ok {
			return nil, errors.New("replayingRelayTransport: endpoint closed")
		}
		fresh = resp
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tracer != nil {
		r.tracer(raw, fresh, armed && len(stale) > 0)
	}
	// Only capture for replay AFTER the handshake is complete. The
	// handshake itself advances the secure-channel state, so we want
	// our captured "good" response to be a post-handshake one. The
	// simplest heuristic: capture the last response that came back
	// with secure-messaging CLA bit set on the request (0x04 in
	// raw[0]). If the endpoint goroutine ever returns a response to
	// a non-SM request, that's a handshake APDU; don't capture it.
	if len(raw) > 0 && (raw[0]&0x04) != 0 {
		r.lastResp = append(r.lastResp[:0], fresh...)
	}

	if armed && len(stale) > 0 {
		r.replayArmed = false
		// Return the stale bytes; the fresh response was consumed
		// to keep the endpoint goroutine moving but is otherwise
		// discarded.
		return stale, nil
	}
	return fresh, nil
}

func (r *replayingRelayTransport) armReplay() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replayArmed = true
}

func (r *replayingRelayTransport) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	close(r.reqCh)
	return nil
}

var _ transport.Transport = (*replayingRelayTransport)(nil)
