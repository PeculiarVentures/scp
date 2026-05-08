package session

import (
	"context"
	"errors"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/piv/profile"
)

// goldKeyStyleTransmitter models a card that responds to SELECT
// AID PIV with SW=61xx (application property template fetched
// separately via GET RESPONSE) rather than 9000 inline. This is
// the response shape observed against a GoldKey Security PIV
// Token (ATR 3B941881B1807D1F0319C80050DC) during real-card
// testing. PR #150 fixed the bug class in piv/profile/probe.go;
// this fixture exercises the parallel piv/session path.
type goldKeyStyleTransmitter struct {
	appPropTemplate []byte
	selectCalls     int
	getRespCalls    int
}

func (g *goldKeyStyleTransmitter) Transmit(_ context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	switch cmd.INS {
	case 0xA4: // SELECT AID
		g.selectCalls++
		l := len(g.appPropTemplate)
		if l > 0xFF {
			l = 0xFF
		}
		return &apdu.Response{SW1: 0x61, SW2: byte(l)}, nil
	case 0xC0: // GET RESPONSE
		g.getRespCalls++
		return &apdu.Response{
			Data: append([]byte(nil), g.appPropTemplate...),
			SW1:  0x90, SW2: 0x00,
		}, nil
	default:
		return &apdu.Response{SW1: 0x6D, SW2: 0x00}, nil
	}
}

// TestNew_Follows61xxChainOnSelectAIDPIV is the regression for the
// session-layer parallel of #150. Pre-fix, a GoldKey-style card
// caused session.New to fail with 'piv/session: SELECT AID PIV
// failed (SW=61xx)' because selectPIV used bare tx.Transmit. Post-
// fix, the chain is followed and the session opens normally.
func TestNew_Follows61xxChainOnSelectAIDPIV(t *testing.T) {
	// Synthetic 30-byte app property template — content doesn't
	// matter for the regression, only that the chain is followed.
	appProp := make([]byte, 30)
	tx := &goldKeyStyleTransmitter{appPropTemplate: appProp}

	// SkipProbe=true forces the path through New's selectPIV +
	// (no Probe). We supply an explicit profile so New doesn't
	// try to detect one.
	sess, err := New(context.Background(), tx, Options{
		Profile:   profile.NewStandardPIVProfile(),
		SkipProbe: true,
	})
	if err != nil {
		t.Fatalf("New should follow 61xx chain on SELECT AID PIV; got err = %v", err)
	}
	defer sess.Close()

	if tx.selectCalls != 1 {
		t.Errorf("selectCalls = %d, want 1", tx.selectCalls)
	}
	if tx.getRespCalls != 1 {
		t.Errorf("getRespCalls = %d, want 1 (the chain follow)", tx.getRespCalls)
	}
}

// TestNew_StillReportsHardSelectFailures confirms the fix didn't
// regress the legitimate 'no PIV applet' case. A card that returns
// SW=6A82 to both the full and truncated AID variants must still
// produce an error.
func TestNew_StillReportsHardSelectFailures(t *testing.T) {
	tx := &fixedSWTransmitter{sw: 0x6A82}
	_, err := New(context.Background(), tx, Options{
		Profile:   profile.NewStandardPIVProfile(),
		SkipProbe: true,
	})
	if err == nil {
		t.Fatal("expected error when SELECT returns 6A82 on both AID variants")
	}
}

type fixedSWTransmitter struct {
	sw uint16
}

func (f *fixedSWTransmitter) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	if f.sw == 0 {
		return nil, errors.New("fixedSWTransmitter: no SW configured")
	}
	return &apdu.Response{
		SW1: byte(f.sw >> 8),
		SW2: byte(f.sw),
	}, nil
}
