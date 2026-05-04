package scp03

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/channel"
	"github.com/PeculiarVentures/scp/transport"
)

// erroringTransport rejects every command. Used to drive Open past
// the SecurityLevel validation without needing a real card.
type erroringTransport struct{}

func (erroringTransport) Transmit(_ context.Context, _ *apdu.Command) (*apdu.Response, error) {
	return nil, errors.New("erroringTransport: no card")
}
func (erroringTransport) TransmitRaw(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("erroringTransport: no card")
}
func (erroringTransport) Close() error { return nil }

// TestOpen_RejectsCDECWithoutCMAC confirms SCP03 refuses to negotiate
// command encryption without command authentication. See the doc on
// Config.InsecureAllowPartialSecurityLevel for why this matters.
func TestOpen_RejectsCDECWithoutCMAC(t *testing.T) {
	cfg := &Config{
		Keys:          DefaultKeys,
		KeyVersion:    0xFF,
		SecurityLevel: channel.LevelCDEC, // C-DEC alone, no C-MAC
	}
	_, err := Open(context.Background(), NewMockCard(DefaultKeys).Transport(), cfg)
	if err == nil {
		t.Fatal("Open with C-DEC sans C-MAC should fail; got success")
	}
	if !strings.Contains(err.Error(), "C-DEC without C-MAC") {
		t.Errorf("error should mention partial-security combination; got: %v", err)
	}
}

// TestOpen_RejectsRENCWithoutRMAC confirms the response-side variant
// of the partial-security check.
func TestOpen_RejectsRENCWithoutRMAC(t *testing.T) {
	cfg := &Config{
		Keys:          DefaultKeys,
		KeyVersion:    0xFF,
		SecurityLevel: channel.LevelCMAC | channel.LevelCDEC | channel.LevelRENC, // R-ENC alone, no R-MAC
	}
	_, err := Open(context.Background(), NewMockCard(DefaultKeys).Transport(), cfg)
	if err == nil {
		t.Fatal("Open with R-ENC sans R-MAC should fail; got success")
	}
	if !strings.Contains(err.Error(), "R-ENC without R-MAC") {
		t.Errorf("error should mention partial-security combination; got: %v", err)
	}
}

// TestOpen_AllowsPartialSecurityWithEscapeHatch confirms the
// InsecureAllowPartialSecurityLevel knob bypasses the safety check.
// Earning that bypass is the point of the deliberately ugly name.
// We expect Open to fail later (the stub transport rejects every
// command) but NOT on the SecurityLevel validation.
func TestOpen_AllowsPartialSecurityWithEscapeHatch(t *testing.T) {
	cfg := &Config{
		Keys:                              DefaultKeys,
		KeyVersion:                        0xFF,
		SecurityLevel:                     channel.LevelCDEC,
		InsecureAllowPartialSecurityLevel: true,
	}
	tr := &erroringTransport{}
	_, err := Open(context.Background(), tr, cfg)
	if err == nil {
		t.Fatal("Open with erroring transport should have failed eventually")
	}
	if strings.Contains(err.Error(), "C-DEC without C-MAC") {
		t.Errorf("escape hatch should bypass partial-security check; got: %v", err)
	}
	if strings.Contains(err.Error(), "R-ENC without R-MAC") {
		t.Errorf("escape hatch should bypass partial-security check; got: %v", err)
	}
}

func (erroringTransport) TrustBoundary() transport.TrustBoundary {
	return transport.TrustBoundaryUnknown
}
