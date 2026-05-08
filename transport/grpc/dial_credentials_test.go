package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestDial_FailsClosedOnNoCredentials pins the post-2026 default:
// Dial with empty GRPCDialOptions and AllowInsecure=false must
// refuse the dial. The previous behavior silently fell through to
// insecure credentials, which is a production foot-gun — any
// deployment forgetting to pass mTLS would silently get plaintext
// APDU relay.
//
// The error message must point the caller at both correct shapes
// (production: pass GRPCDialOptions with TLS; dev/lab: set
// AllowInsecure=true) so the operator debugging the dial doesn't
// have to consult docs.
func TestDial_FailsClosedOnNoCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := Dial(ctx, DialOptions{
		Target: "localhost:9999",
		// no GRPCDialOptions, no AllowInsecure: this is the
		// foot-gun the new check refuses.
	})
	if err == nil {
		t.Fatal("Dial: expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no transport credentials configured") {
		t.Errorf("Dial error: %q does not surface the no-credentials cause", msg)
	}
	// The error must point the caller at both correct shapes.
	if !strings.Contains(msg, "GRPCDialOptions") {
		t.Errorf("Dial error: %q does not name the production option", msg)
	}
	if !strings.Contains(msg, "AllowInsecure") {
		t.Errorf("Dial error: %q does not name the dev/lab option", msg)
	}
}

// TestDial_AcceptsExplicitInsecureOptIn pins that AllowInsecure=true
// with empty GRPCDialOptions is accepted, going through the dial.
// The dial itself fails downstream because there's no server at the
// target, but Dial's credential resolution succeeds — meaning the
// fail-closed default did not trip.
//
// This is the dev/lab path. The caller has loudly opted in to
// plaintext APDU relay against a known-local server.
func TestDial_AcceptsExplicitInsecureOptIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := Dial(ctx, DialOptions{
		Target:        "localhost:1", // unlikely to have a server
		AllowInsecure: true,
	})
	// We expect a downstream connection or stream error here
	// (newClient will fail to open a session because no server
	// is listening). The thing we're explicitly NOT expecting is
	// the credentials-config error from the fail-closed path.
	if err == nil {
		t.Fatal("Dial: expected downstream error (no server), got nil")
	}
	if strings.Contains(err.Error(), "no transport credentials configured") {
		t.Errorf("Dial: AllowInsecure=true should bypass the credentials-config error; got %v", err)
	}
}

// TestDial_AcceptsExplicitTLSCredentials pins that non-empty
// GRPCDialOptions are passed through. Like the AllowInsecure
// case, the dial fails downstream because there's no server, but
// not from the credentials-config check.
func TestDial_AcceptsExplicitTLSCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := Dial(ctx, DialOptions{
		Target: "localhost:1",
		GRPCDialOptions: []grpc.DialOption{
			// In production this would be NewTLS(tlsConfig); for
			// the test we just need a non-empty option set so the
			// dial doesn't trip the no-credentials check. The
			// underlying connection will still fail.
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
	})
	if err == nil {
		t.Fatal("Dial: expected downstream error (no server), got nil")
	}
	if strings.Contains(err.Error(), "no transport credentials configured") {
		t.Errorf("Dial: GRPCDialOptions present should bypass the credentials-config error; got %v", err)
	}
}

// TestDial_RejectsConflictingCredentials pins that setting both
// GRPCDialOptions AND AllowInsecure=true is a configuration error.
// The dial refuses rather than guess which the caller meant —
// either path is potentially correct on its own, but the
// combination indicates the caller has not made a clear choice
// between production and dev/lab modes.
func TestDial_RejectsConflictingCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := Dial(ctx, DialOptions{
		Target: "localhost:1",
		GRPCDialOptions: []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
		AllowInsecure: true,
	})
	if err == nil {
		t.Fatal("Dial: expected error from conflicting credentials, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("Dial: error does not name the conflict; got %v", err)
	}
}

// errorFor is a sanity helper to make sure errors.Is is what we
// expect when the caller propagates these errors. Not every error
// here is backed by a sentinel (some are inline errors.New); the
// helper exists so future error-classification work has a place
// to grow.
func errorFor(t *testing.T, want error) func(error) bool {
	t.Helper()
	return func(got error) bool { return errors.Is(got, want) }
}

var _ = errorFor // suppresses unused-helper warnings in this revision
