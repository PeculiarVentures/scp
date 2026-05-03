package securitydomain

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/apdu"
	scp03 "github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/session"
)

// Compile-time assertions: both production session types must
// satisfy the unexported capability interfaces. A refactor that
// removes one of these methods will fail at build time, before any
// production code path silently degrades to the string-match
// fallback.
var (
	_ dekProvider  = (*session.Session)(nil)
	_ oceAuthState = (*session.Session)(nil)
	_ dekProvider  = (*scp03.Session)(nil)
	_ oceAuthState = (*scp03.Session)(nil)
)

// TestCapabilityInterfaces_ConcreteSessionsSatisfy is a runtime
// confirmation of the same property — kept as a test so it shows
// up in coverage reports and gives a concrete failure message if
// someone accidentally narrows the interface with a build tag.
func TestCapabilityInterfaces_ConcreteSessionsSatisfy(t *testing.T) {
	// Vacuous body — the var block above is the real assertion.
	// If this file compiles, the property holds.
	t.Log("compile-time: *session.Session and *scp03.Session satisfy dekProvider + oceAuthState")
}

// TestSessionOCEAuthenticated_TypedPath confirms the capability-
// interface path is preferred over Protocol() string matching when
// both are available. We construct a fake session that reports a
// nonsense protocol string but implements oceAuthState; the typed
// answer must win.
func TestSessionOCEAuthenticated_TypedPath(t *testing.T) {
	f := &fakeOCESession{proto: "SCP99-bogus", auth: true}
	if !sessionOCEAuthenticated(f) {
		t.Error("typed oceAuthState=true should win over unknown protocol string")
	}

	f2 := &fakeOCESession{proto: "SCP03", auth: false}
	if sessionOCEAuthenticated(f2) {
		t.Error("typed oceAuthState=false should win over recognized protocol string")
	}
}

// TestSessionOCEAuthenticated_FallbackPath confirms that a
// scp.Session that doesn't implement oceAuthState falls through to
// the conservative string match. This is the compatibility path
// for test doubles and any third-party Session adapter.
func TestSessionOCEAuthenticated_FallbackPath(t *testing.T) {
	f := &fakePlainSession{proto: "SCP11a"}
	if !sessionOCEAuthenticated(f) {
		t.Error("fallback should accept SCP11a as OCE-auth")
	}
	f2 := &fakePlainSession{proto: "SCP11b"}
	if sessionOCEAuthenticated(f2) {
		t.Error("fallback must reject SCP11b as OCE-auth")
	}
	f3 := &fakePlainSession{proto: "MysteryProtocol"}
	if sessionOCEAuthenticated(f3) {
		t.Error("fallback must reject unknown protocols (default-deny)")
	}
}

// TestSessionDEK_FallsBackToNil confirms a session that doesn't
// implement dekProvider yields a nil DEK (rather than panicking
// or reaching for some imagined method).
func TestSessionDEK_FallsBackToNil(t *testing.T) {
	f := &fakePlainSession{proto: "SCP11b"}
	if got := sessionDEK(f); got != nil {
		t.Errorf("sessionDEK on non-provider session must return nil, got %x", got)
	}
}

// fakeOCESession satisfies oceAuthState (and scp.Session minimally)
// to exercise the typed capability path.
type fakeOCESession struct {
	proto string
	auth  bool
}

func (f *fakeOCESession) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return nil, nil
}
func (f *fakeOCESession) Close()                  {}
func (f *fakeOCESession) Protocol() string        { return f.proto }
func (f *fakeOCESession) OCEAuthenticated() bool  { return f.auth }

// fakePlainSession is the opposite — minimum-viable scp.Session
// without any capability methods, to exercise the fallback path.
type fakePlainSession struct {
	proto string
}

func (f *fakePlainSession) Transmit(ctx context.Context, cmd *apdu.Command) (*apdu.Response, error) {
	return nil, nil
}
func (f *fakePlainSession) Close()           {}
func (f *fakePlainSession) Protocol() string { return f.proto }
