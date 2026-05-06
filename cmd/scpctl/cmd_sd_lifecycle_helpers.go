package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// readISDLifecycle opens an unauthenticated Security Domain session
// and returns the current ISD lifecycle byte. Used by sd lock /
// unlock / terminate as a pre-flight check so the command can:
//
//   - Skip a no-op transition (e.g. lock when already CARD_LOCKED).
//   - Refuse to operate on a TERMINATED card (no recovery is possible).
//   - Report a meaningful "before" value in the per-command output.
//
// Cards that require authentication for ISD GET STATUS surface the
// error here. In that case the lifecycle commands proceed without a
// pre-check (the destructive path will surface authentication or
// transition errors at SET STATUS time anyway). The caller treats a
// nil error as authoritative; an error means "couldn't read, proceed
// with reduced safety."
func readISDLifecycle(ctx context.Context, t transport.Transport) (securitydomain.LifecycleState, error) {
	sd, err := securitydomain.OpenUnauthenticated(ctx, t, nil)
	if err != nil {
		return 0, fmt.Errorf("open unauthenticated SD: %w", err)
	}
	defer sd.Close()

	entries, err := sd.GetStatus(ctx, securitydomain.StatusScopeISD)
	if err != nil {
		return 0, fmt.Errorf("GET STATUS ISD: %w", err)
	}
	if len(entries) == 0 {
		// Empty registry for this scope — should not happen on a
		// real card (the ISD always exists) but possible on cards
		// that gate even ISD reads behind auth and return an empty
		// rather than 6A88. Treat as "couldn't read."
		return 0, fmt.Errorf("ISD GET STATUS returned no entries")
	}
	return securitydomain.LifecycleState(entries[0].Lifecycle), nil
}
