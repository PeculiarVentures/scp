package main

import (
	"context"
	"errors"
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
	sd, err := securitydomain.OpenUnauthenticated(ctx, t)
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

// extractLifecycleSW returns the raw status word a card returned
// for a failed SET STATUS, or 0 if err didn't originate from a
// card-side rejection (transport error, OCE-auth refusal, etc.).
//
// The lifecycle data structs (sdLockData, sdUnlockData,
// sdTerminateData) each carry a LastSW string field for JSON
// output; this helper is the single extraction point so all three
// commands populate that field consistently.
//
// Per the external review on feat/sd-keys-cli, Finding 10:
// 'lifecycle behavior varies across cards [...] the CLI should
// preserve raw lifecycle byte and raw SW in JSON for every failed
// transition.' The structured field lets an operator tell card-
// side rejections (6985 conditions of use, 6982 security status,
// 6A88 referenced data not found) apart from host-side encoding
// problems without parsing the human-readable Detail string.
//
// Returns the SW as an uppercase 4-digit hex string ("6985",
// "6A88") for direct inclusion in JSON, or "" if no LifecycleError
// could be unwrapped from err.
func extractLifecycleSW(err error) string {
	if err == nil {
		return ""
	}
	var lerr *securitydomain.LifecycleError
	if errors.As(err, &lerr) {
		return fmt.Sprintf("%04X", lerr.SW)
	}
	return ""
}
