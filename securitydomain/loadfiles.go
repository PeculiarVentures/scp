package securitydomain

import (
	"context"
	"errors"
)

// LoadFilesResult is the result of GetStatusLoadFiles. The
// Modules-included path is preferred (P1=0x10), but cards that
// don't support it fall back to LoadFiles-only (P1=0x20). The
// Scope field reports which path actually returned the data so
// callers can inform the operator that module names are absent
// from this card's response.
type LoadFilesResult struct {
	Entries []RegistryEntry
	Scope   StatusScope
}

// GetStatusLoadFiles retrieves the Executable Load Files registry
// from the card, preferring the Modules-included scope (P1=0x10)
// and falling back to LoadFiles-only (P1=0x20) when the card
// rejects the first request as unsupported.
//
// Fallback triggers on SW=6A86 (incorrect P1/P2) and SW=6D00
// (instruction not supported on this CLA), the two real-card
// signals that the LoadFilesAndModules scope is not accepted.
// Other failure modes (auth required, transport error, no
// entries) propagate without retry: a 6A88 means "no load files
// at all," not "the request shape is wrong."
//
// The fallback exists because some cards (a subset of older
// JCOPs and various low-end Java Card runtimes) only honor the
// LoadFiles-only form; the host-side workaround is one extra
// round trip in exchange for partial data (load file AIDs and
// versions, no module enumeration).
func (s *Session) GetStatusLoadFiles(ctx context.Context) (LoadFilesResult, error) {
	if entries, err := s.GetStatus(ctx, StatusScopeLoadFilesAndModules); err == nil {
		return LoadFilesResult{Entries: entries, Scope: StatusScopeLoadFilesAndModules}, nil
	} else if !isUnsupportedScopeError(err) {
		return LoadFilesResult{}, err
	}
	entries, err := s.GetStatus(ctx, StatusScopeLoadFiles)
	if err != nil {
		return LoadFilesResult{}, err
	}
	return LoadFilesResult{Entries: entries, Scope: StatusScopeLoadFiles}, nil
}

// isUnsupportedScopeError reports whether err signals that the
// card rejected the request because it doesn't accept this scope
// variant — as distinct from any other failure (auth, transport,
// truly empty registry).
//
// SW=6A86 (incorrect P1/P2) and SW=6D00 (INS not supported on
// this CLA) are the GP-spec rejection signals for an unsupported
// scope; SW=6A88 is "no entries in this scope," which is success
// from the request-shape viewpoint and must not trigger fallback.
func isUnsupportedScopeError(err error) bool {
	var ae *APDUError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.SW == 0x6A86 || ae.SW == 0x6D00
}
