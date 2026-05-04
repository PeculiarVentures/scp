package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/transport/pcsc"
)

// connectFunc is how subcommands obtain a transport from a reader name.
// Tests substitute their own implementation that returns a mockcard
// transport instead of going through PC/SC.
//
// readerName may be empty, in which case the connector picks the
// first reader (per pcsc.OpenFirstReader's contract) or returns an
// informative error.
type connectFunc func(ctx context.Context, readerName string) (transport.Transport, error)

// pcscConnect is the production implementation of connectFunc, going
// through the OS PC/SC service.
//
// On Linux this requires pcsc-lite to be installed and pcscd running;
// on macOS and Windows PC/SC is built in. See the transport/pcsc
// package documentation for details.
func pcscConnect(_ context.Context, readerName string) (transport.Transport, error) {
	if readerName == "" {
		t, err := pcsc.OpenFirstReader()
		if err != nil {
			return nil, fmt.Errorf("open first reader: %w", err)
		}
		return t, nil
	}

	// Substring match: callers commonly pass "YubiKey" rather than
	// the full reader-and-slot name.
	readers, err := pcsc.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("list readers: %w", err)
	}
	matched, err := matchReader(readers, readerName)
	if err != nil {
		return nil, err
	}
	t, err := pcsc.OpenReader(matched)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", matched, err)
	}
	return t, nil
}

// matchReader picks a reader by case-sensitive substring. If the
// substring matches more than one reader, the call fails — picking
// arbitrarily would silently target a different YubiKey than the
// user has plugged in next time. Exact matches always win over
// substring matches; a user who wants a specific reader can pass
// its full name.
func matchReader(readers []string, query string) (string, error) {
	if len(readers) == 0 {
		return "", fmt.Errorf("no PC/SC readers connected")
	}
	for _, r := range readers {
		if r == query {
			return r, nil
		}
	}
	var matches []string
	for _, r := range readers {
		if contains(r, query) {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no reader matches %q (have: %v)", query, readers)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%q matches multiple readers (%v); pass a more specific name",
			query, matches)
	}
}

// contains is a substring check. We avoid strings.Contains in this
// file purely to keep imports small; it's a one-line helper.
func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
