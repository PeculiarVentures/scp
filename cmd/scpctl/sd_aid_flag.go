package main

import "fmt"

// decodeSDAIDFlag decodes the --sd-aid CLI flag value into bytes.
// Empty string means "use the GP-default ISD AID"; the returned
// nil slice signals callers to fall through to whatever default
// the underlying API uses (securitydomain.AIDSecurityDomain for
// OpenUnauthenticated, scp03.Config.SelectAID nil for OpenSCP03,
// etc.).
//
// Validates length per ISO/IEC 7816-5 (5..16 bytes) so a typo'd
// AID fails fast at flag-parse time rather than mid-flow on a
// SELECT response. Decoding tolerates space and colon separators
// like all other AID flags in scpctl.
func decodeSDAIDFlag(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	aid, err := decodeHexAID(value, "sd-aid")
	if err != nil {
		return nil, fmt.Errorf("--sd-aid: %w", err)
	}
	return aid, nil
}
