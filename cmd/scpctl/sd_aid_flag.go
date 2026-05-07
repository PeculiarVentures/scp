package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
)

// sdAIDFlag is the parsed handle for --sd-aid. Resolves the operator-
// supplied hex string into a byte slice with length validation.
//
// ISO 7816-5 specifies AID length as 5-16 bytes (RID 5 + PIX 0-11),
// so this helper rejects anything outside that range as a usage
// error rather than letting it surface later as an opaque card-side
// 6A82 / 6A86.
//
// Per the external review on feat/sd-keys-cli, Finding 2.
type sdAIDFlag struct {
	raw *string
}

// registerSDAIDFlag binds --sd-aid to the given FlagSet and returns
// a handle the command body uses to fetch the parsed AID. The flag
// is always optional: empty value (the default) means "use the
// GP-standard ISD AID", and the resolved bytes are nil in that
// case so callers can pass them straight through to the *WithAID
// library variants.
//
// All generic SD commands (sd info, sd reset, sd lock/unlock/
// terminate, sd keys *, sd allowlist *) call this so the flag is
// uniform across the surface. Bootstrap commands targeting the ISD
// by definition (bootstrap-oce etc.) deliberately don't register
// it — there's no SSD bootstrap path today, and offering --sd-aid
// on a command that ignores it would be a footgun.
func registerSDAIDFlag(fs *flag.FlagSet) *sdAIDFlag {
	return &sdAIDFlag{
		raw: fs.String("sd-aid", "",
			"Hex-encoded Security Domain AID to target (5-16 bytes "+
				"per ISO 7816-5; spaces and colons accepted). Empty "+
				"defaults to the GP-standard Issuer Security Domain "+
				"AID A0000001510000. Use this flag to address "+
				"non-default ISDs on vendor-specific cards or "+
				"Supplementary Security Domains by AID. Must match "+
				"what the card actually advertises; the wrong AID "+
				"surfaces as 'select SD: card returned SW=6A82' "+
				"(file not found)."),
	}
}

// Resolve parses --sd-aid into a byte slice. Returns:
//
//   - (nil, nil) when the flag was empty (default ISD).
//   - (bytes, nil) when the flag parses cleanly into 5-16 bytes.
//   - (nil, *usageError) on hex parse error or length out of range.
//
// Callers can pass the (bytes, err) result through unchanged: nil
// matches the default-ISD semantics expected by Open*WithAID and
// profile.Probe; on error the *usageError surfaces correctly to
// the CLI's flag-error reporter.
//
// Whitespace and colons inside the hex string are tolerated so an
// operator can paste 'A0:00:00:01:51:00:00:00' or
// 'A0 00 00 01 51 00 00 00' or 'a0000001510000' interchangeably.
// The hex output is case-insensitive.
func (f *sdAIDFlag) Resolve() ([]byte, error) {
	if f == nil || f.raw == nil || *f.raw == "" {
		return nil, nil
	}
	cleaned := strings.NewReplacer(":", "", " ", "", "-", "").Replace(*f.raw)
	if len(cleaned)%2 != 0 {
		return nil, &usageError{
			msg: fmt.Sprintf("--sd-aid: hex string must have even length; got %d characters",
				len(cleaned)),
		}
	}
	aid, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, &usageError{
			msg: fmt.Sprintf("--sd-aid: invalid hex: %v", err),
		}
	}
	if len(aid) < 5 || len(aid) > 16 {
		return nil, &usageError{
			msg: fmt.Sprintf("--sd-aid: AID length %d out of range (ISO 7816-5: 5-16 bytes)",
				len(aid)),
		}
	}
	return aid, nil
}
