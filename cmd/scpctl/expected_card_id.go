package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/securitydomain"
)

// verifyExpectedCardID reads the card's CIN via GET DATA tag
// 0x0045 and compares it to the operator-supplied expected
// value. Returns nil on match, an error on mismatch or when
// the card does not expose CIN.
//
// The hex string accepts the same separators decodeHexAID does
// (space, tab, colon) so an operator can paste a CIN with
// readability separators without re-formatting.
//
// On match, records a PASS check on the report. On mismatch or
// absence, records a FAIL check. The returned error is suitable
// for short-circuiting the command path before any destructive
// APDU is sent.
//
// expected must be non-empty; an empty string is the caller's
// signal that the operator did not pass --expected-card-id, in
// which case the verification is skipped (returns nil) and no
// check is appended.
func verifyExpectedCardID(ctx context.Context, sd *securitydomain.Session, expected string, report *Report) error {
	if expected == "" {
		return nil
	}
	expectedBytes, err := hex.DecodeString(stripWhitespace(expected))
	if err != nil {
		report.Fail("expected-card-id", err.Error())
		return fmt.Errorf("--expected-card-id: %w", err)
	}
	if len(expectedBytes) == 0 {
		report.Fail("expected-card-id", "value is empty")
		return errors.New("--expected-card-id: value cannot be empty")
	}

	got, err := sd.GetCIN(ctx)
	if err != nil {
		if errors.Is(err, securitydomain.ErrCardIdentityMissing) {
			report.Fail("expected-card-id",
				"card does not expose CIN (GET DATA 0x0045 returned SW=6A88); cannot verify identity")
			return fmt.Errorf("--expected-card-id: %w", err)
		}
		report.Fail("expected-card-id", err.Error())
		return fmt.Errorf("--expected-card-id: %w", err)
	}

	if !bytes.Equal(got, expectedBytes) {
		report.Fail("expected-card-id",
			fmt.Sprintf("CIN mismatch: card=%s expected=%s",
				strings.ToUpper(hex.EncodeToString(got)),
				strings.ToUpper(hex.EncodeToString(expectedBytes))))
		return fmt.Errorf("--expected-card-id: card CIN %X does not match expected %X",
			got, expectedBytes)
	}

	report.Pass("expected-card-id",
		fmt.Sprintf("matched CIN %s", strings.ToUpper(hex.EncodeToString(got))))
	return nil
}
