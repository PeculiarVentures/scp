package scp11

import (
	"strings"
	"testing"
)

// TestParseCertsFromStore_StrictRejectsMalformedEntry pins the
// load-bearing assertion of the post-2026 strict mode: when
// strict=true and the input contains a DER blob that fails to
// parse as X.509, parseCertsFromStore returns an error rather
// than silently dropping the malformed entry.
//
// External review (ChatGPT, May 2026) flagged the silent-skip
// behavior as too forgiving for production trust-policy
// enforcement: a card returning a malformed entry alongside a
// valid one would silently appear to validate via a shorter
// path, with the operator never seeing the malformed entry as
// anomalous.
//
// The strict mode is opt-in via Policy.RejectUnparseableCertEntries
// at the SCP11 call site; this test exercises the parser flag
// directly.
func TestParseCertsFromStore_StrictRejectsMalformedEntry(t *testing.T) {
	valid := generateSelfSignedCert(t).Raw
	// 0x30 0x82 starts a SEQUENCE with a 2-byte length, so
	// splitDER will consume 4+0x0010=20 bytes thinking they're
	// a DER element. The 16 garbage bytes that follow are NOT
	// a valid X.509 cert, so x509.ParseCertificate will reject
	// them. This is exactly the failure mode strict mode catches.
	garbage := []byte{0x30, 0x82, 0x00, 0x10}
	garbage = append(garbage, []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}...)
	concat := append([]byte{}, valid...)
	concat = append(concat, garbage...)

	_, err := parseCertsFromStore(concat, true)
	if err == nil {
		t.Fatal("strict mode: expected error, got nil")
	}
	// Error must surface the index, length, and leading bytes
	// of the failed entry so the operator can identify which
	// entry is anomalous without re-running with debug logging.
	msg := err.Error()
	if !strings.Contains(msg, "parse cert entry") {
		t.Errorf("error %q does not name the parse-cert-entry failure", msg)
	}
	if !strings.Contains(msg, "len=") {
		t.Errorf("error %q does not name the entry length", msg)
	}
	if !strings.Contains(msg, "leading bytes") {
		t.Errorf("error %q does not show the entry's leading bytes", msg)
	}
}

// TestParseCertsFromStore_PermissiveSkipsMalformedEntry pins
// that the legacy default (strict=false) preserves the pre-2026
// behavior: a malformed entry is silently skipped, and the
// remaining valid certs are returned.
//
// This is a regression test for the compatibility path — the
// post-2026 strict mode is purely opt-in, so callers that don't
// set Policy.RejectUnparseableCertEntries get byte-identical
// behavior to the pre-fix codebase.
func TestParseCertsFromStore_PermissiveSkipsMalformedEntry(t *testing.T) {
	valid := generateSelfSignedCert(t).Raw
	garbage := []byte{0x30, 0x82, 0x00, 0x10}
	garbage = append(garbage, []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}...)
	concat := append([]byte{}, valid...)
	concat = append(concat, garbage...)

	certs, err := parseCertsFromStore(concat, false)
	if err != nil {
		t.Fatalf("permissive mode: unexpected error %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("permissive mode: expected 1 cert (garbage skipped), got %d", len(certs))
	}
}

// TestParseCertsFromStore_StrictAcceptsAllValid pins that strict
// mode is no-overhead for well-formed input: a sequence of all-
// valid certs returns the same result as permissive mode.
func TestParseCertsFromStore_StrictAcceptsAllValid(t *testing.T) {
	cert1 := generateSelfSignedCert(t).Raw
	cert2 := generateSelfSignedCert(t).Raw
	concat := append([]byte{}, cert1...)
	concat = append(concat, cert2...)

	certs, err := parseCertsFromStore(concat, true)
	if err != nil {
		t.Fatalf("strict mode on all-valid input: unexpected error %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("strict mode on all-valid input: expected 2 certs, got %d", len(certs))
	}
}
