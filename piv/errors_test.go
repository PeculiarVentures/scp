package piv

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCardErrorString(t *testing.T) {
	e := NewCardError("VERIFY PIN", 0x63C2, "")
	got := e.Error()
	if !strings.Contains(got, "VERIFY PIN") || !strings.Contains(got, "63C2") {
		t.Errorf("Error() = %q, want operation and SW present", got)
	}
	if !strings.Contains(got, "2 retries remaining") {
		t.Errorf("Error() = %q, want retries-remaining description", got)
	}

	e2 := NewCardError("PUT CERTIFICATE", 0x6982, "extra context")
	if !strings.Contains(e2.Error(), "extra context") {
		t.Errorf("Error() = %q, want extra context appended", e2.Error())
	}
}

func TestStatusWord(t *testing.T) {
	e := NewCardError("X", 0x6A82, "")
	sw, ok := StatusWord(e)
	if !ok || sw != 0x6A82 {
		t.Errorf("StatusWord = (%04X, %v), want (6A82, true)", sw, ok)
	}

	// Wrapped CardError still reachable via errors.As.
	wrapped := fmt.Errorf("outer: %w", e)
	sw, ok = StatusWord(wrapped)
	if !ok || sw != 0x6A82 {
		t.Errorf("wrapped StatusWord = (%04X, %v), want (6A82, true)", sw, ok)
	}

	// Non-CardError returns ok=false.
	if _, ok := StatusWord(errors.New("plain error")); ok {
		t.Error("plain error reported as having a status word")
	}
	if _, ok := StatusWord(nil); ok {
		t.Error("nil reported as having a status word")
	}
}

func TestRetriesRemaining(t *testing.T) {
	cases := []struct {
		sw       uint16
		want     int
		wantOK   bool
	}{
		{0x63C0, 0, true},
		{0x63C1, 1, true},
		{0x63C5, 5, true},
		{0x63CF, 15, true},
		{0x6982, 0, false},
		{0x9000, 0, false},
	}
	for _, c := range cases {
		e := NewCardError("X", c.sw, "")
		got, ok := RetriesRemaining(e)
		if ok != c.wantOK {
			t.Errorf("RetriesRemaining(SW=%04X) ok = %v, want %v", c.sw, ok, c.wantOK)
		}
		if ok && got != c.want {
			t.Errorf("RetriesRemaining(SW=%04X) = %d, want %d", c.sw, got, c.want)
		}
	}
}

func TestIsWrongPIN(t *testing.T) {
	if !IsWrongPIN(NewCardError("VERIFY PIN", 0x63C2, "")) {
		t.Error("63C2 should be wrong PIN")
	}
	if IsWrongPIN(NewCardError("VERIFY PIN", 0x63C0, "")) {
		t.Error("63C0 should be blocked, not wrong PIN")
	}
	if IsWrongPIN(NewCardError("X", 0x6982, "")) {
		t.Error("6982 should not be wrong PIN")
	}
	if IsWrongPIN(nil) {
		t.Error("nil should not be wrong PIN")
	}
}

func TestIsPINBlocked(t *testing.T) {
	cases := []struct {
		sw   uint16
		want bool
	}{
		{0x6983, true},
		{0x63C0, true},
		{0x63C1, false},
		{0x6982, false},
		{0x9000, false},
	}
	for _, c := range cases {
		got := IsPINBlocked(NewCardError("X", c.sw, ""))
		if got != c.want {
			t.Errorf("IsPINBlocked(SW=%04X) = %v, want %v", c.sw, got, c.want)
		}
	}
	if IsPINBlocked(nil) {
		t.Error("nil should not be PIN blocked")
	}
	// IsPUKBlocked is an SW-level alias for IsPINBlocked.
	if !IsPUKBlocked(NewCardError("X", 0x6983, "")) {
		t.Error("IsPUKBlocked should match 6983")
	}
}

func TestIsAuthRequired(t *testing.T) {
	if !IsAuthRequired(ErrNotAuthenticated) {
		t.Error("ErrNotAuthenticated should be auth-required")
	}
	if !IsAuthRequired(NewCardError("X", 0x6982, "")) {
		t.Error("6982 should be auth-required")
	}
	if !IsAuthRequired(fmt.Errorf("wrapped: %w", ErrNotAuthenticated)) {
		t.Error("wrapped ErrNotAuthenticated should be auth-required")
	}
	if IsAuthRequired(NewCardError("X", 0x9000, "")) {
		t.Error("9000 should not be auth-required")
	}
}

func TestIsUnsupportedInstruction(t *testing.T) {
	if !IsUnsupportedInstruction(NewCardError("ATTEST", 0x6D00, "")) {
		t.Error("6D00 should be unsupported instruction")
	}
	if IsUnsupportedInstruction(NewCardError("X", 0x6A82, "")) {
		t.Error("6A82 should not be unsupported instruction")
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(NewCardError("GET CERT", 0x6A82, "")) {
		t.Error("6A82 should be not-found")
	}
	if IsNotFound(NewCardError("X", 0x6A80, "")) {
		t.Error("6A80 should not be not-found")
	}
}

func TestIsIncorrectData(t *testing.T) {
	if !IsIncorrectData(NewCardError("PUT", 0x6A80, "")) {
		t.Error("6A80 should be incorrect data")
	}
	if IsIncorrectData(NewCardError("X", 0x6982, "")) {
		t.Error("6982 should not be incorrect data")
	}
}

func TestIsUnsupportedByProfile(t *testing.T) {
	if !IsUnsupportedByProfile(ErrUnsupportedByProfile) {
		t.Error("ErrUnsupportedByProfile should match")
	}
	wrapped := fmt.Errorf("session refusal: %w", ErrUnsupportedByProfile)
	if !IsUnsupportedByProfile(wrapped) {
		t.Error("wrapped ErrUnsupportedByProfile should match")
	}
	if IsUnsupportedByProfile(NewCardError("X", 0x6D00, "")) {
		t.Error("6D00 (host-side unsupported) should not match profile sentinel")
	}
}
