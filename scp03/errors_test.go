package scp03_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
)

// TestErrInvalidConfig_NilConfig confirms passing a nil Config to
// scp03.Open returns an error that errors.Is matches as
// ErrInvalidConfig. The descriptive message is preserved alongside
// the sentinel chain.
func TestErrInvalidConfig_NilConfig(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	_, err := scp03.Open(context.Background(), card.Transport(), nil)
	if err == nil {
		t.Fatal("expected error for nil Config; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
	// The descriptive substring should still appear so logs and
	// debug output remain useful.
	if !strings.Contains(err.Error(), "Config is required") {
		t.Errorf("error should retain descriptive context; got: %v", err)
	}
}

// TestErrInvalidConfig_NilTransport confirms a missing transport is
// reported as ErrInvalidConfig, matching the rest of the caller-error
// category.
func TestErrInvalidConfig_NilTransport(t *testing.T) {
	_, err := scp03.Open(context.Background(), nil, &scp03.Config{Keys: scp03.DefaultKeys})
	if err == nil {
		t.Fatal("expected error for nil transport; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestErrInvalidConfig_KeysizeMismatch confirms a Config with
// inconsistent key lengths is reported as ErrInvalidConfig.
func TestErrInvalidConfig_KeysizeMismatch(t *testing.T) {
	bad := scp03.StaticKeys{
		ENC: make([]byte, 16),
		MAC: make([]byte, 32), // mismatched
		DEK: make([]byte, 16),
	}
	card := scp03.NewMockCard(scp03.DefaultKeys)
	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{Keys: bad})
	if err == nil {
		t.Fatal("expected error for mismatched key lengths; got nil")
	}
	if !errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
	}
}

// TestErrAuthFailed_WrongKeys confirms a handshake against a card
// that holds a different key set is reported as ErrAuthFailed,
// distinct from ErrInvalidConfig and ErrInvalidResponse. Mirrors the
// pattern in TestSCP03_WrongKeys but adds the errors.Is assertion.
func TestErrAuthFailed_WrongKeys(t *testing.T) {
	// The mock card holds the well-known DefaultKeys (0x40..0x4F).
	card := scp03.NewMockCard(scp03.DefaultKeys)

	// The caller authenticates with a different key set, well-formed
	// but not matching the card.
	wrongKeys := scp03.StaticKeys{
		ENC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		MAC: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		DEK: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	}
	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: wrongKeys,
	})
	if err == nil {
		t.Fatal("expected error for wrong keys; got nil")
	}
	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}
	if errors.Is(err, scp03.ErrInvalidConfig) {
		t.Errorf("ErrAuthFailed must not be confused with ErrInvalidConfig; err = %v", err)
	}
}

// TestSentinelsAreDistinct guards against accidentally aliasing two
// sentinels to the same value, which would defeat the whole point of
// having distinct categories.
func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{scp03.ErrAuthFailed, scp03.ErrInvalidConfig, scp03.ErrInvalidResponse}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels at index %d and %d compare equal: %v == %v", i, j, a, b)
			}
		}
	}
}

// TestCryptogramMismatchError_FieldsAndError pins the new rich
// auth-failure shape. Builds a CryptogramMismatchError directly,
// asserts that the bytes round-trip on the value, that errors.Is
// against ErrAuthFailed succeeds (so existing callers using
// errors.Is(err, ErrAuthFailed) continue to match), and that the
// rendered Error() string carries both bytes plus the brick-risk
// warning so log lines stay informative.
func TestCryptogramMismatchError_FieldsAndError(t *testing.T) {
	cm := &scp03.CryptogramMismatchError{
		Expected: []byte{0xB2, 0xF3, 0x92, 0xD2, 0xCF, 0xB9, 0xA4, 0x59},
		Received: []byte{0x76, 0x53, 0x2D, 0x72, 0xCF, 0x9D, 0xE0, 0x5F},
	}

	// errors.Is via ErrAuthFailed.
	if !errors.Is(cm, scp03.ErrAuthFailed) {
		t.Errorf("CryptogramMismatchError should errors.Is as ErrAuthFailed")
	}

	// errors.As against the concrete type for byte recovery.
	var got *scp03.CryptogramMismatchError
	if !errors.As(error(cm), &got) {
		t.Fatal("errors.As should recover the concrete type")
	}
	if string(got.Expected) != string(cm.Expected) {
		t.Errorf("Expected bytes mismatch: got %X want %X", got.Expected, cm.Expected)
	}
	if string(got.Received) != string(cm.Received) {
		t.Errorf("Received bytes mismatch: got %X want %X", got.Received, cm.Received)
	}

	// Rendered message must include both bytes (uppercase hex,
	// matching gppro) and the brick-risk warning.
	msg := cm.Error()
	for _, want := range []string{
		"B2F392D2CFB9A459", // expected
		"76532D72CF9DE05F", // received
		"Do not re-try",
		"counter",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() missing %q; got:\n%s", want, msg)
		}
	}
}

// TestCryptogramMismatchError_IsThroughWrap confirms the type
// continues to satisfy errors.Is(err, ErrAuthFailed) when wrapped
// behind another error in a fmt.Errorf %w chain. Pre-fix the
// callsite produced fmt.Errorf("%w: ...", ErrAuthFailed); post-fix
// it returns *CryptogramMismatchError directly. Both should
// behave the same for downstream callers using errors.Is.
func TestCryptogramMismatchError_IsThroughWrap(t *testing.T) {
	cm := &scp03.CryptogramMismatchError{
		Expected: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Received: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
	}
	wrapped := fmt.Errorf("opening session: %w", cm)

	if !errors.Is(wrapped, scp03.ErrAuthFailed) {
		t.Errorf("wrapped CryptogramMismatchError should errors.Is as ErrAuthFailed")
	}

	var got *scp03.CryptogramMismatchError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As should still recover the concrete type through wrap")
	}
	if got.Received[0] != 0x10 {
		t.Errorf("byte recovery failed through wrap: got %X", got.Received)
	}
}

// TestOpen_WrongKeys_SurfacesCryptogramBytes is the integration-
// level check. Drives a real handshake against the SCP03 mock with
// deliberately-wrong host keys. The mock's INITIALIZE UPDATE
// response includes a card cryptogram derived from the mock's
// configured (correct) keys; the host computes its own cryptogram
// from the wrong keys; the mismatch surfaces as a
// CryptogramMismatchError carrying both byte sequences.
func TestOpen_WrongKeys_SurfacesCryptogramBytes(t *testing.T) {
	// The mock card is configured with DefaultKeys.
	card := scp03.NewMockCard(scp03.DefaultKeys)

	// The host opens with a different key set. Both have to be
	// AES-128 (or all the same length) since scp03.Open enforces
	// uniform key length.
	wrongKeys := scp03.StaticKeys{
		ENC: bytes16(0xAA),
		MAC: bytes16(0xBB),
		DEK: bytes16(0xCC),
	}

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: wrongKeys,
	})
	if err == nil {
		t.Fatal("expected auth failure with mismatched keys; got nil")
	}

	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}

	var cm *scp03.CryptogramMismatchError
	if !errors.As(err, &cm) {
		t.Fatalf("errors.As should recover *CryptogramMismatchError; err = %v", err)
	}
	if len(cm.Expected) == 0 || len(cm.Received) == 0 {
		t.Errorf("CryptogramMismatchError should populate both byte slices; got expected=%X received=%X", cm.Expected, cm.Received)
	}
	if len(cm.Expected) != len(cm.Received) {
		t.Errorf("Expected and Received should have equal length (S8=8 or S16=16); got %d / %d", len(cm.Expected), len(cm.Received))
	}
	// They must differ — that's the whole point.
	if string(cm.Expected) == string(cm.Received) {
		t.Errorf("Expected and Received should differ on a key mismatch; both = %X", cm.Expected)
	}
}

// bytes16 returns a 16-byte slice filled with v. Test helper.
func bytes16(v byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = v
	}
	return out
}

// TestInitializeUpdateError_FieldsAndError pins the rendered shape
// of InitializeUpdateError for each SW the classifier knows about.
// Spec-grade SWs (6982, 6985) get the "not a key problem" framing;
// wrong-key SWs (6A88, 63Cx) get the bare message form so log
// noise doesn't get in the way when the diagnostic just says
// "wrong key, try a different one." Operators reading the rendered
// error can tell which class of failure they hit without parsing
// the SW themselves.
func TestInitializeUpdateError_FieldsAndError(t *testing.T) {
	cases := []struct {
		name     string
		sw1, sw2 byte
		want     []string
		notWant  []string
		retry    bool
	}{
		{
			name: "6982 policy block",
			sw1:  0x69, sw2: 0x82,
			want: []string{
				"SW=6982",
				"Security status not satisfied",
				"retrying with different keys will not help",
				"SD lifecycle",
			},
			retry: false,
		},
		{
			name: "6985 conditions of use",
			sw1:  0x69, sw2: 0x85,
			want: []string{
				"SW=6985",
				"Conditions of use not satisfied",
				"retrying with different keys will not help",
			},
			retry: false,
		},
		{
			name: "6A88 missing KVN",
			sw1:  0x6A, sw2: 0x88,
			want: []string{
				"SW=6A88",
				"Referenced data not found",
				"KIT",
			},
			notWant: []string{"will not help"}, // retry might help here
			retry:   true,
		},
		{
			name: "63CX counter remaining",
			sw1:  0x63, sw2: 0xC5,
			want: []string{
				"SW=63C5",
				"5 attempts remaining",
				"counter is decrementing",
			},
			notWant: []string{"will not help"},
			retry:   true,
		},
		{
			name: "unknown SW",
			sw1:  0x6F, sw2: 0x00,
			want: []string{
				"SW=6F00",
				"unknown to scp03 diagnostics",
				"retrying with different keys will not help",
			},
			retry: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			diag, retry := scp03.ClassifyInitUpdateSWForTest(c.sw1, c.sw2)
			if retry != c.retry {
				t.Errorf("retry flag = %v, want %v", retry, c.retry)
			}
			iue := &scp03.InitializeUpdateError{
				SW1: c.sw1, SW2: c.sw2,
				Diagnostic: diag, RetryDifferentKeys: retry,
			}
			msg := iue.Error()
			for _, want := range c.want {
				if !strings.Contains(msg, want) {
					t.Errorf("Error() should contain %q; got:\n%s", want, msg)
				}
			}
			for _, notWant := range c.notWant {
				if strings.Contains(msg, notWant) {
					t.Errorf("Error() should NOT contain %q for retry=%v; got:\n%s",
						notWant, retry, msg)
				}
			}

			// Sentinel chain.
			if !errors.Is(iue, scp03.ErrAuthFailed) {
				t.Error("InitializeUpdateError should errors.Is as ErrAuthFailed")
			}

			// SW() helper.
			wantSW := uint16(c.sw1)<<8 | uint16(c.sw2)
			if iue.SW() != wantSW {
				t.Errorf("SW() = 0x%04X, want 0x%04X", iue.SW(), wantSW)
			}
		})
	}
}

// TestInitializeUpdateError_DistinctFromCryptogramMismatch confirms
// the two rich error types are indeed distinct under errors.As, so
// callers branching on type can route 6982 (state-block) and
// cryptogram-mismatch (wrong keys) to different remediation
// guidance. Both still satisfy errors.Is(err, ErrAuthFailed) so
// existing callers don't break.
func TestInitializeUpdateError_DistinctFromCryptogramMismatch(t *testing.T) {
	iue := &scp03.InitializeUpdateError{
		SW1: 0x69, SW2: 0x82,
		Diagnostic:         "Security status not satisfied",
		RetryDifferentKeys: false,
	}
	cm := &scp03.CryptogramMismatchError{
		Expected: []byte{0x00, 0x01},
		Received: []byte{0x10, 0x11},
	}

	// Each type errors.As into itself but not into the other.
	var asIUE *scp03.InitializeUpdateError
	if !errors.As(error(iue), &asIUE) {
		t.Error("InitializeUpdateError should errors.As into InitializeUpdateError")
	}
	if errors.As(error(cm), &asIUE) {
		t.Error("CryptogramMismatchError should NOT errors.As into InitializeUpdateError")
	}

	var asCM *scp03.CryptogramMismatchError
	if !errors.As(error(cm), &asCM) {
		t.Error("CryptogramMismatchError should errors.As into CryptogramMismatchError")
	}
	if errors.As(error(iue), &asCM) {
		t.Error("InitializeUpdateError should NOT errors.As into CryptogramMismatchError")
	}

	// Both still match ErrAuthFailed.
	if !errors.Is(iue, scp03.ErrAuthFailed) {
		t.Error("InitializeUpdateError should errors.Is as ErrAuthFailed")
	}
	if !errors.Is(cm, scp03.ErrAuthFailed) {
		t.Error("CryptogramMismatchError should errors.Is as ErrAuthFailed")
	}
}

// TestOpen_InitializeUpdate6982_NotKeyProblem is the integration-
// level assertion that ChatGPT's parallel session against a
// real SafeNet Token JC motivated. When the card returns SW=6982
// to INITIALIZE UPDATE before any cryptogram exchange, scp03.Open
// must surface that as an InitializeUpdateError with
// RetryDifferentKeys=false and a diagnostic message that explicitly
// says retrying with different keys won't help. Operators triaging
// this case shouldn't burn another counter slot guessing keys.
func TestOpen_InitializeUpdate6982_NotKeyProblem(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	card.ForceInitUpdateSW = 0x6982 // Security status not satisfied

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: scp03.DefaultKeys,
	})
	if err == nil {
		t.Fatal("expected error when card returns 6982 on IU; got nil")
	}

	// Sentinel chain still matches.
	if !errors.Is(err, scp03.ErrAuthFailed) {
		t.Errorf("errors.Is(err, ErrAuthFailed) = false; err = %v", err)
	}

	// Concrete type recovers.
	var iue *scp03.InitializeUpdateError
	if !errors.As(err, &iue) {
		t.Fatalf("errors.As should recover *InitializeUpdateError; err = %v", err)
	}
	if iue.SW() != 0x6982 {
		t.Errorf("SW = 0x%04X, want 0x6982", iue.SW())
	}
	if iue.RetryDifferentKeys {
		t.Error("RetryDifferentKeys should be false for SW=6982")
	}

	// Should NOT also recover as a CryptogramMismatchError. Cards
	// that return 6982 before any cryptogram exchange aren't a
	// cryptogram-mismatch failure mode.
	var cm *scp03.CryptogramMismatchError
	if errors.As(err, &cm) {
		t.Error("err should not also recover as CryptogramMismatchError")
	}

	// Rendered message should explicitly say keys aren't the
	// gate, so log readers see the right next step.
	msg := err.Error()
	for _, want := range []string{"6982", "retrying with different keys will not help"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() should contain %q; got:\n%s", want, msg)
		}
	}
}

// TestOpen_InitializeUpdate6A88_RetryWithDifferentKVN confirms the
// retry-different-keys flag stays true when the SW indicates a
// missing key version (rather than a state lock). 6A88 means "the
// requested KVN isn't installed" — caller should investigate KIT
// and try a different KeyVersion, which is a sensible action that
// the diagnostic should encourage rather than discourage.
func TestOpen_InitializeUpdate6A88_RetryWithDifferentKVN(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	card.ForceInitUpdateSW = 0x6A88

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys: scp03.DefaultKeys,
	})
	if err == nil {
		t.Fatal("expected error when card returns 6A88 on IU; got nil")
	}

	var iue *scp03.InitializeUpdateError
	if !errors.As(err, &iue) {
		t.Fatalf("errors.As should recover *InitializeUpdateError; err = %v", err)
	}
	if !iue.RetryDifferentKeys {
		t.Error("RetryDifferentKeys should be true for SW=6A88 (missing KVN)")
	}

	// Rendered message should NOT carry the brick-ish "won't help"
	// language since retry might in fact succeed with a different
	// KVN.
	msg := err.Error()
	if strings.Contains(msg, "will not help") {
		t.Errorf("Error() should NOT discourage retry for 6A88; got:\n%s", msg)
	}
}

// TestInitializeUpdateError_ContextFields confirms the attempt
// context fields (KeyVersion, KeyIdentifier, AID, SCP) round-trip
// through scp03.Open and surface in the rendered error message.
// Operators iterating over key versions or P2 values can recover
// what was tried via errors.As without tracking it externally,
// and the rendered message includes the context inline so a
// single log line carries the full attempt picture.
func TestInitializeUpdateError_ContextFields(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	card.ForceInitUpdateSW = 0x6982

	wantAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00}

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: 0xFF,
		SelectAID:  wantAID,
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}

	var iue *scp03.InitializeUpdateError
	if !errors.As(err, &iue) {
		t.Fatalf("errors.As should recover *InitializeUpdateError; err = %v", err)
	}

	if iue.KeyVersion != 0xFF {
		t.Errorf("KeyVersion = 0x%02X, want 0xFF", iue.KeyVersion)
	}
	if iue.KeyIdentifier != 0x00 {
		t.Errorf("KeyIdentifier = 0x%02X, want 0x00 (SCP03 default for IU)", iue.KeyIdentifier)
	}
	if string(iue.AID) != string(wantAID) {
		t.Errorf("AID = %X, want %X", iue.AID, wantAID)
	}
	if iue.SCP != "SCP03" {
		t.Errorf("SCP = %q, want %q", iue.SCP, "SCP03")
	}

	// Rendered message should carry KV, P2, and AID inline so log
	// readers see the attempt context next to the SW.
	msg := iue.Error()
	for _, want := range []string{"SW=6982", "KV=FF", "P2=00", "AID=A000000018434D00"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() should contain %q; got:\n%s", want, msg)
		}
	}
}

// TestInitializeUpdateError_ContextFields_NoSelectAID confirms the
// AID field stays empty (rather than getting populated with garbage)
// when the caller did SELECT externally and didn't supply a
// Config.SelectAID. The rendered error then omits the AID= portion
// of the context suffix rather than rendering "AID=" with empty hex.
func TestInitializeUpdateError_ContextFields_NoSelectAID(t *testing.T) {
	card := scp03.NewMockCard(scp03.DefaultKeys)
	card.ForceInitUpdateSW = 0x6982

	_, err := scp03.Open(context.Background(), card.Transport(), &scp03.Config{
		Keys:       scp03.DefaultKeys,
		KeyVersion: 0x01,
		// No SelectAID; caller did SELECT externally.
	})
	if err == nil {
		t.Fatal("expected error; got nil")
	}

	var iue *scp03.InitializeUpdateError
	if !errors.As(err, &iue) {
		t.Fatalf("errors.As should recover *InitializeUpdateError; err = %v", err)
	}

	if len(iue.AID) != 0 {
		t.Errorf("AID should be empty when SelectAID is not configured; got %X", iue.AID)
	}

	msg := iue.Error()
	if strings.Contains(msg, "AID=") {
		t.Errorf("Error() should NOT contain 'AID=' when AID is empty; got:\n%s", msg)
	}
	// KV and P2 should still appear since they're always known.
	for _, want := range []string{"KV=01", "P2=00"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() should still contain %q; got:\n%s", want, msg)
		}
	}
}
