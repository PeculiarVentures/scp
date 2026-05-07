package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDInfo_Full_TextOutput populates the mock card's GP registry
// across all three scopes and verifies the human-readable output
// from 'sd info --full'.
func TestSDInfo_Full_TextOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle:  0x0F,
			Privileges: [3]byte{0xC0, 0x00, 0x00},
		},
	}
	mc.RegistryApps = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00},
			Lifecycle:  0x07,
			Privileges: [3]byte{0x00, 0x00, 0x00},
		},
	}
	mc.RegistryLoadFiles = []mockcard.MockRegistryEntry{
		{
			AID:       []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01},
			Lifecycle: 0x01,
			Version:   []byte{0x01, 0x02},
		},
	}
	out := runSDInfoFull(t, mc)

	for _, want := range []string{
		"scpctl sd info",
		"PASS",
		"GET STATUS scope=ISD",
		"1 entries",
		"A000000151000000",
		"GET STATUS scope=Applications",
		"GET STATUS scope=LoadFiles",
		"A0000006472F0001",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDInfo_Full_JSONOutput verifies the JSON shape of --full output:
// each scope under data.registry as a structured array.
func TestSDInfo_Full_JSONOutput(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{
			AID:        []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle:  0x0F,
			Privileges: [3]byte{0xC0, 0x00, 0x00},
		},
	}
	out := runSDInfoFullJSON(t, mc)

	var report struct {
		Data struct {
			Registry struct {
				ISD []struct {
					AID           string   `json:"aid"`
					Lifecycle     string   `json:"lifecycle"`
					LifecycleByte string   `json:"lifecycle_byte"`
					Privileges    []string `json:"privileges"`
				} `json:"isd"`
			} `json:"registry"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("JSON decode: %v\n--- output ---\n%s", err, out)
	}
	if got := len(report.Data.Registry.ISD); got != 1 {
		t.Fatalf("registry.isd count = %d, want 1\n--- output ---\n%s", got, out)
	}
	isd := report.Data.Registry.ISD[0]
	if isd.AID != "A000000151000000" {
		t.Errorf("isd[0].aid = %q, want A000000151000000", isd.AID)
	}
	if isd.Lifecycle != "SECURED" {
		t.Errorf("isd[0].lifecycle = %q, want SECURED", isd.Lifecycle)
	}
	if isd.LifecycleByte != "0x0F" {
		t.Errorf("isd[0].lifecycle_byte = %q, want 0x0F", isd.LifecycleByte)
	}
	wantPrivs := map[string]bool{"SecurityDomain": true, "DAPVerification": true}
	for _, p := range isd.Privileges {
		if !wantPrivs[p] {
			t.Errorf("isd[0].privileges contains unexpected %q", p)
		}
		delete(wantPrivs, p)
	}
	if len(wantPrivs) > 0 {
		t.Errorf("isd[0].privileges missing %v", wantPrivs)
	}
}

// TestSDInfo_Full_EmptyRegistry verifies that scopes with no entries
// (mock returns SW=6A88) are reported as "no entries" PASS lines, not
// failures.
func TestSDInfo_Full_EmptyRegistry(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// Leave all three registry slices empty; mockcard returns
	// SW=6A88 for each scope.
	out := runSDInfoFull(t, mc)
	for _, want := range []string{
		"GET STATUS scope=ISD",
		"GET STATUS scope=Applications",
		"GET STATUS scope=LoadFiles",
		"no entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestSDInfo_NoFull_NoRegistryFields confirms that without --full,
// no GET STATUS calls are issued and no registry block appears in
// either text or JSON output. This pins the surface so 'sd info'
// without --full stays the lightweight unauthenticated probe it has
// always been.
func TestSDInfo_NoFull_NoRegistryFields(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.RegistryISD = []mockcard.MockRegistryEntry{
		{AID: []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, Lifecycle: 0x0F},
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "registry") || strings.Contains(out, "GET STATUS") {
		t.Errorf("sd info without --full should not mention the registry; got:\n%s", out)
	}
}

// runSDInfoFull invokes 'sd info --full' against a mock card and
// returns the captured stdout. Used by tests that need to assert on
// human-readable output.
func runSDInfoFull(t *testing.T, mc *mockcard.Card) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--full"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	return buf.String()
}

// runSDInfoFullJSON invokes 'sd info --full --json' and returns the
// captured stdout, expected to be a JSON object.
func runSDInfoFullJSON(t *testing.T, mc *mockcard.Card) string {
	t.Helper()
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--full", "--json"}); err != nil {
		t.Fatalf("cmdSDInfo: %v", err)
	}
	return buf.String()
}

// TestSDInfo_Full_SCP03Default_AuthModeScp03 pins the Finding 9
// contract: when --full is paired with --scp03-keys-default, the
// session opens authenticated and the JSON reports auth_mode="scp03".
//
// The deeper "registry scopes populate instead of SKIP" claim is
// hard to assert in a unit test because no single mock currently
// speaks BOTH SCP03 secure messaging AND a populated GP registry:
//
//   - mockcard.Card has the registry (RegistryISD/Apps/LoadFiles)
//     but doesn't run an SCP03 handshake; INITIALIZE UPDATE returns
//     SW=6D00.
//   - scp03.MockCard runs the handshake but doesn't persist a
//     registry; GET STATUS returns SW=6A88 'no entries'.
//
// The hardware lab test (lab_scp11c_test.go) closes that loop on
// real cards. For the unit-test layer we assert what we can: the
// auth_mode JSON field flips from "none" to "scp03", and the
// SCP03 session opened cleanly. Future work to merge the two
// mock surfaces (or carry registry through scp03.MockCard) would
// let this test also assert post-auth registry population.
//
// Per the external review on feat/sd-keys-cli, Finding 9.
func TestSDInfo_Full_SCP03Default_AuthModeScp03(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{
		"--reader", "fake",
		"--full",
		"--json",
		"--scp03-keys-default",
	}); err != nil {
		t.Fatalf("cmdSDInfo: %v\n--- output ---\n%s", err, buf.String())
	}

	var report struct {
		Data struct {
			AuthMode string `json:"auth_mode"`
		} `json:"data"`
		Checks []struct {
			Name   string `json:"name"`
			Result string `json:"result"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("JSON decode: %v\n--- output ---\n%s", err, buf.String())
	}

	if got, want := report.Data.AuthMode, "scp03"; got != want {
		t.Errorf("data.auth_mode = %q, want %q", got, want)
	}

	// Sanity: the auth check passed (no FAIL on 'open SCP03 SD').
	for _, c := range report.Checks {
		if c.Name == "open SCP03 SD" && c.Result != "PASS" {
			t.Errorf("'open SCP03 SD' check = %s, want PASS", c.Result)
		}
	}
}

// TestSDInfo_NoSCP03Flags_AuthModeIsNone confirms the unauthenticated
// default path still reports auth_mode="none" in JSON. Pins the JSON
// schema so consumers can rely on the field always being present.
func TestSDInfo_NoSCP03Flags_AuthModeIsNone(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	out := runSDInfoFullJSON(t, mc)
	var report struct {
		Data struct {
			AuthMode string `json:"auth_mode"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("JSON decode: %v\n--- output ---\n%s", err, out)
	}
	if got, want := report.Data.AuthMode, "none"; got != want {
		t.Errorf("data.auth_mode = %q, want %q", got, want)
	}
}

// TestSDInfo_SCP03WithoutFull_RejectedAsUsageError confirms that
// --scp03-* without --full is a usage error. Without --full, the
// session does only CRD + KIT reads, both of which are
// unauthenticated by definition; authenticating just for those
// reads would burn an auth round-trip for no benefit and obscure
// the SCP03-as-authenticated-registry-walk semantic.
func TestSDInfo_SCP03WithoutFull_RejectedAsUsageError(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	err = cmdSDInfo(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
		// no --full
	})
	if err == nil {
		t.Fatalf("expected usage error from --scp03-* without --full; got nil")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("error type = %T; want *usageError", err)
	}
	if !strings.Contains(err.Error(), "--full") {
		t.Errorf("usage error should mention --full; got %q", err.Error())
	}
}

// TestProbe_TopLevel_NoSCP03FlagsRegistered verifies that the
// top-level 'scpctl probe' command (which goes through runProbe
// with allowFullStatus=false) does NOT register --scp03-* flags.
// The flag set is intentionally narrow there: probe is the
// pre-authentication card-identity surface, and adding auth flags
// would muddy that.
func TestProbe_TopLevel_NoSCP03FlagsRegistered(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	err = cmdProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
	})
	if err == nil {
		t.Fatalf("expected unknown-flag error from --scp03-keys-default on top-level probe; got nil")
	}
	if !strings.Contains(err.Error(), "scp03-keys-default") &&
		!strings.Contains(err.Error(), "flag provided but not defined") {
		t.Errorf("expected unknown-flag error; got %q", err.Error())
	}
}

// TestSDInfo_SDAIDFlag_TargetsCustomAID exercises --sd-aid plumbed
// end-to-end through 'sd info'. Confirms three things:
//
//  1. The mockcard's MockSDAID override gates SELECT correctly:
//     without --sd-aid, the default ISD lookup fails (SW=6A82); the
//     command surfaces that as a Fail line.
//  2. With --sd-aid set to the same value as MockSDAID, SELECT
//     succeeds and the rest of 'sd info' runs cleanly.
//  3. Hex parsing accepts the colon-separated form from the help
//     text, since that's the form an operator copy-pasting from a
//     vendor data sheet is most likely to use.
//
// Per the external review on feat/sd-keys-cli, Finding 2.
func TestSDInfo_SDAIDFlag_TargetsCustomAID(t *testing.T) {
	customAID := []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}

	t.Run("without --sd-aid, default ISD select fails", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockSDAID = customAID
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mc.Transport(), nil
			},
		}
		err = cmdSDInfo(context.Background(), env, []string{"--reader", "fake"})
		if err == nil {
			t.Fatalf("expected Fail when --sd-aid omitted against custom-AID card; got nil\n%s", buf.String())
		}
		// The error should come from the SELECT step (6A82 file
		// not found). Don't pin the exact wording — it comes
		// from the apdu package — but the signal should be there.
		if !strings.Contains(buf.String(), "select") {
			t.Errorf("expected output to mention 'select'; got:\n%s", buf.String())
		}
	})

	t.Run("with --sd-aid colon-form, SELECT resolves", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockSDAID = customAID
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mc.Transport(), nil
			},
		}
		err = cmdSDInfo(context.Background(), env, []string{
			"--reader", "fake",
			"--sd-aid", "A0:00:00:06:47:2F:00:01",
		})
		if err != nil {
			t.Fatalf("cmdSDInfo: %v\n%s", err, buf.String())
		}
		out := buf.String()
		// Should record the SD select PASS line.
		if !strings.Contains(out, "select ISD") {
			t.Errorf("expected 'select ISD' check in output; got:\n%s", out)
		}
		// And it should NOT contain a Fail.
		if strings.Contains(out, "FAIL") {
			t.Errorf("unexpected FAIL line:\n%s", out)
		}
	})

	t.Run("with --sd-aid bare-hex form, SELECT resolves", func(t *testing.T) {
		mc, err := mockcard.New()
		if err != nil {
			t.Fatalf("mockcard.New: %v", err)
		}
		mc.MockSDAID = customAID
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mc.Transport(), nil
			},
		}
		err = cmdSDInfo(context.Background(), env, []string{
			"--reader", "fake",
			"--sd-aid", "A0000006472F0001",
		})
		if err != nil {
			t.Fatalf("cmdSDInfo: %v\n%s", err, buf.String())
		}
	})
}

// TestSDInfo_SDAIDFlag_RejectsInvalid covers the integration: an
// invalid --sd-aid value surfaces as a usage error before any
// transport activity.
func TestSDInfo_SDAIDFlag_RejectsInvalid(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	connectCalled := false
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			connectCalled = true
			return mc.Transport(), nil
		},
	}
	err = cmdSDInfo(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", "AB", // 1 byte, below the 5-byte minimum
	})
	if err == nil {
		t.Fatalf("expected usage error from short --sd-aid; got nil")
	}
	if connectCalled {
		t.Errorf("connect should not be called when --sd-aid is invalid")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("err type = %T, want *usageError", err)
	}
}

// TestSDInfo_CardLocked6283_ReportsAndContinues exercises the
// end-to-end CARD_LOCKED path through 'sd info' against a mockcard
// configured with MockSelectSW=0x6283. Pins three behaviors:
//
//  1. The command does NOT fail. Returns nil error and emits a
//     readable report.
//  2. The output contains a CARD_LOCKED indicator (the SKIP line
//     emitted by runProbe before any read paths).
//  3. The JSON output sets data.card_locked=true so a programmatic
//     consumer can key on the field rather than parsing prose.
//
// Per the third external review, Section 9.
func TestSDInfo_CardLocked6283_ReportsAndContinues(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	mc.MockSelectSW = 0x6283

	t.Run("text output reports CARD_LOCKED and does not fail", func(t *testing.T) {
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mc.Transport(), nil
			},
		}
		err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake"})
		if err != nil {
			t.Fatalf("cmdSDInfo: %v\n%s", err, buf.String())
		}
		out := buf.String()
		if !strings.Contains(out, "CARD_LOCKED") {
			t.Errorf("expected CARD_LOCKED indicator in output:\n%s", out)
		}
		if !strings.Contains(out, "6283") {
			t.Errorf("expected SW 6283 referenced in output:\n%s", out)
		}
	})

	t.Run("JSON output sets data.card_locked=true", func(t *testing.T) {
		var buf bytes.Buffer
		env := &runEnv{
			out: &buf, errOut: &buf,
			connect: func(_ context.Context, _ string) (transport.Transport, error) {
				return mc.Transport(), nil
			},
		}
		err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--json"})
		if err != nil {
			t.Fatalf("cmdSDInfo: %v\n%s", err, buf.String())
		}
		out := buf.String()
		// Pin the field name. JSON shape is decided in
		// probeData; if a regression renames or drops the
		// field, programmatic consumers break.
		if !strings.Contains(out, "\"card_locked\"") {
			t.Errorf("expected 'card_locked' key in JSON output:\n%s", out)
		}
		if !strings.Contains(out, "\"card_locked\": true") {
			t.Errorf("expected card_locked=true; got:\n%s", out)
		}
	})
}

// TestSDInfo_NormalSelect_NoCardLockedField pins the negative case:
// a regular 9000 SELECT must NOT include the card_locked field in
// JSON output (omitempty) and must NOT mention CARD_LOCKED in text.
// Catches a regression that flips the default or always includes
// the warning.
func TestSDInfo_NormalSelect_NoCardLockedField(t *testing.T) {
	mc, err := mockcard.New()
	if err != nil {
		t.Fatalf("mockcard.New: %v", err)
	}
	// MockSelectSW unset → defaults to 9000.

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mc.Transport(), nil
		},
	}
	if err := cmdSDInfo(context.Background(), env, []string{"--reader", "fake", "--json"}); err != nil {
		t.Fatalf("cmdSDInfo: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, "card_locked") {
		t.Errorf("'card_locked' should be omitted from JSON when false (omitempty); got:\n%s", out)
	}
	if strings.Contains(out, "CARD_LOCKED") {
		t.Errorf("CARD_LOCKED should not appear in text on a normal 9000 SELECT; got:\n%s", out)
	}
}
