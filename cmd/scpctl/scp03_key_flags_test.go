package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/scp03"
)

// TestSCP03KeyFlags_DefaultIsFactory confirms no flags = factory.
// Identical behavior to before this PR; the test pins the
// equivalence so a refactor doesn't accidentally change it.
func TestSCP03KeyFlags_DefaultIsFactory(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != scp03.YubiKeyFactoryKeyVersion {
		t.Errorf("KVN got 0x%02X want 0x%02X (YubiKey factory)",
			cfg.KeyVersion, scp03.YubiKeyFactoryKeyVersion)
	}
	if !bytesEqualKey(cfg.Keys.ENC, scp03.DefaultKeys.ENC) {
		t.Error("ENC key not the well-known factory value")
	}
	if !strings.Contains(kf.describeKeys(cfg), "factory") {
		t.Errorf("describeKeys should call this factory; got %q", kf.describeKeys(cfg))
	}
}

// TestSCP03KeyFlags_ExplicitDefault confirms --scp03-keys-default
// produces the same factory config as the implicit default.
func TestSCP03KeyFlags_ExplicitDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{"--scp03-keys-default"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != scp03.YubiKeyFactoryKeyVersion {
		t.Errorf("KVN: got 0x%02X want 0x%02X", cfg.KeyVersion, scp03.YubiKeyFactoryKeyVersion)
	}
}

// TestSCP03KeyFlags_CustomKeys_AES128 confirms --scp03-{kvn,enc,mac,
// dek} all together produce a Config with the supplied bytes. The
// most realistic scenario: a card whose factory keys have been
// rotated to a known operator-controlled set.
func TestSCP03KeyFlags_CustomKeys_AES128(t *testing.T) {
	enc := strings.Repeat("11", 16)
	macK := strings.Repeat("22", 16)
	dek := strings.Repeat("33", 16)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-enc", enc,
		"--scp03-mac", macK,
		"--scp03-dek", dek,
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != 0x01 {
		t.Errorf("KVN: got 0x%02X want 0x01", cfg.KeyVersion)
	}
	if hex.EncodeToString(cfg.Keys.ENC) != enc {
		t.Error("ENC bytes don't match")
	}
	if hex.EncodeToString(cfg.Keys.MAC) != macK {
		t.Error("MAC bytes don't match")
	}
	if hex.EncodeToString(cfg.Keys.DEK) != dek {
		t.Error("DEK bytes don't match")
	}
	desc := kf.describeKeys(cfg)
	if !strings.Contains(desc, "custom") || !strings.Contains(desc, "AES-128") {
		t.Errorf("describeKeys: got %q, want custom AES-128", desc)
	}
}

// TestSCP03KeyFlags_CustomKeys_AES192_AES256 confirms longer key
// lengths work. AES-192 (24 bytes) is a realistic post-rotation
// state on YubiKey 5.7+.
func TestSCP03KeyFlags_CustomKeys_AES192_AES256(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"AES-192", 24},
		{"AES-256", 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := strings.Repeat("AB", tc.size)
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse([]string{
				"--scp03-kvn", "FF",
				"--scp03-enc", k, "--scp03-mac", k, "--scp03-dek", k,
			}); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg, err := kf.applyToConfig()
			if err != nil {
				t.Fatalf("applyToConfig: %v", err)
			}
			if len(cfg.Keys.ENC) != tc.size {
				t.Errorf("ENC length: got %d want %d", len(cfg.Keys.ENC), tc.size)
			}
			if !strings.Contains(kf.describeKeys(cfg), tc.name) {
				t.Errorf("describeKeys: got %q want %s", kf.describeKeys(cfg), tc.name)
			}
		})
	}
}

// TestSCP03KeyFlags_TolerantHexFormatting confirms the paste-from-
// docs cosmetics work: spaces, colons, dashes are all stripped
// before hex-decoding.
func TestSCP03KeyFlags_TolerantHexFormatting(t *testing.T) {
	want, _ := hex.DecodeString("404142434445464748494a4b4c4d4e4f")
	cases := []string{
		"40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f",
		"40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f",
		"40-41-42-43-44-45-46-47-48-49-4a-4b-4c-4d-4e-4f",
	}
	for i, s := range cases {
		t.Run(fmt.Sprintf("variant_%d", i), func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse([]string{
				"--scp03-kvn", "FF",
				"--scp03-enc", s, "--scp03-mac", s, "--scp03-dek", s,
			}); err != nil {
				t.Fatal(err)
			}
			cfg, err := kf.applyToConfig()
			if err != nil {
				t.Fatalf("applyToConfig: %v", err)
			}
			if !bytesEqualKey(cfg.Keys.ENC, want) {
				t.Errorf("decoded bytes mismatch")
			}
		})
	}
}

// TestSCP03KeyFlags_RejectsPartialCustom confirms that supplying
// some but not all of --scp03-{kvn,enc,mac,dek} is a usage error.
// A half-specified key set is one of the easier ways to misfire a
// production rotation; failing closed is the right move.
func TestSCP03KeyFlags_RejectsPartialCustom(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing dek", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
		}},
		{"missing mac and dek", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 16),
		}},
		{"missing kvn", []string{
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatal("expected partial-custom error")
			}
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Errorf("expected *usageError, got %T", err)
			}
			if !strings.Contains(err.Error(), "all four") {
				t.Errorf("error should mention all four flags must be supplied; got %v", err)
			}
		})
	}
}

// TestSCP03KeyFlags_RejectsMixedDefaultAndCustom confirms
// --scp03-keys-default with any --scp03-{kvn,enc,mac,dek} fails.
// Operator must be deliberate.
func TestSCP03KeyFlags_RejectsMixedDefaultAndCustom(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-keys-default",
		"--scp03-kvn", "01",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("expected *usageError, got %T", err)
	}
}

// TestSCP03KeyFlags_RejectsInconsistentKeyLengths confirms
// enc/mac/dek must all be the same length. SCP03 sessions need
// matching ENC/MAC/DEK key sizes; mismatch is a usage error
// rather than an opaque card SW.
func TestSCP03KeyFlags_RejectsInconsistentKeyLengths(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-enc", strings.Repeat("11", 16),
		"--scp03-mac", strings.Repeat("22", 24), // wrong length
		"--scp03-dek", strings.Repeat("33", 16),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected length-mismatch error")
	}
	if !strings.Contains(err.Error(), "length mismatch") {
		t.Errorf("expected length-mismatch error; got %v", err)
	}
}

// TestSCP03KeyFlags_Shorthand_Success confirms --scp03-key produces
// a Config with the same hex value used for ENC, MAC, and DEK.
// Common configuration on GP cards provisioned with a single master
// key.
func TestSCP03KeyFlags_Shorthand_Success(t *testing.T) {
	k := strings.Repeat("AB", 16)
	wantBytes, _ := hex.DecodeString(k)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-key", k,
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	if cfg.KeyVersion != 0x01 {
		t.Errorf("KVN: got 0x%02X want 0x01", cfg.KeyVersion)
	}
	if !bytesEqualKey(cfg.Keys.ENC, wantBytes) {
		t.Error("ENC bytes don't match shorthand value")
	}
	if !bytesEqualKey(cfg.Keys.MAC, wantBytes) {
		t.Error("MAC bytes don't match shorthand value")
	}
	if !bytesEqualKey(cfg.Keys.DEK, wantBytes) {
		t.Error("DEK bytes don't match shorthand value")
	}
}

// TestSCP03KeyFlags_Shorthand_BytesAreIndependent confirms that
// mutating one of ENC/MAC/DEK does not affect the others. Defends
// the by-construction-copy invariant in applyToConfig — the scp03
// layer is not expected to mutate, but the invariant should hold
// before a downstream caller can rely on it.
func TestSCP03KeyFlags_Shorthand_BytesAreIndependent(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-kvn", "01",
		"--scp03-key", strings.Repeat("AB", 16),
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := kf.applyToConfig()
	if err != nil {
		t.Fatalf("applyToConfig: %v", err)
	}
	cfg.Keys.ENC[0] = 0x00
	if cfg.Keys.MAC[0] == 0x00 {
		t.Error("mutating ENC[0] corrupted MAC[0]; ENC and MAC share backing storage")
	}
	if cfg.Keys.DEK[0] == 0x00 {
		t.Error("mutating ENC[0] corrupted DEK[0]; ENC and DEK share backing storage")
	}
}

// TestSCP03KeyFlags_Shorthand_RequiresKVN confirms --scp03-key alone
// (without --scp03-kvn) is a usage error. KVN is independent of the
// key bytes — the card needs both to authenticate.
func TestSCP03KeyFlags_Shorthand_RequiresKVN(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-key", strings.Repeat("AB", 16),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected error for --scp03-key without --scp03-kvn")
	}
	if !strings.Contains(err.Error(), "scp03-kvn") {
		t.Errorf("error should reference --scp03-kvn; got %v", err)
	}
}

// TestSCP03KeyFlags_Shorthand_RejectsMixedWithSplit confirms
// --scp03-key combined with any of --scp03-{enc,mac,dek} is a
// usage error. Operator must pick one form or the other.
func TestSCP03KeyFlags_Shorthand_RejectsMixedWithSplit(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"key + enc", []string{
			"--scp03-kvn", "01",
			"--scp03-key", strings.Repeat("AB", 16),
			"--scp03-enc", strings.Repeat("11", 16),
		}},
		{"key + mac", []string{
			"--scp03-kvn", "01",
			"--scp03-key", strings.Repeat("AB", 16),
			"--scp03-mac", strings.Repeat("22", 16),
		}},
		{"key + dek", []string{
			"--scp03-kvn", "01",
			"--scp03-key", strings.Repeat("AB", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatal("expected mutual-exclusion error")
			}
			if !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("error should mention mutual exclusivity; got %v", err)
			}
		})
	}
}

// TestSCP03KeyFlags_Shorthand_RejectsMixedWithDefault confirms
// --scp03-key combined with --scp03-keys-default is a usage error.
func TestSCP03KeyFlags_Shorthand_RejectsMixedWithDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	kf := registerSCP03KeyFlags(fs)
	if err := fs.Parse([]string{
		"--scp03-keys-default",
		"--scp03-key", strings.Repeat("AB", 16),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := kf.applyToConfig()
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
}

// TestSCP03KeyFlags_RejectsBadHex covers the parse-failure path
// for individual key flags.
func TestSCP03KeyFlags_RejectsBadHex(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bad enc hex", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", "ZZ",
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
		{"bad kvn hex", []string{
			"--scp03-kvn", "GG",
			"--scp03-enc", strings.Repeat("11", 16),
			"--scp03-mac", strings.Repeat("22", 16),
			"--scp03-dek", strings.Repeat("33", 16),
		}},
		{"unsupported key length 8 bytes", []string{
			"--scp03-kvn", "01",
			"--scp03-enc", strings.Repeat("11", 8),
			"--scp03-mac", strings.Repeat("22", 8),
			"--scp03-dek", strings.Repeat("33", 8),
		}},
		{"shorthand with bad hex", []string{
			"--scp03-kvn", "01",
			"--scp03-key", "ZZ",
		}},
		{"shorthand with unsupported length", []string{
			"--scp03-kvn", "01",
			"--scp03-key", strings.Repeat("AB", 8),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			kf := registerSCP03KeyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			_, err := kf.applyToConfig()
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
