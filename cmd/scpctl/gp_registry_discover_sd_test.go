package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestGPRegistry_DiscoverSD_DefaultAIDMatches: --discover-sd on
// gp registry walks the curated AID list, finds the first AID
// the card answers 9000 to, and proceeds to open SCP03 against
// that AID. The mockcard answers 9000 to any SELECT and supports
// SCP03 with the default keys, so this exercises the full flow.
func TestGPRegistry_DiscoverSD_DefaultAIDMatches(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--discover-sd",
		"--scp03-keys-default",
	}); err != nil {
		t.Fatalf("cmdGPRegistry with --discover-sd: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "discover ISD") {
		t.Errorf("output should contain 'discover ISD' check:\n%s", out)
	}
	if !strings.Contains(out, "A000000151000000") {
		t.Errorf("output should mention the matched AID:\n%s", out)
	}
	if !strings.Contains(out, "open SCP03 SD") {
		t.Errorf("output should reach 'open SCP03 SD' after discovery:\n%s", out)
	}
}

// TestGPRegistry_DiscoverSD_MutualExclusionWithSDAID: --discover-sd
// and --sd-aid cannot both be supplied; the CLI rejects the
// combination at flag-validation time, before opening any session.
func TestGPRegistry_DiscoverSD_MutualExclusionWithSDAID(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--discover-sd",
		"--sd-aid", "A000000151000000",
		"--scp03-keys-default",
	})
	if err == nil {
		t.Fatal("expected error on --discover-sd + --sd-aid")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("flag conflict should fail before any I/O; saw %d APDUs", len(rec.cmds))
	}
}
