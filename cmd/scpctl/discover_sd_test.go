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

// TestDiscoverSD_DefaultAIDMatches: the combined mock answers
// 9000 to any SELECT, so the first candidate (GP default ISD)
// resolves and the report says so.
func TestDiscoverSD_DefaultAIDMatches(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--discover-sd",
	}); err != nil {
		t.Fatalf("cmdGPProbe with --discover-sd: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "discover ISD") {
		t.Errorf("output should contain 'discover ISD' check:\n%s", out)
	}
	if !strings.Contains(out, "A000000151000000") {
		t.Errorf("output should mention the matched AID:\n%s", out)
	}
}

// TestDiscoverSD_MutualExclusionWithSDAID: --discover-sd and
// --sd-aid cannot both be supplied; the CLI rejects the
// combination at flag-parse time.
func TestDiscoverSD_MutualExclusionWithSDAID(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--discover-sd",
		"--sd-aid", "A000000151000000",
	})
	if err == nil {
		t.Fatal("expected error on mutual exclusion")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("flag conflict should fail before any I/O; saw %d APDUs", len(rec.cmds))
	}
}
