package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/PeculiarVentures/scp/mockcard"
	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// TestSDAIDFlag_Probe_DefaultUsesISDAID confirms the unauthenticated
// probe path SELECTs the GP-default ISD AID when no override is
// supplied. Captures the on-wire SELECT and compares.
func TestSDAIDFlag_Probe_DefaultUsesISDAID(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPProbe(context.Background(), env, []string{"--reader", "fake"}); err != nil {
		t.Fatalf("cmdGPProbe: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("default SELECT AID = %X, want %X (GP ISD)", sel.Data, want)
	}
}

// TestSDAIDFlag_Probe_OverridePassesThrough confirms --sd-aid
// reaches the SELECT command's data field.
func TestSDAIDFlag_Probe_OverridePassesThrough(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	custom := "A0000005591010"
	if err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", custom,
	}); err != nil {
		t.Fatalf("cmdGPProbe with --sd-aid: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("--sd-aid override SELECT data = %X, want %X", sel.Data, want)
	}
}

// TestSDAIDFlag_Probe_RejectsMalformed: too-short AIDs fail at
// flag parse time before any I/O.
func TestSDAIDFlag_Probe_RejectsMalformed(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	err := cmdGPProbe(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", "AB", // 1 byte — below ISO 7816-5 5-byte minimum
	})
	if err == nil {
		t.Fatal("expected validation error for too-short AID")
	}
	// Connection should not have been opened on flag-parse errors.
	if len(rec.cmds) != 0 {
		t.Errorf("malformed --sd-aid should fail before any I/O; saw %d APDUs", len(rec.cmds))
	}
}

// TestSDAIDFlag_Registry_OverridePassesThrough: the SCP03
// authenticated path threads the override through cfg.SelectAID
// and the underlying scp03.Open SELECTs that AID.
func TestSDAIDFlag_Registry_OverridePassesThrough(t *testing.T) {
	mc := mockcard.NewSCP03Card(scp03.DefaultKeys)
	rec := newRecordingTransport(mc.Transport())

	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) { return rec, nil },
	}
	if err := cmdGPRegistry(context.Background(), env, []string{
		"--reader", "fake",
		"--sd-aid", "A0000001515350",
		"--scp03-keys-default",
	}); err != nil {
		t.Fatalf("cmdGPRegistry: %v\n%s", err, buf.String())
	}
	sel := rec.firstSelect()
	if sel == nil {
		t.Fatal("no SELECT seen on wire")
	}
	want := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50}
	if !bytes.Equal(sel.Data, want) {
		t.Errorf("--sd-aid override SELECT data = %X, want %X", sel.Data, want)
	}
}
