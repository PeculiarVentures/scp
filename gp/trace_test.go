package gp

import "testing"

func TestNopTraceSink_DiscardsEvents(t *testing.T) {
	// Smoke: NopTraceSink.Record must not panic on any event,
	// including the zero value and one with all fields populated.
	var sink TraceSink = NopTraceSink{}
	sink.Record(TraceEvent{})
	sink.Record(TraceEvent{
		Phase:       "scp03_handshake",
		CommandName: "INITIALIZE UPDATE",
		PlainAPDU:   []byte{0x80, 0x50, 0x00, 0x00},
		WrappedAPDU: []byte{0x80, 0x50, 0x00, 0x00},
		Response:    []byte{0x00, 0x00, 0x42},
		SW:          0x9000,
		SWMeaning:   "success",
		Notes:       []string{"fresh handshake"},
	})
}

// recordingSink is a test helper used elsewhere in the gp package.
// Defined here so it lives next to the TraceSink interface it
// implements rather than scattered across test files.
type recordingSink struct {
	events []TraceEvent
}

func (r *recordingSink) Record(event TraceEvent) {
	r.events = append(r.events, event)
}

func TestRecordingSink_CapturesEvents(t *testing.T) {
	sink := &recordingSink{}
	sink.Record(TraceEvent{Phase: "select", CommandName: "SELECT ISD"})
	sink.Record(TraceEvent{Phase: "registry", CommandName: "GET STATUS"})

	if len(sink.events) != 2 {
		t.Fatalf("got %d events, want 2", len(sink.events))
	}
	if sink.events[0].CommandName != "SELECT ISD" {
		t.Errorf("event[0].CommandName = %q, want SELECT ISD", sink.events[0].CommandName)
	}
	if sink.events[1].Phase != "registry" {
		t.Errorf("event[1].Phase = %q, want registry", sink.events[1].Phase)
	}
}
