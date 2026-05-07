package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Result is the outcome of a single check or test.
type Result string

const (
	ResultPass Result = "PASS"
	ResultFail Result = "FAIL"
	ResultSkip Result = "SKIP"
	// ResultWarn means the check completed successfully but the
	// result has a known caveat the operator should notice. The
	// archetypal case is parsing a CAP whose package name was
	// inferred from the ZIP directory layout rather than the
	// Header component — the parse succeeds, but if the archive
	// was repackaged the inferred name may be stale. Warn keeps
	// HasFailure false so the exit code stays 0; only Fail flips
	// the bit. JSON consumers can branch on ResultWarn directly;
	// text-mode output renders WARN like PASS so the operator
	// reads the detail.
	ResultWarn Result = "WARN"
)

// Check is one named line of output: "X: PASS — extra info." A
// subcommand collects checks as it runs and emits them at the end so
// JSON output is a single object rather than streaming lines.
type Check struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// Report is the aggregate output of a subcommand.
type Report struct {
	Subcommand string `json:"subcommand"`
	Reader     string `json:"reader,omitempty"`

	// TransportSecurity is a top-level structured field naming
	// the wire-layer security posture of the operation. Set by
	// handlers that interact with the card through openPIVSession
	// or any other transport-establishing helper. The value is
	// one of:
	//
	//   "raw-pcsc"     direct APDUs over PC/SC; the host running
	//                  scpctl is in the operator's trust boundary.
	//   "scp11b-piv"   APDUs travel inside an SCP11b-on-PIV
	//                  authenticated key-agreement channel.
	//   ""             unset; either the command did not touch
	//                  the card (help/version/info-only paths) or
	//                  the report was emitted before the channel
	//                  mode was decided.
	//
	// This is a top-level field rather than a check-line detail
	// because external consumers (audit logs, automation that
	// branches on transport) need it to be machine-extractable
	// without parsing the human-readable check stream. The same
	// posture also appears as a 'channel mode' check so a human
	// reading the text output sees it inline.
	TransportSecurity string `json:"transport_security,omitempty"`

	Checks []Check `json:"checks"`
	// Data carries subcommand-specific structured fields like parsed
	// CRD or key info. JSON mode emits it; text mode pretty-prints.
	Data any `json:"data,omitempty"`
}

// Pass appends a passing check.
func (r *Report) Pass(name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Result: ResultPass, Detail: detail})
}

// Fail appends a failing check.
func (r *Report) Fail(name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Result: ResultFail, Detail: detail})
}

// Skip appends a skipped check.
func (r *Report) Skip(name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Result: ResultSkip, Detail: detail})
}

// Warn appends a passing-but-caveated check. Used when a check
// completed and produced a result, but the operator should know
// the result has a known shortcoming (e.g. CAP package name
// inferred from ZIP path rather than read from the Header
// component). Does not flip HasFailure, so the exit code stays
// 0; differs from Pass only in surfacing the caveat to text
// readers and to JSON consumers that branch on Result.
func (r *Report) Warn(name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Result: ResultWarn, Detail: detail})
}

// HasFailure reports whether any check is FAIL. Used to set the
// process exit code.
func (r *Report) HasFailure() bool {
	for _, c := range r.Checks {
		if c.Result == ResultFail {
			return true
		}
	}
	return false
}

// Transport-security constants for Report.TransportSecurity. Using
// constants rather than string literals at call sites makes the
// available values discoverable and prevents typo drift across
// handlers.
const (
	// TransportSecurityRawPCSC means APDUs travel directly over
	// PC/SC with no wire-layer encryption or authentication. The
	// operator must have asserted that the host running scpctl is
	// in their trust boundary (--raw-local-ok). Suitable for
	// local-USB administration.
	TransportSecurityRawPCSC = "raw-pcsc"

	// TransportSecurityScp11bPIV means APDUs travel inside an
	// SCP11b-on-PIV authenticated key-agreement channel. The
	// channel cert was either validated against trust roots
	// (--trust-roots) or skipped for lab use
	// (--lab-skip-scp11-trust); both states are still reported as
	// scp11b-piv at this layer because the structural posture is
	// the same. The trust-validation distinction surfaces in the
	// 'apply trust' check line and in the lab-skip-mode SKIP entry.
	TransportSecurityScp11bPIV = "scp11b-piv"
)

// Emit writes the report to w. When jsonMode is true, output is a
// single indented JSON object; otherwise it's human-readable text.
//
// Text-mode rendering shape:
//
//	scpctl <group> <subcommand>
//	  reader: <name>
//	  data:
//	    <key>: <value>
//	    ...
//	  <check name>                  <PASS|FAIL|SKIP> — <detail>
//	  ...
//
// The data block is rendered when Report.Data is non-nil; rendering
// goes through encoding/json so any Data type that round-trips via
// json.Marshal also pretty-prints, with no per-subcommand wiring.
// Only top-level fields of object-shaped Data are listed; nested
// objects and arrays render as compact JSON on the same line.
func (r *Report) Emit(w io.Writer, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	// Subcommand carries the full group-qualified path
	// ('test scp03-sd-read', 'piv info', 'sd bootstrap-oce').
	// Emit it directly with a fixed 'scpctl' prefix.
	fmt.Fprintln(w, "scpctl", r.Subcommand)
	if r.Reader != "" {
		fmt.Fprintln(w, "  reader:", r.Reader)
	}
	if r.Data != nil {
		if err := emitDataText(w, r.Data); err != nil {
			return err
		}
	}
	for _, c := range r.Checks {
		if c.Detail == "" {
			fmt.Fprintf(w, "  %-32s %s\n", c.Name, c.Result)
		} else {
			fmt.Fprintf(w, "  %-32s %s — %s\n", c.Name, c.Result, c.Detail)
		}
	}
	return nil
}

// emitDataText pretty-prints Report.Data for human-readable output.
// Top-level fields of an object (struct or map) become 'key: value'
// lines under a 'data:' header; scalars are rendered as Go fmt %v
// would, slices and nested objects are rendered as compact JSON.
//
// The intermediate JSON round-trip is deliberate: every existing
// Data shape in this CLI already declares JSON tags (because that's
// how the JSON output mode works), so the JSON tag names are also
// what humans should see in text mode. No second tag system, no
// reflect-walk over Go field names.
func emitDataText(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		// If the Data value is not JSON-marshalable, fall back to
		// the Go default %v rendering rather than failing the whole
		// report emit. This should not happen for types the CLI
		// uses today (all of which are tagged structs) but the
		// fallback keeps Emit total.
		fmt.Fprintf(w, "  data: %v\n", data)
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// Non-object Data (a bare string, number, or array). Render
		// as compact JSON so the human still sees the value.
		fmt.Fprintf(w, "  data: %s\n", raw)
		return nil
	}
	if len(fields) == 0 {
		return nil
	}
	// Sort keys for deterministic output. Test goldens and human
	// diffs both benefit from a stable order.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(w, "  data:")
	for _, k := range keys {
		v := fields[k]
		// String values: drop the surrounding quotes for readability.
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			var s string
			if err := json.Unmarshal(v, &s); err == nil {
				fmt.Fprintf(w, "    %s: %s\n", k, s)
				continue
			}
		}
		// Everything else (numbers, bools, nested objects, arrays)
		// renders as compact JSON.
		fmt.Fprintf(w, "    %s: %s\n", k, v)
	}
	return nil
}
