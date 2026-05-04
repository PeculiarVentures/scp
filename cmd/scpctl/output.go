package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Result is the outcome of a single check or test.
type Result string

const (
	ResultPass Result = "PASS"
	ResultFail Result = "FAIL"
	ResultSkip Result = "SKIP"
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
	Subcommand string  `json:"subcommand"`
	Reader     string  `json:"reader,omitempty"`
	Checks     []Check `json:"checks"`
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
	// The Subcommand field carries the full label including any
	// group prefix ('piv info', 'sd info', 'piv-provision', etc.),
	// so emitting it directly is correct for all groups. Smoke
	// commands set Subcommand to e.g. 'probe' and rely on the
	// 'scpctl smoke' prefix being added here for backwards-
	// compatibility with the original scp-smoke output shape.
	switch {
	case strings.Contains(r.Subcommand, " "):
		// Already group-qualified ('piv info', 'sd info').
		fmt.Fprintln(w, "scpctl", r.Subcommand)
	default:
		// Bare smoke subcommand name.
		fmt.Fprintln(w, "scpctl smoke", r.Subcommand)
	}
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
