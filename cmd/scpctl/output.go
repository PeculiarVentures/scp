package main

import (
	"encoding/json"
	"fmt"
	"io"
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
func (r *Report) Emit(w io.Writer, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	fmt.Fprintln(w, "scpctl smoke", r.Subcommand)
	if r.Reader != "" {
		fmt.Fprintln(w, "  reader:", r.Reader)
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
