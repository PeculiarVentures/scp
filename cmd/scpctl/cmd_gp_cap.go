package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/PeculiarVentures/scp/gp"
)

// cap is a sub-group within the gp group: 'scpctl gp cap inspect'.
// Today there is only the inspect subcommand; the sub-grouping
// reserves namespace for future host-side CAP utilities (sign,
// dump, diff) that would also be cardless and that don't naturally
// belong as siblings of probe/registry.
var gpCapCommands = map[string]func(ctx context.Context, env *runEnv, args []string) error{
	"inspect": cmdGPCapInspect,
}

func gpCapUsage(w io.Writer) {
	fmt.Fprint(w, `scpctl gp cap - Java Card CAP file utilities (host-only)

Usage:
  scpctl gp cap <subcommand> [flags]

Subcommands:
  inspect <path>  Read a CAP file from disk and print its package
                  AID, package version, applet inventory, and
                  component sizes. Does NOT touch a card.

Use "scpctl gp cap <subcommand> -h" for per-command flags.
`)
}

// cmdGPCap dispatches the cap-subgroup. Mirrors the top-level
// runGroup pattern used by gp/piv/sd/oce groups, scaled down: the
// only subcommand today is inspect.
func cmdGPCap(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		gpCapUsage(env.out)
		return &usageError{msg: "gp cap requires a subcommand"}
	}
	sub := args[0]
	rest := args[1:]
	if sub == "-h" || sub == "--help" || sub == "help" {
		gpCapUsage(env.out)
		return nil
	}
	handler, ok := gpCapCommands[sub]
	if !ok {
		gpCapUsage(env.out)
		return &usageError{msg: fmt.Sprintf("unknown gp cap subcommand %q", sub)}
	}
	return handler(ctx, env, rest)
}

// gpCapInspectData is the JSON payload of 'gp cap inspect'.
type gpCapInspectData struct {
	File              string                       `json:"file"`
	FileSize          int64                        `json:"file_size"`
	CAPVersion        string                       `json:"cap_version"`
	PackageVersion    string                       `json:"package_version"`
	PackageAID        string                       `json:"package_aid"`
	PackageName       string                       `json:"package_name,omitempty"`
	PackageNameSource string                       `json:"package_name_source"`
	Applets           []gpCapInspectApplet         `json:"applets"`
	Imports           []gpCapInspectImport         `json:"imports"`
	JavaCardVersion   string                       `json:"java_card_version,omitempty"`
	Components        []gpCapInspectComponentEntry `json:"components"`
}

type gpCapInspectApplet struct {
	AID                    string `json:"aid"`
	InstallMethodOffset    int    `json:"install_method_offset"`
	InstallMethodOffsetHex string `json:"install_method_offset_hex"`
}

type gpCapInspectImport struct {
	AID     string `json:"aid"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version"`
}

type gpCapInspectComponentEntry struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
	Size int    `json:"size"`
}

// cmdGPCapInspect reads a CAP file from disk via gp.ParseCAPFile
// and renders its metadata. Host-only: never connects to a reader.
//
// Argument shape: positional path. The CAP file path is the only
// thing the command actually needs, and a positional arg reads
// more naturally than '--cap <path>' for a single-input inspector.
func cmdGPCapInspect(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("gp cap inspect", env)
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return &usageError{msg: "gp cap inspect requires exactly one positional argument: the CAP file path"}
	}
	path := rest[0]

	report := &Report{Subcommand: "gp cap inspect"}

	st, err := os.Stat(path)
	if err != nil {
		report.Fail("stat CAP", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("stat %s: %w", path, err)
	}
	report.Pass("stat CAP", fmt.Sprintf("%s (%d bytes)", path, st.Size()))

	capFile, err := gp.ParseCAPFile(path)
	if err != nil {
		report.Fail("parse CAP", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("parse %s: %w", path, err)
	}
	report.Pass("parse CAP", fmt.Sprintf("package %s, %d applet(s), %d component(s)",
		capFile.PackageAID, len(capFile.Applets), len(capFile.Components)))
	report.Pass("parse scope",
		"host structural parse only (Header + Applet + Import); does not validate Method bytecode, ConstantPool offsets, install_method_offset references, or per-card load policy. A successful parse here is not a guarantee the CAP will load.")

	// Surface the package-name provenance explicitly. The Header
	// component is authoritative when it carries a non-empty
	// package_name; the ZIP-path fallback can disagree if the
	// archive was repackaged or built by a converter that places
	// components in a directory that doesn't match the package.
	// PartialInstallError-style stage hints depend on the operator
	// trusting the inspector's metadata, so flag the inferred case.
	switch capFile.PackageNameSource {
	case "header_component":
		// Authoritative; nothing to add.
	case "zip_path":
		report.Warn("package name source",
			"derived from ZIP directory path; may be stale if the archive was repackaged. The Header component did not carry a package_name field. Verify against the source jar before using this name as a stable identifier.")
	case "absent":
		report.Warn("package name source",
			"no package name found in either the Header component or the ZIP path; only the package AID is reliable.")
	}

	data := &gpCapInspectData{
		File:              path,
		FileSize:          st.Size(),
		CAPVersion:        fmt.Sprintf("%d.%d", capFile.CAPVersionMajor, capFile.CAPVersionMinor),
		PackageVersion:    fmt.Sprintf("%d.%d", capFile.PackageVersionMajor, capFile.PackageVersionMinor),
		PackageAID:        capFile.PackageAID.String(),
		PackageNameSource: capFile.PackageNameSource,
		// Initialize to empty slices rather than rely on append's
		// nil-handling: a nil slice in Go marshals to JSON null,
		// which forces script consumers to handle two distinct
		// representations of "no entries". An empty slice marshals
		// to []. Library CAPs (no Applet.cap) and minimal CAPs (no
		// known components) both reach this path with capFile
		// fields nil; the explicit initialization stabilizes the
		// JSON shape regardless.
		Applets:    []gpCapInspectApplet{},
		Imports:    []gpCapInspectImport{},
		Components: []gpCapInspectComponentEntry{},
	}
	if len(capFile.PackageName) > 0 {
		data.PackageName = string(capFile.PackageName)
	}
	for _, a := range capFile.Applets {
		data.Applets = append(data.Applets, gpCapInspectApplet{
			AID:                    a.AID.String(),
			InstallMethodOffset:    int(a.InstallMethodOffset),
			InstallMethodOffsetHex: fmt.Sprintf("0x%04X", a.InstallMethodOffset),
		})
	}
	for _, imp := range capFile.Imports {
		data.Imports = append(data.Imports, gpCapInspectImport{
			AID:     imp.AID.String(),
			Name:    imp.Name,
			Version: fmt.Sprintf("%d.%d", imp.MajorVersion, imp.MinorVersion),
		})
	}
	if jc := capFile.JavaCardVersion(); jc != "" {
		data.JavaCardVersion = jc
		report.Pass("Java Card runtime", jc)
	}
	if len(capFile.Imports) > 0 {
		report.Pass("imports",
			fmt.Sprintf("%d package(s)", len(capFile.Imports)))
	}
	for _, c := range capFile.Components {
		data.Components = append(data.Components, gpCapInspectComponentEntry{
			Name: c.Name,
			Tag:  fmt.Sprintf("0x%02X", c.Tag),
			Size: len(c.Raw),
		})
	}
	report.Data = data

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return fmt.Errorf("gp cap inspect reported failures")
	}
	return nil
}
