package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/PeculiarVentures/scp/gp"
	"github.com/PeculiarVentures/scp/securitydomain"
)

// gpInstallData is the JSON payload for `gp install`. Mirrors the
// section names operators see in text mode so JSON consumers and
// humans see structurally similar output.
type gpInstallData struct {
	Protocol      string `json:"protocol,omitempty"`
	CAPPath       string `json:"cap_path,omitempty"`
	PackageAID    string `json:"package_aid,omitempty"`
	AppletAID     string `json:"applet_aid,omitempty"`
	ModuleAID     string `json:"module_aid,omitempty"`
	LoadImageSize int    `json:"load_image_size,omitempty"`
	SHA256        string `json:"load_image_sha256,omitempty"`
	SHA1          string `json:"load_image_sha1,omitempty"`

	// Preflight surfaces the host-side decisions the operator
	// should review before authorizing a write. JSON consumers
	// branching on these can compare a dry-run report against a
	// confirm-write report to detect drift in the CAP, the
	// component-exclusion policy, or the chunk plan between
	// preview and execution.
	LoadImageComponents []string `json:"load_image_components,omitempty"`
	LoadBlockSize       int      `json:"load_block_size,omitempty"`
	LoadBlockCount      int      `json:"load_block_count,omitempty"`
	PrivilegesHex       string   `json:"privileges_hex,omitempty"`
	LoadHashAlgorithm   string   `json:"load_hash_algorithm,omitempty"`

	DryRun      bool   `json:"dry_run"`
	Stage       string `json:"failed_stage,omitempty"`
	BytesLoaded int    `json:"bytes_loaded,omitempty"`
	CleanupHint string `json:"cleanup_hint,omitempty"`
}

// cmdGPInstall is the destructive applet-install operator command.
// Wraps securitydomain.Session.Install behind the standard
// --confirm-write idiom established by bootstrap-oce: without the
// flag, the command runs in dry-run mode (parses the CAP, verifies
// inputs, computes load image hashes, prints what it would do)
// without transmitting any APDU that mutates card state.
//
// Flags:
//
//	--cap <path>           CAP file to install (required)
//	--applet-aid <hex>     applet AID to register (required)
//	--module-aid <hex>     module AID; defaults to applet AID
//	--package-aid <hex>    override the load file AID parsed from
//	                       the CAP (rarely needed)
//	--privileges <hex>     applet privilege bytes (1..3); default 0x00
//	--include-debug        keep Debug.cap in the load image
//	--include-descriptor   keep Descriptor.cap in the load image
//	--load-block-size N    LOAD chunk size; 0 = default 200
//	--reader <name>        PC/SC reader substring
//	--json                 emit JSON output
//	--scp03-keys-default   YubiKey factory keys (test only)
//	--scp03-{enc,mac,dek}  split-key inputs
//	--scp03-key            single shared SCP03 key
//	--scp03-kvn            key version number on the card
//	--confirm-write        commit the install. Without this flag
//	                       the command is read-only.
//
// On install failure, prints the PartialInstallError stage and
// CleanupRecipe to give the operator an unambiguous next step.
// Exit code is 0 on success or dry-run, 1 on any FAIL check.
func cmdGPInstall(ctx context.Context, env *runEnv, args []string) error {
	fs := newSubcommandFlagSet("gp install", env)
	capPath := fs.String("cap", "", "Path to the CAP file to install (required).")
	appletAIDHex := fs.String("applet-aid", "", "Applet AID to register, hex (required, 5..16 bytes).")
	moduleAIDHex := fs.String("module-aid", "", "Module AID, hex. Defaults to applet AID for single-class applets.")
	packageAIDHex := fs.String("package-aid", "",
		"Override load file (package) AID, hex. Defaults to the AID parsed from the CAP's Header component; override only when the CAP's PackageAID does not match what the card expects.")
	privsHex := fs.String("privileges", "00",
		"Applet privilege bytes, hex (1..3 bytes). Default 00 = no special privileges.")
	includeDebug := fs.Bool("include-debug", false,
		"Keep Debug.cap in the load image. Default excludes it (saves EEPROM, avoids runtime issues on some cards).")
	includeDescriptor := fs.Bool("include-descriptor", false,
		"Keep Descriptor.cap in the load image. Default excludes it.")
	loadBlockSize := fs.Int("load-block-size", 0,
		"LOAD chunk size in bytes (0 = default 200, conservative for SM overhead within short-Lc encoding).")
	reader := fs.String("reader", "", "PC/SC reader name (substring match).")
	sdAIDHex := fs.String("sd-aid", "",
		"Override the Security Domain AID, hex (5..16 bytes). Default is the GP ISD AID (A000000151000000). Use this for cards with a non-default ISD (some SafeNet/Fusion variants, custom JCOP installs).")
	jsonMode := fs.Bool("json", false, "Emit JSON output.")
	scp03Keys := registerSCP03KeyFlags(fs)
	expectedCardID := fs.String("expected-card-id", "",
		"If set, abort before any destructive APDU when the card's CIN (GET DATA 0x0045) does not match this hex value. Recommended for fleet automation: pin the CIN of the card you intended to install onto.")
	confirm := fs.Bool("confirm-write", false,
		"Confirm destructive write. Without this flag, gp install runs in dry-run mode (parses inputs, computes load image hashes, reports planned operations without transmitting writes).")

	if err := fs.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}

	if *capPath == "" {
		return &usageError{msg: "gp install requires --cap <path>"}
	}
	if *appletAIDHex == "" {
		return &usageError{msg: "gp install requires --applet-aid <hex>"}
	}
	if !scp03Keys.explicitlyConfigured() {
		return &usageError{msg: "gp install requires an explicit SCP03 key choice: pass " +
			"--scp03-keys-default for YubiKey/test-card factory keys, " +
			"--scp03-kvn with --scp03-key for single-key cards, or " +
			"--scp03-kvn with --scp03-{enc,mac,dek} for split-key cards"}
	}

	report := &Report{Subcommand: "gp install", Reader: *reader}
	data := &gpInstallData{CAPPath: *capPath, DryRun: !*confirm}
	report.Data = data

	// 1. Parse and validate inputs (host-only; no card I/O).
	cap, err := gp.ParseCAPFile(*capPath)
	if err != nil {
		report.Fail("parse CAP", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("parse CAP: %w", err)
	}
	report.Pass("parse CAP", fmt.Sprintf("%d component(s)", len(cap.Components)))

	loadFileAID, err := decodeAIDOrCAPDefault(*packageAIDHex, "package-aid", cap.PackageAID[:])
	if err != nil {
		report.Fail("package AID", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	data.PackageAID = strings.ToUpper(hex.EncodeToString(loadFileAID))
	report.Pass("package AID", data.PackageAID)

	appletAID, err := decodeHexAID(*appletAIDHex, "applet-aid")
	if err != nil {
		report.Fail("applet AID", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	data.AppletAID = strings.ToUpper(hex.EncodeToString(appletAID))

	moduleAID := appletAID
	if *moduleAIDHex != "" {
		moduleAID, err = decodeHexAID(*moduleAIDHex, "module-aid")
		if err != nil {
			report.Fail("module AID", err.Error())
			_ = report.Emit(env.out, *jsonMode)
			return err
		}
	}
	data.ModuleAID = strings.ToUpper(hex.EncodeToString(moduleAID))
	report.Pass("AIDs",
		fmt.Sprintf("applet=%s module=%s", data.AppletAID, data.ModuleAID))

	privs, err := hex.DecodeString(stripWhitespace(*privsHex))
	if err != nil {
		report.Fail("privileges", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("privileges: %w", err)
	}
	if len(privs) < 1 || len(privs) > 3 {
		err := fmt.Errorf("privileges length %d invalid (must be 1..3 bytes)", len(privs))
		report.Fail("privileges", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}

	// 2. Build the load image and hash it. Hashes go in the report
	//    so an operator running --confirm-write later can verify
	//    they're sending the same bytes a previous dry-run reviewed.
	policy := gp.DefaultLoadImagePolicy()
	policy.ExcludeDebug = !*includeDebug
	policy.ExcludeDescriptor = !*includeDescriptor

	loadImage, err := cap.LoadImage(policy)
	if err != nil {
		report.Fail("build load image", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("build load image: %w", err)
	}
	sha256Sum, sha1Sum, err := cap.LoadImageHashes(policy)
	if err != nil {
		report.Fail("hash load image", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("hash load image: %w", err)
	}
	data.LoadImageSize = len(loadImage)
	data.SHA256 = strings.ToUpper(hex.EncodeToString(sha256Sum))
	data.SHA1 = strings.ToUpper(hex.EncodeToString(sha1Sum))
	report.Pass("load image",
		fmt.Sprintf("%d bytes, SHA-256=%s", data.LoadImageSize, data.SHA256))

	// Preflight: surface the host-side decisions the operator
	// should review before authorizing a write. Component list
	// shows which CAP files actually went into the load image
	// (Debug/Descriptor exclusion takes effect here unless
	// --include-debug / --include-descriptor was set). Chunk
	// plan shows how many LOAD APDUs the install will issue at
	// the configured block size. Privileges hex shows the bytes
	// going on the wire so an operator catches a mistyped
	// privilege string before it lands on the card.
	loadComponents := loadImageComponentNames(cap, policy)
	data.LoadImageComponents = loadComponents
	report.Pass("load image components",
		fmt.Sprintf("%d files: %s", len(loadComponents), strings.Join(loadComponents, ", ")))

	chunkSize := *loadBlockSize
	if chunkSize == 0 {
		chunkSize = 200 // matches securitydomain.InstallOptions default
	}
	chunkCount := (data.LoadImageSize + chunkSize - 1) / chunkSize
	data.LoadBlockSize = chunkSize
	data.LoadBlockCount = chunkCount
	report.Pass("load block plan",
		fmt.Sprintf("%d LOAD APDU(s) at %d bytes each (final block %d bytes)",
			chunkCount, chunkSize, finalBlockBytes(data.LoadImageSize, chunkSize)))

	data.PrivilegesHex = strings.ToUpper(hex.EncodeToString(privs))
	report.Pass("privileges", "0x"+data.PrivilegesHex)

	// Hash policy: today the CLI does not auto-compute a load
	// hash. The Session.Install layer accepts whatever LoadHash
	// the caller sets in InstallOptions; gp install passes nil
	// today (no hash on the wire). Surface that explicitly so an
	// operator who expects a hash to be sent knows it isn't, and
	// so a future --load-hash flag has an obvious extension
	// point. JSON consumers branching on this field will see
	// "none" today.
	data.LoadHashAlgorithm = "none"
	report.Pass("load hash", "none (host does not auto-send a hash; some SD policies require one)")

	// 3. Dry-run gate.
	if !*confirm {
		report.Skip("INSTALL [for load]", "dry-run; pass --confirm-write to actually install")
		report.Skip("LOAD blocks", "dry-run")
		report.Skip("INSTALL [for install]", "dry-run")
		_ = report.Emit(env.out, *jsonMode)
		return nil
	}

	// 4. Open SCP03 session.
	cfg, err := scp03Keys.applyToConfig()
	if err != nil {
		return err
	}
	sdAID, err := decodeSDAIDFlag(*sdAIDHex)
	if err != nil {
		report.Fail("sd-aid", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	if sdAID != nil {
		cfg.SelectAID = sdAID
		report.Pass("sd-aid", strings.ToUpper(hex.EncodeToString(sdAID)))
	}
	t, err := env.connect(ctx, *reader)
	if err != nil {
		return err
	}
	defer t.Close()

	report.Pass("SCP03 keys", scp03Keys.describeKeys(cfg))
	sd, err := securitydomain.OpenSCP03(ctx, t, cfg)
	if err != nil {
		report.Fail("open SCP03 SD", err.Error())
		_ = report.Emit(env.out, *jsonMode)
		return fmt.Errorf("open SCP03 SD: %w", err)
	}
	defer sd.Close()
	data.Protocol = sd.Protocol()
	report.Pass("open SCP03 SD", scp03Keys.describeKeys(cfg))

	// Optional CIN pin. If --expected-card-id was supplied,
	// verify the card's CIN before sending any destructive APDU.
	// Mismatch aborts the install with no card mutation.
	if err := verifyExpectedCardID(ctx, sd, *expectedCardID, report); err != nil {
		_ = report.Emit(env.out, *jsonMode)
		return err
	}

	// 5. Install. Failure surfaces a PartialInstallError describing
	//    the stage; we map that to per-stage check lines so the
	//    operator sees exactly where the chain stopped.
	opts := securitydomain.InstallOptions{
		LoadFileAID:   loadFileAID,
		LoadImage:     loadImage,
		ModuleAID:     moduleAID,
		AppletAID:     appletAID,
		Privileges:    privs,
		LoadBlockSize: *loadBlockSize,
	}
	if err := sd.Install(ctx, opts); err != nil {
		recordInstallFailure(report, data, err)
		_ = report.Emit(env.out, *jsonMode)
		return err
	}
	report.Pass("INSTALL [for load]", fmt.Sprintf("load file %s registered", data.PackageAID))
	report.Pass("LOAD blocks", fmt.Sprintf("%d bytes streamed", data.LoadImageSize))
	report.Pass("INSTALL [for install]", fmt.Sprintf("applet %s installed", data.AppletAID))

	if err := report.Emit(env.out, *jsonMode); err != nil {
		return err
	}
	if report.HasFailure() {
		return errors.New("gp install: one or more checks failed")
	}
	return nil
}

// recordInstallFailure converts a PartialInstallError into per-
// stage report lines and populates the JSON failure fields.
// Called from cmdGPInstall on the install error path.
func recordInstallFailure(report *Report, data *gpInstallData, err error) {
	var pe *securitydomain.PartialInstallError
	if !errors.As(err, &pe) {
		// Not a PartialInstallError: transport-level or
		// validation error before stage 1 even started.
		report.Fail("install", err.Error())
		return
	}

	data.Stage = pe.Stage.String()
	data.BytesLoaded = pe.BytesLoaded
	data.CleanupHint = pe.CleanupRecipe()

	// Walk through each stage and emit PASS up to the failure,
	// FAIL at the failure, SKIP after. This matches the mental
	// model an operator is reading the report with.
	switch pe.Stage {
	case securitydomain.StageInstallForLoad:
		report.Fail("INSTALL [for load]", pe.Error())
		report.Skip("LOAD blocks", "stage 1 failed; not attempted")
		report.Skip("INSTALL [for install]", "stage 1 failed; not attempted")
	case securitydomain.StageLoad:
		report.Pass("INSTALL [for load]", fmt.Sprintf("load file %s allocated", data.PackageAID))
		report.Fail("LOAD blocks",
			fmt.Sprintf("%s after %d/%d bytes", pe.Error(), pe.BytesLoaded, pe.TotalLoadBytes))
		report.Skip("INSTALL [for install]", "stage 2 failed; not attempted")
	case securitydomain.StageInstallForInstall:
		report.Pass("INSTALL [for load]", fmt.Sprintf("load file %s allocated", data.PackageAID))
		report.Pass("LOAD blocks", fmt.Sprintf("%d bytes streamed", pe.TotalLoadBytes))
		report.Fail("INSTALL [for install]", pe.Error())
	default:
		report.Fail("install", pe.Error())
	}
	if hint := pe.CleanupRecipe(); hint != "" {
		report.Fail("cleanup recipe", hint)
	}
}

// --- shared AID parsing helpers (also used by cmd_gp_delete) ----------

// decodeHexAID parses a hex AID string and validates the ISO/IEC
// 7816-5 length range. Used by every CLI flag that takes an AID.
func decodeHexAID(s, fieldName string) ([]byte, error) {
	cleaned := stripWhitespace(s)
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fieldName, err)
	}
	if len(b) < 5 || len(b) > 16 {
		return nil, fmt.Errorf("%s: length %d invalid (must be 5..16 bytes per ISO/IEC 7816-5)",
			fieldName, len(b))
	}
	return b, nil
}

// decodeAIDOrCAPDefault returns the user-supplied AID when non-
// empty, otherwise the CAP-parsed default. The default arrives as
// a raw byte slice to avoid threading the gp.AID type through this
// CLI helper.
func decodeAIDOrCAPDefault(userInput, fieldName string, capDefault []byte) ([]byte, error) {
	if userInput == "" {
		if len(capDefault) == 0 {
			return nil, fmt.Errorf("%s: CAP did not provide a default; --%s is required", fieldName, fieldName)
		}
		out := make([]byte, len(capDefault))
		copy(out, capDefault)
		return out, nil
	}
	return decodeHexAID(userInput, fieldName)
}

// stripWhitespace removes spaces and colons commonly used as AID
// readability separators ("D2 76 00 01 24 01" or "D2:76:00:01:24:01"
// both decode to D2760001 2401).
func stripWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// loadImageComponentNames returns the names of CAP components
// that survive the load-image policy filter, in load order. Used
// to populate the dry-run preflight so an operator can verify
// the Debug/Descriptor exclusion took effect before authorizing
// the write.
func loadImageComponentNames(cap *gp.CAPFile, policy gp.LoadImagePolicy) []string {
	keep := cap.LoadImageComponents(policy)
	names := make([]string, 0, len(keep))
	for _, c := range keep {
		names = append(names, c.Name)
	}
	return names
}

// finalBlockBytes returns the size of the last LOAD chunk given
// the total image size and chunk size, used in the preflight
// summary so an operator can spot a near-empty trailing block
// (a sign the image size isn't aligned to the chunk size in a
// way that would matter on cards with strict block alignment).
func finalBlockBytes(total, chunk int) int {
	if chunk <= 0 || total <= 0 {
		return 0
	}
	rem := total % chunk
	if rem == 0 {
		return chunk
	}
	return rem
}
