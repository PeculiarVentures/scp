package securitydomain

import (
	"context"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/gp"
)

// InstallStage identifies which stage of an install chain failed,
// surfaced through PartialInstallError so the caller can describe
// the card's residual state and prescribe the correct cleanup.
//
// A successful install passes through stages in order:
// InstallForLoad, then Load (one or more LOAD blocks), then
// InstallForInstall. A failure returns PartialInstallError with
// Stage set to the LAST stage that was attempted (which may have
// partially applied), not the next stage that wasn't reached.
type InstallStage int

const (
	// StageInstallForLoad failed before any load file allocation
	// was registered on the card. Cleanup: nothing to do; retry
	// after addressing the underlying cause.
	StageInstallForLoad InstallStage = iota + 1

	// StageLoad failed mid-stream. Cleanup: DELETE the load file
	// AID with the related-objects flag. Retry: reissue the full
	// install chain after delete.
	StageLoad

	// StageInstallForInstall failed after the load file was fully
	// loaded but before the applet was instantiated. Cleanup:
	// DELETE the load file (and its modules); the applet was
	// never registered. Retry: reissue INSTALL [for install] OR
	// reissue the full chain — both are valid.
	StageInstallForInstall
)

// String returns a human-readable name for the stage.
func (s InstallStage) String() string {
	switch s {
	case StageInstallForLoad:
		return "INSTALL [for load]"
	case StageLoad:
		return "LOAD"
	case StageInstallForInstall:
		return "INSTALL [for install]"
	default:
		return fmt.Sprintf("InstallStage(%d)", int(s))
	}
}

// PartialInstallError carries the recovery context for a failed
// install chain: which stage failed, what got partially applied,
// and the underlying cause. The caller (typically scpctl gp
// install) uses this to print a precise cleanup recipe rather
// than a generic "install failed" that leaves the operator
// guessing about card state.
//
// Returned by Session.Install when any stage of the install chain
// fails. Use errors.As to extract:
//
//	var pe *PartialInstallError
//	if errors.As(err, &pe) {
//	    fmt.Fprintf(os.Stderr, "install failed at %s: %v\n", pe.Stage, pe.Cause)
//	    if pe.LoadFileAID != nil {
//	        fmt.Fprintf(os.Stderr, "cleanup: scpctl gp delete --aid %X --related\n", pe.LoadFileAID)
//	    }
//	}
//
// Unwrap returns the underlying cause so errors.Is still works
// against transport-level or APDU-level errors.
type PartialInstallError struct {
	// Stage is the stage at which the failure surfaced.
	Stage InstallStage

	// LoadFileAID is the load file's AID. Set whenever
	// INSTALL [for load] succeeded — even if a later stage failed.
	// Empty when StageInstallForLoad itself failed.
	LoadFileAID []byte

	// AppletAID is the applet AID we were trying to instantiate.
	// Set when InstallForInstall was attempted; not necessarily
	// registered on the card if Stage=StageInstallForInstall
	// (the failure may have happened before or during card-side
	// registration).
	AppletAID []byte

	// BytesLoaded is the count of CAP image bytes successfully
	// streamed to the card before LOAD failed (Stage=StageLoad)
	// or completed (Stage=StageInstallForInstall). Zero before
	// any LOAD block was sent.
	BytesLoaded int

	// TotalLoadBytes is the total CAP image size in bytes. Same
	// regardless of stage; lets the caller compute a percentage
	// for diagnostic output.
	TotalLoadBytes int

	// LastBlockSeq is the sequence number of the last LOAD block
	// the card acknowledged with 9000. -1 before any block was
	// sent. With Stage=StageLoad, this plus 1 is the block that
	// failed.
	LastBlockSeq int

	// SW carries the card's status word when the failure was an
	// APDU-level rejection (e.g. 6A84 not enough memory). Zero
	// when the failure was a transport error (Cause then carries
	// the I/O error).
	SW uint16

	// Cause is the underlying error: a transport error, a wrapped
	// APDU error, or a precondition error (auth not satisfied).
	// errors.Unwrap returns this.
	Cause error
}

// Error implements the error interface.
func (e *PartialInstallError) Error() string {
	desc := fmt.Sprintf("install failed at %s", e.Stage)
	if e.SW != 0 {
		desc += fmt.Sprintf(" (SW=%04X)", e.SW)
	}
	if e.Stage == StageLoad && e.TotalLoadBytes > 0 {
		desc += fmt.Sprintf(" after %d/%d bytes", e.BytesLoaded, e.TotalLoadBytes)
	}
	if e.Cause != nil {
		desc += ": " + e.Cause.Error()
	}
	return desc
}

// Unwrap returns the underlying cause for errors.Is/As traversal.
func (e *PartialInstallError) Unwrap() error { return e.Cause }

// CleanupRecipe returns a short imperative description of how to
// recover from this partial install. The caller can print this
// alongside the error for operator guidance. Returns "" when
// nothing got partially applied (StageInstallForLoad failure).
func (e *PartialInstallError) CleanupRecipe() string {
	if len(e.LoadFileAID) == 0 {
		return ""
	}
	return fmt.Sprintf("DELETE load file %X with --related to remove any partially-loaded state",
		e.LoadFileAID)
}

// InstallOptions is the high-level Install API input. Either
// supply pre-computed parameters and a load image (caller has
// already parsed the CAP), or wrap a CAP file with one of the
// helpers in package gp.
//
// Required fields:
//   - LoadFileAID: AID of the load file (package AID from the CAP)
//   - LoadImage:   bytes of the load file data block (concatenated
//                  CAP components in the order GP §F.2 specifies)
//   - ModuleAID:   AID of the applet's class within the package
//   - AppletAID:   AID under which the instantiated applet is
//                  registered (often equals ModuleAID for single-
//                  class applets but not always)
//
// Optional fields:
//   - SDAID:           target SD AID; empty means current SD (most common)
//   - LoadParams:      INSTALL [for load] parameters (tag-0xC8 version, etc.)
//   - LoadHash:        load file data block hash for integrity check
//   - LoadToken:       load token if the SD requires one
//   - InstallParams:   INSTALL [for install] parameters (applet-specific)
//   - InstallToken:    install token if the SD requires one
//   - Privileges:      applet privilege bytes (1 or 3 bytes; default 0x00)
//   - LoadBlockSize:   chunk size for LOAD; 0 means default 200 bytes
type InstallOptions struct {
	LoadFileAID []byte
	LoadImage   []byte
	ModuleAID   []byte
	AppletAID   []byte

	SDAID         []byte
	LoadParams    []byte
	LoadHash      []byte
	LoadToken     []byte
	InstallParams []byte
	InstallToken  []byte
	Privileges    []byte

	LoadBlockSize int
}

// defaultLoadBlockSize is conservative (~200 bytes) to fit short-Lc
// commands while leaving room for SM overhead (8-byte C-MAC, plus
// padding when C-DEC is on). Real cards advertise their max load
// buffer in CardData; tuning to that is an optimization the host
// can do once it's parsed CardData. 200 is safe for every card we
// know of and only adds a couple of round trips for typical CAPs.
const defaultLoadBlockSize = 200

// Install performs the full install chain (INSTALL [for load] →
// LOAD → INSTALL [for install]) under the current SCP session,
// returning nil on success or a *PartialInstallError describing
// the failure stage and recovery context.
//
// Requires an authenticated session (returns ErrAuthRequired
// otherwise). Operates under whatever security level the session
// was opened with; encrypted sessions stream the LOAD blocks
// encrypted automatically through the embedded transport.
//
// The chain is non-atomic at the card layer: a failure mid-chain
// leaves residual state. The PartialInstallError contains the
// info needed to remediate. Callers building scripted flows
// should always check for *PartialInstallError before treating
// any error as a clean retry.
func (s *Session) Install(ctx context.Context, opts InstallOptions) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if err := validateInstallOptions(opts); err != nil {
		return err
	}

	// Stage 1: INSTALL [for load].
	if err := s.installForLoad(ctx, opts); err != nil {
		return &PartialInstallError{
			Stage:          StageInstallForLoad,
			TotalLoadBytes: len(opts.LoadImage),
			LastBlockSeq:   -1,
			SW:             swFromError(err),
			Cause:          err,
		}
	}

	// Stage 2: LOAD blocks. We track progress so a failure mid-
	// stream produces an accurate PartialInstallError.
	bytesLoaded, lastSeq, err := s.loadImageInBlocks(ctx, opts)
	if err != nil {
		return &PartialInstallError{
			Stage:          StageLoad,
			LoadFileAID:    cloneBytes(opts.LoadFileAID),
			BytesLoaded:    bytesLoaded,
			TotalLoadBytes: len(opts.LoadImage),
			LastBlockSeq:   lastSeq,
			SW:             swFromError(err),
			Cause:          err,
		}
	}

	// Stage 3: INSTALL [for install].
	if err := s.installForInstall(ctx, opts); err != nil {
		return &PartialInstallError{
			Stage:          StageInstallForInstall,
			LoadFileAID:    cloneBytes(opts.LoadFileAID),
			AppletAID:      cloneBytes(opts.AppletAID),
			BytesLoaded:    len(opts.LoadImage),
			TotalLoadBytes: len(opts.LoadImage),
			LastBlockSeq:   lastSeq,
			SW:             swFromError(err),
			Cause:          err,
		}
	}
	return nil
}

func validateInstallOptions(opts InstallOptions) error {
	if err := validateAID(opts.LoadFileAID, "LoadFileAID"); err != nil {
		return err
	}
	if err := validateAID(opts.ModuleAID, "ModuleAID"); err != nil {
		return err
	}
	if err := validateAID(opts.AppletAID, "AppletAID"); err != nil {
		return err
	}
	if len(opts.SDAID) != 0 {
		if err := validateAID(opts.SDAID, "SDAID"); err != nil {
			return err
		}
	}
	if len(opts.LoadImage) == 0 {
		return errors.New("install: LoadImage must be non-empty")
	}
	if len(opts.Privileges) > 3 {
		return fmt.Errorf("install: Privileges length %d invalid (must be 0..3 bytes)", len(opts.Privileges))
	}
	return nil
}

func validateAID(aid []byte, fieldName string) error {
	if len(aid) < 5 || len(aid) > 16 {
		return fmt.Errorf("install: %s length %d invalid (must be 5..16 bytes per ISO/IEC 7816-5)",
			fieldName, len(aid))
	}
	return nil
}

func (s *Session) installForLoad(ctx context.Context, opts InstallOptions) error {
	data := gp.BuildInstallForLoadPayload(
		opts.LoadFileAID, opts.SDAID, opts.LoadHash, opts.LoadParams, opts.LoadToken)
	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  0xE6,
		P1:   0x02, // INSTALL [for load]
		P2:   0x00,
		Data: data,
	}
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return err
	}
	return checkSW(resp, "INSTALL [for load]")
}

// loadImageInBlocks streams the load image to the card in chunks
// of opts.LoadBlockSize (or the default). Returns the number of
// bytes successfully written and the last sequence number the
// card acknowledged. On error, those counts reflect what was
// confirmed up to the failure — useful in PartialInstallError so
// the operator knows how far the load progressed.
func (s *Session) loadImageInBlocks(ctx context.Context, opts InstallOptions) (bytesLoaded, lastSeq int, err error) {
	blockSize := opts.LoadBlockSize
	if blockSize <= 0 {
		blockSize = defaultLoadBlockSize
	}
	image := opts.LoadImage
	totalBlocks := (len(image) + blockSize - 1) / blockSize
	if totalBlocks == 0 {
		return 0, -1, errors.New("load: image is empty")
	}
	if totalBlocks > 256 {
		// LOAD sequence counter is 1 byte (P2). 256 blocks at
		// blockSize bytes each gives 256*blockSize byte capacity;
		// past that, the host must fragment differently or use
		// a larger blockSize.
		return 0, -1, fmt.Errorf("load: image too large: %d bytes / %d-byte blocks > 256 LOAD blocks",
			len(image), blockSize)
	}

	lastSeq = -1
	for seq := 0; seq < totalBlocks; seq++ {
		start := seq * blockSize
		end := start + blockSize
		if end > len(image) {
			end = len(image)
		}
		isLast := (seq == totalBlocks-1)

		var p1 byte
		if isLast {
			p1 = 0x80
		}
		cmd := &apdu.Command{
			CLA:  clsGP,
			INS:  0xE8,
			P1:   p1,
			P2:   byte(seq),
			Data: image[start:end],
		}
		resp, err := s.transmit(ctx, cmd)
		if err != nil {
			return bytesLoaded, lastSeq, err
		}
		if err := checkSW(resp, fmt.Sprintf("LOAD block %d", seq)); err != nil {
			return bytesLoaded, lastSeq, err
		}
		bytesLoaded = end
		lastSeq = seq
	}
	return bytesLoaded, lastSeq, nil
}

func (s *Session) installForInstall(ctx context.Context, opts InstallOptions) error {
	privs := opts.Privileges
	if len(privs) == 0 {
		privs = []byte{0x00}
	}
	data := gp.BuildInstallForInstallPayload(
		opts.LoadFileAID, opts.ModuleAID, opts.AppletAID, privs,
		opts.InstallParams, opts.InstallToken)
	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  0xE6,
		P1:   0x04, // INSTALL [for install]
		P2:   0x00,
		Data: data,
	}
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return err
	}
	return checkSW(resp, "INSTALL [for install]")
}

// Delete removes a registered AID from the card. With related=true,
// also cascades to applets instantiated from the deleted load file
// (GP §11.2 P2 bit 0). Returns nil on success, an APDUError
// (wrapping SW=6A88 "referenced data not found") if the AID isn't
// on the card, or a transport error.
//
// Requires an authenticated session.
func (s *Session) Delete(ctx context.Context, aid []byte, related bool) error {
	if err := s.requireAuth(); err != nil {
		return err
	}
	if err := validateAID(aid, "aid"); err != nil {
		return err
	}
	var p2 byte
	if related {
		p2 = 0x01
	}
	// Per GP §11.2.2.1 the data field is a TLV with one or more
	// 0x4F (AID) elements. We emit a single 0x4F since real-card
	// support for multi-AID DELETE is sparse and the CLI exposes
	// one AID per invocation.
	data := append([]byte{0x4F, byte(len(aid))}, aid...)
	cmd := &apdu.Command{
		CLA:  clsGP,
		INS:  0xE4,
		P1:   0x00,
		P2:   p2,
		Data: data,
	}
	resp, err := s.transmit(ctx, cmd)
	if err != nil {
		return err
	}
	return checkSW(resp, "DELETE")
}

// --- payload builders ---------------------------------------------------
//
// Wire format builders live in package gp; this file just calls
// into them. The builders are public so test fixtures driving
// the mock APDU dispatch use the same code path the production
// session does — a regression in wire layout fails everywhere at
// once rather than diverging between host and tests.

// --- helpers ------------------------------------------------------------

// checkSW returns nil if the response is 9000, otherwise an
// APDUError describing the rejection. Uses the operation name so
// downstream errors say "INSTALL [for load] rejected (SW=6A84)"
// rather than just "rejected (SW=6A84)".
func checkSW(resp *apdu.Response, operation string) error {
	if resp == nil {
		return fmt.Errorf("%s: nil response", operation)
	}
	sw := uint16(resp.SW1)<<8 | uint16(resp.SW2)
	if sw == 0x9000 {
		return nil
	}
	return &APDUError{Operation: operation, SW: sw}
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
