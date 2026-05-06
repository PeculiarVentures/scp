package mockcard

import (
	"bytes"
	"encoding/binary"

	"github.com/PeculiarVentures/scp/apdu"
)

// GP card-content management commands per Card Spec v2.3.1 §11.5
// (INSTALL), §11.6 (LOAD), and §11.2 (DELETE). The mock supports
// the subset that scpctl's gp install / gp delete need to drive
// end-to-end without hardware:
//
//   1. INSTALL [for load]    P1=0x02   start a load file installation
//   2. LOAD                  multi-block stream of CAP component bytes
//   3. INSTALL [for install] P1=0x04   instantiate an applet from
//                                       a previously-loaded executable
//                                       load file
//   4. DELETE                            remove an applet, load file,
//                                       or load file plus its modules
//
// The mock validates command framing (P1, data layout, sequence
// counters) and updates RegistryLoadFiles / RegistryApps so that a
// subsequent GET STATUS reflects the installed package and applet.
// It does NOT validate the CAP byte stream for Java Card semantics:
// any well-framed LOAD chain produces a successful install. The
// reason: the host-side CAP parser already checks structural
// validity, and the mock's job is to exercise the host-side
// command builders, not to validate Java Card runtime constraints.
//
// State transitions:
//
//   loadCtx == nil                        idle
//   INSTALL [for load]                  → loadCtx populated, loadAccum reset
//   LOAD with P1 bit 7 = 0              → append to loadAccum, increment seq
//   LOAD with P1 bit 7 = 1 (final)      → append, finalize: register load
//                                         file in RegistryLoadFiles, clear
//                                         loadCtx
//   INSTALL [for install] (post-load)   → register applet in RegistryApps
//                                         linked to the load file's package
//   DELETE                              → remove matching entry/entries
//
// Outside this state machine, the handlers tolerate INSTALL [for
// install] without a preceding INSTALL [for load] (for tests that
// pre-populate RegistryLoadFiles directly), and DELETE on a
// non-existent AID returns SW=6A88 per GP §11.2.3.

// installLoadContext records the in-flight INSTALL [for load] state.
// Cleared when the load completes (successful final LOAD block) or
// when a new INSTALL [for load] starts.
type installLoadContext struct {
	loadFileAID  []byte
	sdAID        []byte
	loadParams   []byte
	expectedSeq  byte
	bytesLoaded  []byte
}

// doInstall is the GP §11.5 INSTALL handler. The command's P1
// byte selects which INSTALL variant the operator is issuing;
// the mock supports the two variants used by gp install:
//
//	0x02  INSTALL [for load]      load file allocation + ELF metadata
//	0x04  INSTALL [for install]   applet instantiation from a loaded ELF
//
// Other P1 variants (combined load+install 0x06, personalization
// 0x20, registry update 0x40) are rejected with SW=6A86. They
// can be added when a caller needs them.
//
// Data formatting per GP Table 11-50 is checked at the framing
// level: lengths must be consistent, AIDs must fit ISO/IEC 7816-5
// bounds, and the final response is SW=9000 on success or a
// specific error SW on framing rejection.
func (c *Card) doInstall(cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.P2 != 0x00 {
		// P2 is reserved (must be 0x00) for the variants we support.
		return mkSW(0x6A86), nil
	}
	switch cmd.P1 {
	case 0x02:
		return c.doInstallForLoad(cmd)
	case 0x04:
		return c.doInstallForInstall(cmd)
	default:
		return mkSW(0x6A86), nil
	}
}

// doInstallForLoad parses the INSTALL [for load] payload per GP
// §11.5.2.3.1: load file AID + SD AID + load file data block hash
// + load parameters + load token. Hash and token are accepted as
// opaque blobs; the mock does not verify them because that would
// require key material the test fixture won't have.
func (c *Card) doInstallForLoad(cmd *apdu.Command) (*apdu.Response, error) {
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil // wrong data
	}
	if err := validateAIDLen(loadAID); err != nil {
		return mkSW(0x6A80), nil
	}
	sdAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if len(sdAID) != 0 { // 0-length sdAID = current SD; else must be valid AID
		if err := validateAIDLen(sdAID); err != nil {
			return mkSW(0x6A80), nil
		}
	}
	// Hash, params, token: each is length-prefixed; we read but do
	// not validate the content. Parsing them ensures the framing
	// is well-formed.
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80), nil
	}
	loadParams, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80), nil
	}
	if len(d) != 0 {
		return mkSW(0x6A80), nil // trailing bytes after token
	}

	c.loadCtx = &installLoadContext{
		loadFileAID: append([]byte(nil), loadAID...),
		sdAID:       append([]byte(nil), sdAID...),
		loadParams:  append([]byte(nil), loadParams...),
		expectedSeq: 0,
	}
	return mkSW(0x9000), nil
}

// doInstallForInstall parses INSTALL [for install] per GP
// §11.5.2.3.2: load file AID + module AID + applet AID + privileges
// + install parameters + install token. The mock registers the
// applet in RegistryApps under the supplied applet AID and links
// it back to the load file via the load file AID.
//
// If no preceding INSTALL [for load] established the context (or
// the load file AID doesn't match what was loaded), the handler
// still proceeds: tests sometimes pre-populate RegistryLoadFiles
// directly. In real cards this would 6A88, but exercising that
// rejection is not what mock tests typically need; tests that need
// strict-state coverage should set Card.StrictInstallState=true
// (not implemented here; would be a small extension when needed).
func (c *Card) doInstallForInstall(cmd *apdu.Command) (*apdu.Response, error) {
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if err := validateAIDLen(loadAID); err != nil {
		return mkSW(0x6A80), nil
	}
	moduleAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if err := validateAIDLen(moduleAID); err != nil {
		return mkSW(0x6A80), nil
	}
	appletAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if err := validateAIDLen(appletAID); err != nil {
		return mkSW(0x6A80), nil
	}
	privs, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80), nil
	}
	if len(privs) < 1 || len(privs) > 3 {
		return mkSW(0x6A80), nil
	}
	// install_params and install_token: parse for framing only.
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80), nil
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80), nil
	}
	if len(d) != 0 {
		return mkSW(0x6A80), nil
	}

	// Store privilege bytes right-padded to 3 bytes (GP-modern
	// privilege mask layout; older 1-byte form left-aligned into
	// the 3-byte buffer matches what gpCommands' encoder emits).
	var privMask [3]byte
	copy(privMask[:], privs)

	entry := MockRegistryEntry{
		AID:             append([]byte(nil), appletAID...),
		Lifecycle:       0x07, // INSTALLED + SELECTABLE per GP Table 11-2
		Privileges:      privMask,
		AssociatedSDAID: append([]byte(nil), loadAID...),
	}
	c.RegistryApps = append(c.RegistryApps, entry)
	return mkSW(0x9000), nil
}

// doLoad implements the GP §11.6 LOAD command sequence. P1 bit 7
// is the "last block" indicator; P1 bits 0..6 plus P2 form the
// block sequence counter. Real cards may quibble about whether the
// sequence wraps at P2 or includes P1's low bits; the mock checks
// monotonic increment against expectedSeq and flags a mismatch
// with SW=6A86 (incorrect P1/P2) so test code that builds the
// chain incorrectly fails loudly rather than silently.
//
// The data field is the next slice of the CAP load image. The mock
// appends to bytesLoaded; on the final-block (P1 bit 7 set) it
// converts the accumulated payload into a RegistryLoadFiles entry
// and clears loadCtx.
func (c *Card) doLoad(cmd *apdu.Command) (*apdu.Response, error) {
	if c.loadCtx == nil {
		// LOAD without preceding INSTALL [for load]: real cards
		// 6985 (conditions not satisfied). Use that here.
		return mkSW(0x6985), nil
	}
	last := cmd.P1&0x80 != 0
	seq := cmd.P2
	if seq != c.loadCtx.expectedSeq {
		return mkSW(0x6A86), nil
	}
	c.loadCtx.bytesLoaded = append(c.loadCtx.bytesLoaded, cmd.Data...)
	c.loadCtx.expectedSeq++

	if !last {
		return mkSW(0x9000), nil
	}

	// Final block: register the load file. The mock does NOT
	// re-parse the CAP — the host-side parser already validated
	// it. The registry entry records AID, lifecycle, and a
	// non-empty Version slice so GET STATUS shows it as a real
	// load file rather than a placeholder.
	entry := MockRegistryEntry{
		AID:       append([]byte(nil), c.loadCtx.loadFileAID...),
		Lifecycle: 0x01, // LOADED per GP Table 11-3
		Version:   versionFromLoadParams(c.loadCtx.loadParams),
	}
	c.RegistryLoadFiles = append(c.RegistryLoadFiles, entry)
	c.loadCtx = nil
	return mkSW(0x9000), nil
}

// doDelete implements GP §11.2 DELETE. P1 is reserved (0x00); P2
// bit 0 selects "delete object plus related objects" (load file
// AND its modules and instantiated applets) vs. "delete object
// only" (just the named entry). Data is a TLV stream where each
// 0x4F element names an object to delete — but in practice a
// single-AID DELETE is what every caller emits, so the mock
// supports the single-AID case strictly.
//
// SW=6A88 is returned when the named AID is not present in any
// registry; this matches real-card behavior and gives the host
// PartialInstallError logic a deterministic outcome to recover
// from.
func (c *Card) doDelete(cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.P1 != 0x00 {
		return mkSW(0x6A86), nil
	}
	deleteRelated := cmd.P2&0x01 != 0

	// Parse TLV: tag 0x4F (AID) plus optional 0x9E (CRT) which the
	// mock ignores. We require at least one 0x4F.
	d := cmd.Data
	if len(d) < 2 || d[0] != 0x4F {
		return mkSW(0x6A80), nil
	}
	aidLen := int(d[1])
	if 2+aidLen > len(d) {
		return mkSW(0x6A80), nil
	}
	aid := d[2 : 2+aidLen]
	if err := validateAIDLen(aid); err != nil {
		return mkSW(0x6A80), nil
	}

	if c.deleteFromRegistries(aid, deleteRelated) {
		return mkSW(0x9000), nil
	}
	return mkSW(0x6A88), nil // referenced data not found
}

// deleteFromRegistries removes any entry matching aid from the
// three registries. With deleteRelated, also removes RegistryApps
// entries whose AssociatedSDAID points at aid (the load file
// being deleted), modeling GP's "delete with cascading references"
// behavior. Returns true if at least one entry was removed.
func (c *Card) deleteFromRegistries(aid []byte, deleteRelated bool) bool {
	removed := false
	c.RegistryISD, removed = filterOutAID(c.RegistryISD, aid, removed)
	c.RegistryApps, removed = filterOutAID(c.RegistryApps, aid, removed)
	c.RegistryLoadFiles, removed = filterOutAID(c.RegistryLoadFiles, aid, removed)
	if deleteRelated {
		// Remove apps that were instantiated from the deleted
		// load file. AssociatedSDAID==aid is the link.
		c.RegistryApps, removed = filterOutAssociatedSD(c.RegistryApps, aid, removed)
	}
	return removed
}

func filterOutAID(in []MockRegistryEntry, aid []byte, anyRemoved bool) ([]MockRegistryEntry, bool) {
	out := in[:0]
	for _, e := range in {
		if bytes.Equal(e.AID, aid) {
			anyRemoved = true
			continue
		}
		out = append(out, e)
	}
	return out, anyRemoved
}

func filterOutAssociatedSD(in []MockRegistryEntry, sdAID []byte, anyRemoved bool) ([]MockRegistryEntry, bool) {
	out := in[:0]
	for _, e := range in {
		if bytes.Equal(e.AssociatedSDAID, sdAID) {
			anyRemoved = true
			continue
		}
		out = append(out, e)
	}
	return out, anyRemoved
}

// readLV reads a single length-value field: u1 length followed by
// length bytes. Returns the value, the rest of the buffer, and
// ok=false on truncation.
func readLV(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 1 {
		return nil, nil, false
	}
	n := int(b[0])
	if 1+n > len(b) {
		return nil, nil, false
	}
	return b[1 : 1+n], b[1+n:], true
}

// validateAIDLen enforces ISO/IEC 7816-5 5..16 byte AID length.
// Returns a sentinel-style error; callers map to SW=6A80.
func validateAIDLen(aid []byte) error {
	if len(aid) < 5 || len(aid) > 16 {
		return errInvalidAIDLen
	}
	return nil
}

var errInvalidAIDLen = &installError{"invalid AID length"}

type installError struct{ msg string }

func (e *installError) Error() string { return e.msg }

// versionFromLoadParams extracts a 2-byte version hint from the
// INSTALL [for load] parameters block when present (tag 0xC8 in
// the LV-prefixed parameters TLV stream). Returns nil when no
// version is encoded; the GET STATUS response then omits the
// 0xCE Version TLV. Used so installed load files round-trip with
// a recognizable version field rather than always appearing as
// "unversioned" in registry walks.
func versionFromLoadParams(params []byte) []byte {
	for len(params) >= 2 {
		tag := params[0]
		ln := int(params[1])
		if 2+ln > len(params) {
			return nil
		}
		if tag == 0xC8 && ln == 2 {
			return append([]byte(nil), params[2:4]...)
		}
		params = params[2+ln:]
	}
	return nil
}

// _ uses binary to silence unused-import warnings in case future
// LOAD parsing reads big-endian fields.
var _ = binary.BigEndian
