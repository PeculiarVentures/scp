package mockcard

import (
	"bytes"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// GPState is the GlobalPlatform card-content management state that
// can be shared by multiple secure-channel mock fronts (SCP11 in
// mockcard.Card, SCP03 in mockcard.SCP03Card). It owns the three
// registry slices plus the in-flight INSTALL [for load] context,
// and provides the GP §11.x command handlers as methods.
//
// Tests usually access the registry slices directly through the
// embedding mock type's promoted fields (e.g. card.RegistryISD).
// GPState does not export per-handler entry points because the
// expected entry path is always through the embedding mock's APDU
// dispatch.
type GPState struct {
	// RegistryISD, RegistryApps, RegistryLoadFiles back the GP
	// GET STATUS handler. Tests populate these to control what the
	// mock claims is installed. An empty slice for any scope makes
	// that scope return SW=6A88 (referenced data not found),
	// matching real-card behavior on a barren registry.
	RegistryISD       []MockRegistryEntry
	RegistryApps      []MockRegistryEntry
	RegistryLoadFiles []MockRegistryEntry

	// loadCtx tracks in-flight INSTALL [for load] state across the
	// LOAD command sequence. Nil when no load is in progress;
	// populated by handleInstallForLoad and cleared by the final
	// LOAD block.
	loadCtx *installLoadContext

	// FailNextInstallForLoad, if non-zero, makes the next
	// INSTALL [for load] return this SW instead of 9000. Cleared
	// after firing once. Used by Install failure-recovery tests
	// to simulate card-side rejection at stage 1.
	FailNextInstallForLoad uint16

	// FailLoadAtSeq, if >= 0, makes the LOAD block with this
	// sequence number return SW=6A84 (not enough memory).
	// Default zero-value 0 would fail the very first block; set
	// to -1 explicitly to disable. The handler decrements
	// FailLoadAtSeq toward -1 internally so it fires only once.
	FailLoadAtSeq int

	// FailNextInstallForInstall, if non-zero, makes the next
	// INSTALL [for install] return this SW instead of 9000.
	// Cleared after firing once.
	FailNextInstallForInstall uint16
}

// NewGPState returns a fresh GP state with empty registries and no
// load in progress. FailLoadAtSeq is initialized to -1 (no
// failure injection) so tests that don't opt into failure mode
// don't accidentally trigger one.
func NewGPState() *GPState { return &GPState{FailLoadAtSeq: -1} }

// HandleGPCommand dispatches a GP card-content management APDU. It
// returns (nil, false) if the INS byte is not a recognized GP
// command — the caller should fall through to its own non-GP
// handlers in that case. Otherwise it returns the response and
// ok=true.
//
// Recognized INS bytes: 0xF2 GET STATUS, 0xF0 SET STATUS, 0xE6
// INSTALL, 0xE8 LOAD, 0xE4 DELETE.
func (g *GPState) HandleGPCommand(cmd *apdu.Command) (*apdu.Response, bool) {
	switch cmd.INS {
	case 0xF2:
		return g.handleGetStatus(cmd), true
	case 0xF0:
		return g.handleSetStatus(cmd), true
	case 0xE6:
		return g.handleInstall(cmd), true
	case 0xE8:
		return g.handleLoad(cmd), true
	case 0xE4:
		return g.handleDelete(cmd), true
	}
	return nil, false
}

// --- GET STATUS / SET STATUS (originally in mockcard/getstatus.go) ----

func (g *GPState) handleGetStatus(cmd *apdu.Command) *apdu.Response {
	if cmd.P2 != 0x02 {
		return mkSW(0x6A86)
	}

	var (
		entries        []MockRegistryEntry
		includeModules bool
	)
	switch cmd.P1 {
	case statusScopeISD:
		entries = g.RegistryISD
	case statusScopeApplications:
		entries = g.RegistryApps
	case statusScopeLoadFiles:
		entries = g.RegistryLoadFiles
	case statusScopeLoadFilesAndModules:
		entries = g.RegistryLoadFiles
		includeModules = true
	default:
		return mkSW(0x6A86)
	}

	if len(entries) == 0 {
		return mkSW(0x6A88)
	}

	var nodes []*tlv.Node
	for i := range entries {
		nodes = append(nodes, entries[i].encode(includeModules))
	}
	var body []byte
	for _, n := range nodes {
		body = append(body, n.Encode()...)
	}
	return &apdu.Response{Data: body, SW1: 0x90, SW2: 0x00}
}

func (g *GPState) handleSetStatus(cmd *apdu.Command) *apdu.Response {
	if cmd.P1 != 0x80 {
		return mkSW(0x6A86)
	}
	if len(g.RegistryISD) == 0 {
		g.RegistryISD = []MockRegistryEntry{{
			AID:       []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00},
			Lifecycle: cmd.P2,
		}}
	} else {
		g.RegistryISD[0].Lifecycle = cmd.P2
	}
	return mkSW(0x9000)
}

// --- INSTALL / LOAD / DELETE (originally in mockcard/install.go) ------

func (g *GPState) handleInstall(cmd *apdu.Command) *apdu.Response {
	if cmd.P2 != 0x00 {
		return mkSW(0x6A86)
	}
	switch cmd.P1 {
	case 0x02:
		return g.handleInstallForLoad(cmd)
	case 0x04:
		return g.handleInstallForInstall(cmd)
	default:
		return mkSW(0x6A86)
	}
}

func (g *GPState) handleInstallForLoad(cmd *apdu.Command) *apdu.Response {
	if g.FailNextInstallForLoad != 0 {
		sw := g.FailNextInstallForLoad
		g.FailNextInstallForLoad = 0
		return mkSW(sw)
	}
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if err := validateAIDLen(loadAID); err != nil {
		return mkSW(0x6A80)
	}
	sdAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if len(sdAID) != 0 {
		if err := validateAIDLen(sdAID); err != nil {
			return mkSW(0x6A80)
		}
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80)
	}
	loadParams, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80)
	}
	if len(d) != 0 {
		return mkSW(0x6A80)
	}

	g.loadCtx = &installLoadContext{
		loadFileAID: append([]byte(nil), loadAID...),
		sdAID:       append([]byte(nil), sdAID...),
		loadParams:  append([]byte(nil), loadParams...),
		expectedSeq: 0,
	}
	return mkSW(0x9000)
}

func (g *GPState) handleInstallForInstall(cmd *apdu.Command) *apdu.Response {
	if g.FailNextInstallForInstall != 0 {
		sw := g.FailNextInstallForInstall
		g.FailNextInstallForInstall = 0
		return mkSW(sw)
	}
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if err := validateAIDLen(loadAID); err != nil {
		return mkSW(0x6A80)
	}
	moduleAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if err := validateAIDLen(moduleAID); err != nil {
		return mkSW(0x6A80)
	}
	appletAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if err := validateAIDLen(appletAID); err != nil {
		return mkSW(0x6A80)
	}
	privs, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if len(privs) < 1 || len(privs) > 3 {
		return mkSW(0x6A80)
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80)
	}
	if _, d, ok = readLV(d); !ok {
		return mkSW(0x6A80)
	}
	if len(d) != 0 {
		return mkSW(0x6A80)
	}

	var privMask [3]byte
	copy(privMask[:], privs)

	entry := MockRegistryEntry{
		AID:             append([]byte(nil), appletAID...),
		Lifecycle:       0x07,
		Privileges:      privMask,
		AssociatedSDAID: append([]byte(nil), loadAID...),
	}
	g.RegistryApps = append(g.RegistryApps, entry)
	return mkSW(0x9000)
}

func (g *GPState) handleLoad(cmd *apdu.Command) *apdu.Response {
	if g.loadCtx == nil {
		return mkSW(0x6985)
	}
	last := cmd.P1&0x80 != 0
	seq := cmd.P2
	if seq != g.loadCtx.expectedSeq {
		return mkSW(0x6A86)
	}
	if g.FailLoadAtSeq >= 0 && int(seq) == g.FailLoadAtSeq {
		g.FailLoadAtSeq = -1 // fire once
		return mkSW(0x6A84)  // not enough memory
	}
	g.loadCtx.bytesLoaded = append(g.loadCtx.bytesLoaded, cmd.Data...)
	g.loadCtx.expectedSeq++

	if !last {
		return mkSW(0x9000)
	}

	entry := MockRegistryEntry{
		AID:       append([]byte(nil), g.loadCtx.loadFileAID...),
		Lifecycle: 0x01,
		Version:   versionFromLoadParams(g.loadCtx.loadParams),
	}
	g.RegistryLoadFiles = append(g.RegistryLoadFiles, entry)
	g.loadCtx = nil
	return mkSW(0x9000)
}

func (g *GPState) handleDelete(cmd *apdu.Command) *apdu.Response {
	if cmd.P1 != 0x00 {
		return mkSW(0x6A86)
	}
	deleteRelated := cmd.P2&0x01 != 0

	d := cmd.Data
	if len(d) < 2 || d[0] != 0x4F {
		return mkSW(0x6A80)
	}
	aidLen := int(d[1])
	if 2+aidLen > len(d) {
		return mkSW(0x6A80)
	}
	aid := d[2 : 2+aidLen]
	if err := validateAIDLen(aid); err != nil {
		return mkSW(0x6A80)
	}

	if g.deleteFromRegistries(aid, deleteRelated) {
		return mkSW(0x9000)
	}
	return mkSW(0x6A88)
}

func (g *GPState) deleteFromRegistries(aid []byte, deleteRelated bool) bool {
	removed := false
	g.RegistryISD, removed = filterOutAID(g.RegistryISD, aid, removed)
	g.RegistryApps, removed = filterOutAID(g.RegistryApps, aid, removed)
	g.RegistryLoadFiles, removed = filterOutAID(g.RegistryLoadFiles, aid, removed)
	if deleteRelated {
		g.RegistryApps, removed = filterOutAssociatedSD(g.RegistryApps, aid, removed)
	}
	return removed
}

// Sanity check that bytes is referenced (filterOutAID uses bytes.Equal
// indirectly through the existing helpers in install.go).
var _ = bytes.Equal
