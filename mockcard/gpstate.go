package mockcard

import (
	"bytes"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/tlv"
)

// GPState is the GlobalPlatform card-content management state
// shared by mockcard.Card (SCP11) and mockcard.SCP03Card (SCP03).
// It owns the three registry slices, the in-flight INSTALL [for
// load] context, and the optional card-identity values (IIN,
// CIN), and provides the GP §11.x command handlers as methods.
//
// Tests usually access the registry slices directly through the
// embedding mock type's promoted fields (e.g. card.RegistryISD).
// GPState does not export per-handler entry points because the
// expected entry path is always through the embedding mock's APDU
// dispatch.
//
// GPState models card state and only card state. Test affordances
// like fault injection live on the embedding type (SCP03Card) via
// AddFault, not as fields on GPState — keeping the production-
// shaped model free of test-only switches.
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

	// IIN is the Issuer Identification Number per GP §B.3 (5
	// bytes typical, ISO 7812 BCD). Returned by GET DATA tag
	// 0x0042 when non-empty; an empty slice makes the mock
	// return SW=6A88 ("referenced data not found"), matching
	// real cards that don't expose IIN.
	IIN []byte

	// CIN is the Card Image Number per GP §B.4 (variable length,
	// vendor-defined). Returned by GET DATA tag 0x0045 when
	// non-empty; empty produces SW=6A88. CIN is the value the
	// scpctl --expected-card-id flag pins so an operator can
	// verify they're talking to the correct card before issuing
	// destructive commands.
	CIN []byte
}

// NewGPState returns a fresh GP state with empty registries and
// no load in progress.
func NewGPState() *GPState { return &GPState{} }

// HandleGPCommand dispatches a GP card-content management APDU. It
// returns (nil, false) if the INS byte is not a recognized GP
// command — the caller should fall through to its own non-GP
// handlers in that case. Otherwise it returns the response and
// ok=true.
//
// Recognized INS bytes: 0xF2 GET STATUS, 0xF0 SET STATUS, 0xE6
// INSTALL, 0xE8 LOAD, 0xE4 DELETE. Plus, when the corresponding
// field is non-empty, GET DATA (INS=0xCA) for tags 0x0042 (IIN)
// and 0x0045 (CIN). If neither IIN nor CIN is configured, GET
// DATA falls through to the default handler so the mock's CRD
// (tag 0x66) and Key Information (tag 0xE0) responses still
// work.
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
	case 0xCA:
		// Only intercept the identity tags. Other GET DATA
		// queries (CRD, Key Info) are answered by the embedding
		// mock's default handler.
		tag := uint16(cmd.P1)<<8 | uint16(cmd.P2)
		switch tag {
		case 0x0042:
			if len(g.IIN) == 0 {
				return mkSW(0x6A88), true
			}
			return &apdu.Response{
				Data: append([]byte(nil), g.IIN...),
				SW1:  0x90, SW2: 0x00,
			}, true
		case 0x0045:
			if len(g.CIN) == 0 {
				return mkSW(0x6A88), true
			}
			return &apdu.Response{
				Data: append([]byte(nil), g.CIN...),
				SW1:  0x90, SW2: 0x00,
			}, true
		}
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
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if !validAIDLen(loadAID) {
		return mkSW(0x6A80)
	}
	sdAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if len(sdAID) != 0 {
		if !validAIDLen(sdAID) {
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
	d := cmd.Data
	loadAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if !validAIDLen(loadAID) {
		return mkSW(0x6A80)
	}
	moduleAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if !validAIDLen(moduleAID) {
		return mkSW(0x6A80)
	}
	appletAID, d, ok := readLV(d)
	if !ok {
		return mkSW(0x6A80)
	}
	if !validAIDLen(appletAID) {
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
	if !validAIDLen(aid) {
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
