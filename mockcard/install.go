package mockcard

import (
	"bytes"
)

// Helpers shared by GPState's INSTALL/LOAD/DELETE handlers in
// gpstate.go. The actual handlers moved to *GPState methods so
// they can be shared by both Card (SCP11) and SCP03Card (SCP03);
// only the pure-data helpers remain here.

// installLoadContext records the in-flight INSTALL [for load]
// state. Cleared when the load completes (successful final LOAD
// block) or when a new INSTALL [for load] starts.
type installLoadContext struct {
	loadFileAID []byte
	sdAID       []byte
	loadParams  []byte
	expectedSeq byte
	bytesLoaded []byte
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

// validAIDLen reports whether the slice is a syntactically valid
// ISO/IEC 7816-5 AID (5..16 bytes). Callers that fail validation
// surface SW=6A80 to the host; the predicate shape avoids the
// alloc + interface dance an error sentinel would impose for what
// is purely a length check.
func validAIDLen(aid []byte) bool {
	return len(aid) >= 5 && len(aid) <= 16
}

// versionFromLoadParams extracts a 2-byte version hint from the
// INSTALL [for load] parameters block when present (tag 0xC8 in
// the LV-prefixed parameters TLV stream). Returns nil when no
// version is encoded; the GET STATUS response then omits the
// 0xCE Version TLV.
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
