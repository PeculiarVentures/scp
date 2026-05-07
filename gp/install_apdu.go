package gp

import "fmt"

// INSTALL command data-field builders per GP Card Spec v2.3.1
// §11.5.2.3. The wire format is a sequence of length-value
// fields: each field is a single u1 length byte followed by that
// many bytes of value. Empty fields encode as a single 0x00
// byte (zero-length value).
//
// The single-byte length field caps each field at 255 bytes.
// AIDs are bounded by ISO 7816-5 to 16 bytes so they cannot
// trigger the cap, but install params, load params, hashes, and
// tokens are unbounded by spec and operator-supplied: a SHA-512
// hash with TLV framing or vendor-specific install params can
// plausibly exceed 255. The builders return an error rather than
// silently truncate; the caller surfaces a stage-tagged failure
// before any APDU goes on the wire.
//
// These builders live in package gp because they produce GP wire
// format and have no dependencies beyond the spec. Both the host
// session code (securitydomain.Session.Install) and test fixtures
// driving APDUs against mocks share the same builder, so a
// regression in the wire layout fails everywhere at once rather
// than diverging silently.

// BuildInstallForLoadPayload encodes the INSTALL [for load] data
// field per §11.5.2.3.1: load file AID, SD AID, load file data
// block hash, load parameters, load token. Empty fields are
// emitted as zero-length values. Returns an error if any field
// exceeds 255 bytes (the single-byte LV length cap).
func BuildInstallForLoadPayload(loadAID, sdAID, hash, params, token []byte) ([]byte, error) {
	fields := []struct {
		name string
		v    []byte
	}{
		{"load file AID", loadAID},
		{"SD AID", sdAID},
		{"load file data block hash", hash},
		{"load parameters", params},
		{"load token", token},
	}
	return buildLVConcat(fields)
}

// BuildInstallForInstallPayload encodes the INSTALL [for install]
// data field per §11.5.2.3.2: load file AID, module AID, applet
// AID, privileges, install parameters, install token. Returns an
// error if any field exceeds 255 bytes.
func BuildInstallForInstallPayload(loadAID, moduleAID, appletAID, privs, params, token []byte) ([]byte, error) {
	fields := []struct {
		name string
		v    []byte
	}{
		{"load file AID", loadAID},
		{"module AID", moduleAID},
		{"applet AID", appletAID},
		{"privileges", privs},
		{"install parameters", params},
		{"install token", token},
	}
	return buildLVConcat(fields)
}

// buildLVConcat assembles a sequence of named LV fields into the
// INSTALL data shape, returning a clear error pointing at which
// field overflowed when one exceeds 255 bytes.
func buildLVConcat(fields []struct {
	name string
	v    []byte
}) ([]byte, error) {
	var b []byte
	for _, f := range fields {
		if len(f.v) > 255 {
			return nil, fmt.Errorf("gp: INSTALL %s exceeds single-byte LV cap (%d bytes, max 255)",
				f.name, len(f.v))
		}
		b = append(b, byte(len(f.v)))
		b = append(b, f.v...)
	}
	return b, nil
}
