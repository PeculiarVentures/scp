package gp

// INSTALL command data-field builders per GP Card Spec v2.3.1
// §11.5.2.3. The wire format is a sequence of length-value
// fields: each field is a single u1 length byte followed by that
// many bytes of value. Empty fields encode as a single 0x00
// byte (zero-length value).
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
// emitted as zero-length values.
func BuildInstallForLoadPayload(loadAID, sdAID, hash, params, token []byte) []byte {
	var b []byte
	b = appendLVField(b, loadAID)
	b = appendLVField(b, sdAID)
	b = appendLVField(b, hash)
	b = appendLVField(b, params)
	b = appendLVField(b, token)
	return b
}

// BuildInstallForInstallPayload encodes the INSTALL [for install]
// data field per §11.5.2.3.2: load file AID, module AID, applet
// AID, privileges, install parameters, install token.
func BuildInstallForInstallPayload(loadAID, moduleAID, appletAID, privs, params, token []byte) []byte {
	var b []byte
	b = appendLVField(b, loadAID)
	b = appendLVField(b, moduleAID)
	b = appendLVField(b, appletAID)
	b = appendLVField(b, privs)
	b = appendLVField(b, params)
	b = appendLVField(b, token)
	return b
}

// appendLVField appends a single u1-length-prefixed value to b.
// Unexported because the GP INSTALL wire format is the only
// caller; sharing this primitive across the package's other TLV
// helpers (which use multi-byte BER lengths) would conflate
// unrelated formats.
func appendLVField(b, v []byte) []byte {
	b = append(b, byte(len(v)))
	b = append(b, v...)
	return b
}
