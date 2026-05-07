package scp03

// GET DATA behavioral surface for MockCard.
//
// This file holds doGetData (the GET DATA INS=0xCA dispatcher) and
// the static response blobs it returns for the GP-spec tags. The
// dispatcher's job is to route on the (P1, P2) tag and either
// answer with a precomputed blob (Card Recognition Data, YubiKey
// firmware version) or delegate to a stateful builder elsewhere
// in the package (Key Information Template uses the inventory
// model in mock_inventory.go; cert store uses mock_certstore.go).
//
// Split from mock.go because GET DATA is its own dispatch surface
// independent of the secure-channel state machine — the card can
// answer GET DATA in plaintext (no SCP session required for tags
// like 0x0066, 0x5FC1) but must answer over secure messaging when
// authentication is in force. processPlain and processSecure both
// route here; this file owns the tag-based decision once they do.

import (
	"github.com/PeculiarVentures/scp/apdu"
)

func (c *MockCard) doGetData(p1, p2 byte, requestBody []byte) (*apdu.Response, error) {
	tag := uint16(p1)<<8 | uint16(p2)
	switch tag {
	case 0x9F7F:
		// CPLC. The mock claims to be a YubiKey-shaped GP card
		// and YubiKey 5.x advertises CPLC at this tag, so the
		// mock returns the bytes captured from a real YubiKey
		// 5.7.4. The post-fabrication date fields contain
		// random per-card serial bytes (not valid BCD) which is
		// authentic YubiKey behavior — gp/cplc tolerates it.
		return &apdu.Response{Data: append([]byte(nil), syntheticCPLC...), SW1: 0x90, SW2: 0x00}, nil
	case 0x0066:
		return &apdu.Response{Data: append([]byte(nil), syntheticCRD...), SW1: 0x90, SW2: 0x00}, nil
	case 0x00E0:
		// Key Information Template. Built dynamically from the
		// inventory map so post-install state shows up in
		// sd keys list output. Initial inventory is the factory
		// SCP03 key at 0x01/0xFF, which marshals to the same bytes
		// as the legacy syntheticKeyInfo blob — every existing
		// test that asserted "GET DATA tag E0 returns the factory
		// key" still passes unchanged.
		return &apdu.Response{Data: c.buildKeyInfoResponse(), SW1: 0x90, SW2: 0x00}, nil
	case 0xBF21:
		// Cert store read: parse key reference from request body,
		// look up against the persisted certStore map. The library
		// returns 6A88 for "no chain stored" via parseCertificates;
		// we mirror that exactly.
		stored, ok := c.lookupCertChain(requestBody)
		if !ok {
			return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil
		}
		return &apdu.Response{Data: stored, SW1: 0x90, SW2: 0x00}, nil
	case 0x5FC1:
		// YubiKey firmware version object (tag 5FC109). The
		// profile package's Probe sends GET DATA with P1=0x5F
		// P2=0xC1 and reads the response as raw
		// major.minor.patch — three bytes. Real YubiKey 5.x
		// hardware advertises this; standard GP cards return
		// 6A88 because the tag is a Yubico extension. The mock
		// is a YubiKey-shaped simulator, so it should answer
		// the way a YubiKey does: SW=9000 with three bytes.
		// Without this case, profile.Probe defaults to
		// StandardSDProfile against the mock, which then breaks
		// any test that exercises GenerateECKey through the
		// profile gate.
		//
		// Returning 5.7.1 specifically: the mock's behavior is
		// modeled on YubiKey 5.7.x firmware (SCP11 support,
		// AES-128 SCP03 key sets, etc.); 5.7.1 is the published
		// version that matches that surface. Operators reading
		// trace logs see a familiar version.
		return &apdu.Response{Data: []byte{5, 7, 1}, SW1: 0x90, SW2: 0x00}, nil
	default:
		return &apdu.Response{SW1: 0x6A, SW2: 0x88}, nil // reference data not found
	}
}

// syntheticCPLC is the Card Production Life Cycle blob the mock
// returns for GET DATA tag 0x9F7F. Bytes captured from a real
// YubiKey 5C NFC firmware 5.7.4 on 2026-05-07. Includes the
// 9F 7F 2A tag/length header (45 bytes total). The post-
// fabrication date fields contain random per-card serial bytes
// rather than valid BCD dates — authentic YubiKey behavior that
// gp/cplc.Parse accepts (marks affected DateField entries as
// Valid=false while preserving Raw bytes for inspection).
var syntheticCPLC = []byte{
	0x9F, 0x7F, 0x2A,
	0x40, 0x90, // ICFabricator
	0x33, 0x2B, // ICType
	0xF9, 0x17, // OperatingSystemID
	0x8E, 0xD7, // OperatingSystemReleaseDate (random bytes, not BCD)
	0xA0, 0xF2, // OperatingSystemReleaseLevel
	0xEA, 0x2B, // ICFabricationDate (random bytes)
	0xBD, 0x96, 0x9B, 0x1A, // ICSerialNumber
	0xF9, 0x5C, // ICBatchIdentifier
	0xA7, 0xDA, 0x23, 0xEB, // ICModuleFabricator + ICModulePackagingDate
	0xE2, 0xFF, 0x57, 0xCA, // ICCManufacturer + ICEmbeddingDate
	0x47, 0xF7, 0xE7, 0x46, // ICPrePersonalizer + Date
	0x93, 0x3E, 0x48, 0x5C, // ICPrePersonalizationEquipmentID
	0x05, 0x71, 0xCE, 0x68, // ICPersonalizer + Date
	0x51, 0x80, 0x9F, 0x60, // ICPersonalizationEquipmentID
}

// syntheticCRD is the Card Recognition Data blob the mock returns
// for GET DATA tag 0x0066. Hand-assembled per GP Card Spec §H.2:
// outer 66 LL, inner 73 LL OID list, GP RID marker + GP version
// (1.2.840.114283.2.2.3.1 = 2.3.1) + Card Identification Scheme
// (1.2.840.114283.3) + SCP03 (i=0x60) + SCP11 (i=0x0D86). Same
// byte-exact shape captured from a retail YubiKey 5.7.4, also pinned
// in cardrecognition/cardrecognition_test.go's
// TestParse_RetailYubiKey5_BothSCPs.
//
// The SCP11 entry is load-bearing: securitydomain/profile.classifyByCRD
// requires SCP11 in the SCPs list to classify as yubikey-sd. Card_IDS
// OID 1.2.840.114283.3 is the GP-standard identifier and is also
// emitted by non-YubiKey GP cards (SafeNet eToken Fusion observed
// to do so), so the OID alone is not a sufficient YubiKey signal.
//
// Length math: inner children = GP RID (9) + GP version (14) +
// card-id OID (11) + SCP03 (13) + SCP11 (14) = 61 = 0x3D. Wrapped
// tag 0x73 -> 63 bytes. Wrapped tag 0x66 -> 65 bytes total.
var syntheticCRD = []byte{
	0x66, 0x3F,
	0x73, 0x3D,
	0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
	0x60, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x01,
	0x63, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03,
	0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x60,
	0x64, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x11, 0x9B, 0x06,
}

// syntheticKeyInfo is a minimal Key Information Template the mock
// previously returned unconditionally for GET DATA tag 0x00E0. It
// advertises one keyset: the YubiKey factory SCP03 keyset at
// KID=0x01, KVN=0xFF with AES-128 components.
//
//	E0 06              -- Key Information container, 6 bytes
//	  C0 04            -- one Key Information Template, 4 bytes
//	    01             -- KID = 0x01 (SCP03)
//	    FF             -- KVN = 0xFF (YubiKey factory)
//	    88 10          -- component pair (algorithm 0x88 = AES, length-id 0x10)
//
// Decoded by securitydomain.parseKeyInformation as:
//
//	KeyInfo{Reference: {ID: 0x01, Version: 0xFF}, Components: {0x88: 0x10}}
//
// The 0x00E0 case in doGetData now delegates to
// buildKeyInfoResponse() which renders these same bytes when the
// inventory contains only the initial factory entry, and renders
// updated bytes after PUT KEY / GENERATE EC KEY / DELETE KEY
// commands shape the inventory. This blob is retained as a
// readable reference for what the initial-state response looks
// like; nothing in production code reads it directly.
var syntheticKeyInfo = []byte{
	0xE0, 0x06,
	0xC0, 0x04, 0x01, 0xFF, 0x88, 0x10,
}
