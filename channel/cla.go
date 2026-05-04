package channel

// CLA decoding per ISO 7816-4 §5.4.1 and GP Card Spec §11.1.4.
//
// The CLA byte conveys four orthogonal pieces of information: which
// class encoding is in use (first interindustry, further interindustry,
// proprietary), whether secure messaging is present, whether command
// chaining is in effect, and the logical channel number. The bit
// positions of secure messaging and logical channel depend on the
// class encoding, which is why a naive "cmd.CLA | 0x04" only works
// for basic-channel proprietary CLA values (the YubiKey case) and
// breaks on further-interindustry CLAs that encode logical channels
// 4-19.
//
// The helpers in this file centralize the encoding so wrap/unwrap on
// both ends of the channel agree on which bit to set/clear and how
// to decode logical channels. They are the verified building block
// for broader GlobalPlatform interoperability beyond the basic
// channel; the YubiKey profile happens to land on basic-channel
// proprietary CLA, where the older naive code worked, but the same
// secure messaging stack must drive logical channels 1-3 (basic
// class) and 4-19 (further-interindustry) for general GP cards.

// SMBitFirstInterindustry is the secure-messaging bit position for
// CLA values in the first interindustry range (0x00-0x3F) and for
// proprietary CLAs that GlobalPlatform encodes with the same layout
// (0x80-0xBF). Set this bit to indicate ISO secure messaging without
// command-header authentication, which is the form SCP03 and SCP11
// use.
//
// Per ISO 7816-4 §5.4.1, the two-bit field at positions 2-3 codes:
//
//	00  no secure messaging
//	01  proprietary secure messaging
//	10  ISO secure messaging, command header not authenticated  (= 0x04)
//	11  ISO secure messaging, command header authenticated      (= 0x0C)
//
// SCP03 and SCP11 use code 10 (= 0x04). Code 11 is not used by
// either protocol.
const SMBitFirstInterindustry byte = 0x04

// SMBitFurtherInterindustry is the secure-messaging bit position for
// CLA values in the further-interindustry range (0x40-0x7F). In this
// encoding, secure messaging is a single bit at position 5 (= 0x20)
// rather than the two-bit field used by first-interindustry. Logical
// channels 4-19 are only addressable via further-interindustry CLA,
// so any logical-channel-aware GP integration must understand this
// alternate position.
const SMBitFurtherInterindustry byte = 0x20

// ChainingBitFirstInterindustry is the command-chaining bit for
// first-interindustry and proprietary-basic CLAs (bit 4 = 0x10).
// Its value is the same in further-interindustry encoding, so this
// constant is the chaining bit position for both.
const ChainingBitFirstInterindustry byte = 0x10

// ChainingBitFurtherInterindustry is an alias for the chaining bit
// in further-interindustry encoding. ISO 7816-4 puts chaining at
// the same bit (4 = 0x10) for both first and further interindustry
// CLA, but the alias is kept for readability at call sites that
// branch on encoding.
const ChainingBitFurtherInterindustry byte = 0x10

// ClassEncoding identifies which CLA layout governs a given byte.
// The layout determines bit positions for secure messaging and
// logical channel encoding.
type ClassEncoding int

const (
	// ClassFirstInterindustry covers CLA 0x00-0x3F: ISO standard
	// interindustry commands. Logical channels 0-3 are encoded in
	// bits 0-1; secure messaging is bits 2-3; chaining is bit 4.
	ClassFirstInterindustry ClassEncoding = iota

	// ClassFurtherInterindustry covers CLA 0x40-0x7F: ISO standard
	// further-interindustry commands. Logical channels 4-19 are
	// encoded as bits 0-3 + 4; secure messaging is bit 5; chaining
	// is bit 4.
	ClassFurtherInterindustry

	// ClassProprietary covers CLA 0x80-0xFE: vendor-defined classes.
	// Most GlobalPlatform cards use the first-interindustry layout
	// for their proprietary CLAs (notably 0x80-0x8F basic channel,
	// 0x84 with secure messaging set), so the helpers in this file
	// treat ClassProprietary identically to ClassFirstInterindustry.
	// Cards that depart from this convention will need a custom
	// transport-side wrapper.
	ClassProprietary

	// ClassReserved covers CLA 0xFF, which ISO 7816-4 reserves as
	// invalid for any CLA byte (it is the PPS request opcode at the
	// transport layer below APDU). A CLA in this range coming
	// through the APDU layer is a programming error.
	ClassReserved
)

// ClassifyCLA returns the encoding category for a CLA byte.
func ClassifyCLA(cla byte) ClassEncoding {
	switch {
	case cla == 0xFF:
		return ClassReserved
	case cla < 0x40:
		// 0x00-0x3F: first interindustry.
		return ClassFirstInterindustry
	case cla < 0x80:
		// 0x40-0x7F: further interindustry.
		return ClassFurtherInterindustry
	default:
		// 0x80-0xFE: proprietary. GP convention is first-interindustry
		// layout; we report ClassProprietary so callers that want to
		// branch can, but the helpers below treat it the same.
		return ClassProprietary
	}
}

// SecureMessagingCLA returns cla with the appropriate secure-messaging
// bit set per ISO 7816-4 §5.4.1 / GP Card Spec §11.1.4.
//
// The bit position depends on the class encoding:
//
//   - First interindustry (0x00-0x3F) and proprietary (0x80-0xFE):
//     bit 2 (0x04) marks ISO secure messaging without command-header
//     authentication, which is the form SCP03 and SCP11 use.
//
//   - Further interindustry (0x40-0x7F): bit 5 (0x20) is the single
//     secure-messaging indication; the first-interindustry two-bit
//     field is not present in this encoding.
//
//   - Reserved (0xFF): no SM bit is set; the CLA is returned
//     unchanged. ISO 7816-4 reserves 0xFF as invalid at the APDU
//     layer, and a caller passing it is almost certainly mistaken.
//     Returning unchanged surfaces the bug at the card rather than
//     hiding it behind a silently-modified byte.
//
// This is the value transmitted on the wire AND the value covered by
// the C-MAC. Per GP Amendment D §6.2.5, SCP03 / SCP11 secure messaging
// MAC over CLA with the SM bit set, and the wrapped command transmits
// CLA with the same bit set. The two are intentionally identical here.
//
// Calling SecureMessagingCLA on a CLA that already has the SM bit
// set is idempotent.
//
// Edge case: SecureMessagingCLA(0xFB) returns 0xFF, which collides
// with reserved. Callers building proprietary CLAs in the 0xFB range
// (proprietary, channel 3, with bit 3 set) cannot enable SCP03/SCP11
// secure messaging without colliding with reserved encoding. Real-
// world GP cards do not use 0xFB; the collision is a property of bit
// positions, not a defect in this helper.
func SecureMessagingCLA(cla byte) byte {
	switch ClassifyCLA(cla) {
	case ClassFirstInterindustry, ClassProprietary:
		return cla | SMBitFirstInterindustry
	case ClassFurtherInterindustry:
		return cla | SMBitFurtherInterindustry
	default: // ClassReserved
		return cla
	}
}

// ClearSecureMessagingCLA returns cla with the secure-messaging bit
// cleared per its class encoding. Card-side mock implementations and
// transport-layer test fixtures use this to recover the plain CLA
// from a wrapped APDU before dispatching to the underlying handler.
//
// Mirror of SecureMessagingCLA: applying SecureMessagingCLA followed
// by ClearSecureMessagingCLA is idempotent on any non-reserved CLA.
func ClearSecureMessagingCLA(cla byte) byte {
	switch ClassifyCLA(cla) {
	case ClassFirstInterindustry, ClassProprietary:
		return cla &^ SMBitFirstInterindustry
	case ClassFurtherInterindustry:
		return cla &^ SMBitFurtherInterindustry
	default: // ClassReserved
		return cla
	}
}

// IsSecureMessaging reports whether cla has the secure-messaging
// bit set, accounting for class encoding. Returns false for
// reserved CLA values; the SM concept is undefined there.
func IsSecureMessaging(cla byte) bool {
	switch ClassifyCLA(cla) {
	case ClassFirstInterindustry, ClassProprietary:
		return cla&SMBitFirstInterindustry != 0
	case ClassFurtherInterindustry:
		return cla&SMBitFurtherInterindustry != 0
	default: // ClassReserved
		return false
	}
}

// LogicalChannel returns the logical channel encoded in cla per
// ISO 7816-4 §5.4.1.
//
//   - First interindustry (0x00-0x3F) and proprietary (0x80-0xFE):
//     channel = bits 0-1, range 0-3.
//
//   - Further interindustry (0x40-0x7F): channel = bits 0-3 + 4,
//     range 4-19.
//
//   - Reserved (0xFF): returns -1.
func LogicalChannel(cla byte) int {
	switch ClassifyCLA(cla) {
	case ClassFirstInterindustry, ClassProprietary:
		return int(cla & 0x03)
	case ClassFurtherInterindustry:
		return 4 + int(cla&0x0F)
	default:
		return -1
	}
}

// IsCommandChaining reports whether the chaining bit is set in cla.
// Chaining is bit 4 (0x10) in both first-interindustry and
// further-interindustry encodings, but proprietary classes are not
// guaranteed to follow this convention; callers integrating with
// non-GP-conventional cards should not rely on this helper.
//
// Returns false for reserved CLA.
func IsCommandChaining(cla byte) bool {
	switch ClassifyCLA(cla) {
	case ClassFirstInterindustry, ClassFurtherInterindustry, ClassProprietary:
		return cla&ChainingBitFirstInterindustry != 0
	default:
		return false
	}
}
