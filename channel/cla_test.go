package channel

import "testing"

// TestSecureMessagingCLA covers ISO 7816-4 §5.4.1 / GP Card Spec
// §11.1.4 secure-messaging bit positions across the full CLA range.
//
// First-interindustry (0x00-0x3F) and proprietary (0x80-0xFE) take
// the SM bit at 0x04. Further-interindustry (0x40-0x7F) takes the
// SM bit at 0x20. The reserved 0xFF is returned unchanged.
//
// This is the one test most likely to catch a regression that turns
// "supports basic-channel YubiKey" into "breaks on logical channel
// 4+ for any other GP card", so it covers each class explicitly.
func TestSecureMessagingCLA(t *testing.T) {
	tests := []struct {
		name string
		in   byte
		want byte
	}{
		// First interindustry, basic channel
		{"first interindustry channel 0", 0x00, 0x04},
		{"first interindustry channel 1", 0x01, 0x05},
		{"first interindustry channel 2", 0x02, 0x06},
		{"first interindustry channel 3", 0x03, 0x07},
		// First interindustry with chaining bit preserved
		{"first interindustry channel 0 chained", 0x10, 0x14},
		{"first interindustry channel 3 chained", 0x13, 0x17},
		// First interindustry already has SM set — idempotent
		{"first interindustry channel 0 SM-set idempotent", 0x04, 0x04},
		{"first interindustry channel 0 SM+chain idempotent", 0x14, 0x14},

		// Further interindustry: SM bit is 0x20, NOT 0x04
		{"further interindustry channel 4", 0x40, 0x60},
		{"further interindustry channel 5", 0x41, 0x61},
		{"further interindustry channel 19", 0x4F, 0x6F},
		// Further with chaining
		{"further interindustry channel 4 chained", 0x50, 0x70},
		{"further interindustry channel 19 chained", 0x5F, 0x7F},
		// Further with SM already set — idempotent
		{"further interindustry channel 4 SM-set idempotent", 0x60, 0x60},
		{"further interindustry channel 19 SM+chain idempotent", 0x7F, 0x7F},

		// Proprietary (typical GP)
		{"proprietary channel 0", 0x80, 0x84},
		{"proprietary channel 0 chained", 0x90, 0x94},
		{"proprietary channel 3 chained", 0x93, 0x97},
		// Proprietary at upper range — still first-interindustry layout
		{"proprietary 0xC0", 0xC0, 0xC4},
		{"proprietary 0xCF", 0xCF, 0xCF},

		// Reserved: returned unchanged.
		{"reserved 0xFF", 0xFF, 0xFF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SecureMessagingCLA(tt.in)
			if got != tt.want {
				t.Errorf("SecureMessagingCLA(%#02x) = %#02x, want %#02x", tt.in, got, tt.want)
			}
		})
	}
}

// TestClearSecureMessagingCLA confirms the inverse of
// SecureMessagingCLA. For any non-reserved CLA whose SM-set form is
// also non-reserved, applying SM-set then SM-clear must return the
// original byte (subject to the SM bit already being clear in the
// original).
//
// Skipped: 0xFB (proprietary, bit pattern 1111_1011) ORs with 0x04
// to land on 0xFF (reserved). The caller passing 0xFB to the helper
// is legitimate, but the result collides with reserved CLA encoding,
// and ClearSecureMessagingCLA(0xFF) returns 0xFF unchanged. This is
// an unavoidable consequence of bit positions colliding with the
// reserved value; documented as an edge case in the helper godoc.
// Real-world GP CLAs (0x00, 0x10, 0x80, 0x84, 0x40, 0x60, etc.) do
// not hit this collision.
func TestClearSecureMessagingCLA(t *testing.T) {
	for cla := 0; cla < 256; cla++ {
		c := byte(cla)
		// Skip reserved and the 0xFB collision case.
		if c == 0xFF || c == 0xFB {
			continue
		}
		round := ClearSecureMessagingCLA(SecureMessagingCLA(c))
		want := ClearSecureMessagingCLA(c)
		if round != want {
			t.Errorf("CLA %#02x: SM-set then SM-clear = %#02x, want %#02x",
				c, round, want)
		}
	}
}

// TestIsSecureMessaging covers detection across encodings. A naive
// check of bit 0x04 alone will misclassify further-interindustry
// CLAs (where 0x04 is part of the channel encoding rather than
// secure messaging).
func TestIsSecureMessaging(t *testing.T) {
	tests := []struct {
		cla  byte
		want bool
	}{
		// First interindustry without/with SM
		{0x00, false},
		{0x04, true},
		{0x80, false},
		{0x84, true},
		{0x10, false}, // chaining-only
		{0x14, true},  // chaining + SM

		// Further interindustry: 0x04 here is part of the channel, NOT SM
		{0x44, false}, // channel 8, no SM — this is the case the naive
		// check gets wrong: 0x44 & 0x04 != 0, but 0x44 is logical
		// channel 8 with no secure messaging.
		{0x60, true},  // channel 4, SM set
		{0x64, true},  // channel 8, SM set (4 + 4)
		{0x6F, true},  // channel 19, SM set
		{0x40, false}, // channel 4, no SM
		{0x4F, false}, // channel 19, no SM

		// Proprietary
		{0xCF, true},  // 1100_1111: bit 2 set, SM present
		{0xCB, false}, // 1100_1011: bit 2 clear, no SM
		{0xC4, true},

		// Reserved
		{0xFF, false},
	}
	for _, tt := range tests {
		got := IsSecureMessaging(tt.cla)
		if got != tt.want {
			t.Errorf("IsSecureMessaging(%#02x) = %v, want %v", tt.cla, got, tt.want)
		}
	}
}

// TestLogicalChannel covers channel decoding. Channels 0-3 are in
// the low two bits of first-interindustry / proprietary CLA;
// channels 4-19 are in the low four bits of further-interindustry,
// offset by 4.
func TestLogicalChannel(t *testing.T) {
	tests := []struct {
		cla  byte
		want int
	}{
		// First interindustry
		{0x00, 0},
		{0x01, 1},
		{0x02, 2},
		{0x03, 3},
		// SM and chaining bits don't affect channel
		{0x14, 0},
		{0x07, 3},
		// Proprietary
		{0x80, 0},
		{0x83, 3},
		{0x87, 3},

		// Further interindustry
		{0x40, 4},
		{0x41, 5},
		{0x44, 8},
		{0x4F, 19},
		// SM and chaining bits don't affect channel
		{0x60, 4}, // SM set, channel 4
		{0x70, 4}, // SM + chaining, channel 4
		{0x7F, 19},

		// Reserved
		{0xFF, -1},
	}
	for _, tt := range tests {
		got := LogicalChannel(tt.cla)
		if got != tt.want {
			t.Errorf("LogicalChannel(%#02x) = %d, want %d", tt.cla, got, tt.want)
		}
	}
}

// TestIsCommandChaining covers the chaining bit (0x10) across
// first-interindustry and further-interindustry encodings, where
// chaining is in the same bit position.
func TestIsCommandChaining(t *testing.T) {
	tests := []struct {
		cla  byte
		want bool
	}{
		{0x00, false},
		{0x10, true},
		{0x14, true}, // chaining + SM
		{0x80, false},
		{0x90, true}, // proprietary chained
		{0x40, false},
		{0x50, true}, // further-interindustry chained
		{0x70, true}, // further chained + SM
		{0xFF, false},
	}
	for _, tt := range tests {
		got := IsCommandChaining(tt.cla)
		if got != tt.want {
			t.Errorf("IsCommandChaining(%#02x) = %v, want %v", tt.cla, got, tt.want)
		}
	}
}

// TestClassifyCLA confirms boundary detection between the four
// encoding categories.
func TestClassifyCLA(t *testing.T) {
	tests := []struct {
		cla  byte
		want ClassEncoding
	}{
		{0x00, ClassFirstInterindustry},
		{0x3F, ClassFirstInterindustry},
		{0x40, ClassFurtherInterindustry},
		{0x7F, ClassFurtherInterindustry},
		{0x80, ClassProprietary},
		{0xFE, ClassProprietary},
		{0xFF, ClassReserved},
	}
	for _, tt := range tests {
		got := ClassifyCLA(tt.cla)
		if got != tt.want {
			t.Errorf("ClassifyCLA(%#02x) = %d, want %d", tt.cla, got, tt.want)
		}
	}
}

// TestSecureMessagingCLA_NaiveOrEqualsBreaks demonstrates the bug
// the helper fixes. The historical "cmd.CLA | 0x04" treatment turns
// CLA 0x40 (logical channel 4, no SM) into 0x44 (logical channel
// 8, no SM) — silently re-routing the command to a different
// channel rather than enabling secure messaging. SecureMessagingCLA
// produces 0x60 (logical channel 4, SM set), which is the correct
// transformation.
func TestSecureMessagingCLA_NaiveOrEqualsBreaks(t *testing.T) {
	const ch4NoSM byte = 0x40

	// What the naive code would do.
	naive := ch4NoSM | 0x04
	if got := LogicalChannel(naive); got != 8 {
		t.Errorf("baseline check: 0x44 should decode as logical channel 8, got %d", got)
	}
	if IsSecureMessaging(naive) {
		t.Error("baseline check: 0x44 has the channel-8-encoding bit set, not SM — naive code creates an SM false positive")
	}

	// What the helper does.
	correct := SecureMessagingCLA(ch4NoSM)
	if got := LogicalChannel(correct); got != 4 {
		t.Errorf("SecureMessagingCLA(0x40) decoded channel = %d, want 4", got)
	}
	if !IsSecureMessaging(correct) {
		t.Error("SecureMessagingCLA(0x40) result must report secure messaging")
	}
	if correct != 0x60 {
		t.Errorf("SecureMessagingCLA(0x40) = %#02x, want 0x60", correct)
	}
}
