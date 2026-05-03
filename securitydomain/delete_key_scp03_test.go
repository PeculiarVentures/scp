package securitydomain

import (
	"testing"
)

// TestIsSCP03KeyID checks the helper that drives the special-case
// behavior in Session.DeleteKey.
func TestIsSCP03KeyID(t *testing.T) {
	cases := []struct {
		kid  byte
		want bool
	}{
		{0x01, true}, // SCP03 ENC
		{0x02, true}, // SCP03 MAC
		{0x03, true}, // SCP03 DEK
		{0x00, false},
		{0x10, false}, // OCE
		{0x11, false}, // SCP11a
		{0x13, false}, // SCP11b
		{0x15, false}, // SCP11c
	}
	for _, c := range cases {
		if got := isSCP03KeyID(c.kid); got != c.want {
			t.Errorf("isSCP03KeyID(0x%02X) = %v, want %v", c.kid, got, c.want)
		}
	}
}
