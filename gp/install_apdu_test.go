package gp

import (
	"strings"
	"testing"
)

// TestBuildInstallForLoadPayload_ParamsOverflow covers the
// silent-truncation bug surfaced in branch review of gp/main-body
// (review item #5). A 256-byte LoadParams blob would have wrapped
// the single-byte LV length to 0 and produced a card-side
// 6A80/6985 with no signal that the host was at fault. The
// builder now returns a typed error with the field name.
func TestBuildInstallForLoadPayload_ParamsOverflow(t *testing.T) {
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	sdAID := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	bigParams := make([]byte, 256) // one over the cap

	_, err := BuildInstallForLoadPayload(loadAID, sdAID, nil, bigParams, nil)
	if err == nil {
		t.Fatal("expected error for 256-byte LoadParams, got nil (silent truncation regression)")
	}
	if !strings.Contains(err.Error(), "load parameters") {
		t.Errorf("error should name the field: %v", err)
	}
	if !strings.Contains(err.Error(), "256") {
		t.Errorf("error should report the actual length: %v", err)
	}
}

// TestBuildInstallForLoadPayload_HashOverflow: a SHA-512 plus
// TLV framing or a vendor-specific hash structure can plausibly
// exceed 255 bytes. The error should name the hash field.
func TestBuildInstallForLoadPayload_HashOverflow(t *testing.T) {
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	sdAID := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	hugeHash := make([]byte, 300)

	_, err := BuildInstallForLoadPayload(loadAID, sdAID, hugeHash, nil, nil)
	if err == nil {
		t.Fatal("expected error for 300-byte hash")
	}
	if !strings.Contains(err.Error(), "load file data block hash") {
		t.Errorf("error should name the hash field: %v", err)
	}
}

// TestBuildInstallForLoadPayload_BoundaryAccept: 255 bytes is
// the maximum legal field length. Must succeed.
func TestBuildInstallForLoadPayload_BoundaryAccept(t *testing.T) {
	loadAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	sdAID := []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	maxParams := make([]byte, 255)

	out, err := BuildInstallForLoadPayload(loadAID, sdAID, nil, maxParams, nil)
	if err != nil {
		t.Fatalf("255-byte field should be accepted: %v", err)
	}
	// LoadFile AID len + 6 + SD AID len + 8 + hash 0 + params len + 255 + token 0
	want := 1 + 6 + 1 + 8 + 1 + 1 + 255 + 1
	if len(out) != want {
		t.Errorf("payload length = %d, want %d", len(out), want)
	}
}

// TestBuildInstallForInstallPayload_TokenOverflow: install token
// is operator-supplied and could be a long signature blob.
// Overflow here should fail with the token field name.
func TestBuildInstallForInstallPayload_TokenOverflow(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	bigToken := make([]byte, 1024)

	_, err := BuildInstallForInstallPayload(aid, aid, aid, []byte{0x00}, nil, bigToken)
	if err == nil {
		t.Fatal("expected error for 1024-byte install token")
	}
	if !strings.Contains(err.Error(), "install token") {
		t.Errorf("error should name the token field: %v", err)
	}
}

// TestBuildInstallForInstallPayload_PrivilegesOverflow: privs
// over 255 bytes is nonsense (real privs are 1 or 3 bytes) but
// the cap should still apply uniformly.
func TestBuildInstallForInstallPayload_PrivilegesOverflow(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	bigPrivs := make([]byte, 256)

	_, err := BuildInstallForInstallPayload(aid, aid, aid, bigPrivs, nil, nil)
	if err == nil {
		t.Fatal("expected error for 256-byte privileges")
	}
	if !strings.Contains(err.Error(), "privileges") {
		t.Errorf("error should name the privileges field: %v", err)
	}
}
