package gp

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // see loadimage.go header
	"crypto/sha256"
	"errors"
	"testing"
)

// pickComponent returns the component with the given basename, or
// nil if not present. Reduces test boilerplate when verifying that
// a particular component made it into (or out of) the load image.
func pickComponent(c *CAPFile, name string) *CAPComponent {
	for i := range c.Components {
		if c.Components[i].Name == name {
			return &c.Components[i]
		}
	}
	return nil
}

// parsedDefaultCAP returns a parsed CAP fixture with the full set
// of components defaultCAP() produces. Provides a clean handle
// for LoadImage tests so they don't repeat the build/parse dance.
func parsedDefaultCAP(t *testing.T) *CAPFile {
	t.Helper()
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: []byte("x.y")})
	zipBytes := defaultCAP(hp, nil).bytes(t)
	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}
	return cap
}

// TestLoadImage_DefaultPolicy_ExcludesDebugAndDescriptor confirms
// the documented default behavior: production loads omit Debug.cap
// and Descriptor.cap. The test sums up the kept bytes against the
// raw-component bytes minus the excluded components and checks
// they match.
func TestLoadImage_DefaultPolicy_ExcludesDebugAndDescriptor(t *testing.T) {
	cap := parsedDefaultCAP(t)
	policy := DefaultLoadImagePolicy()

	got, err := cap.LoadImage(policy)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}

	// Compute expected: every component EXCEPT Debug and
	// Descriptor, in the parser's preserved order.
	var want []byte
	for _, comp := range cap.Components {
		if comp.Name == componentNameDebug || comp.Name == componentNameDescriptor {
			continue
		}
		want = append(want, comp.Raw...)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("LoadImage bytes mismatch\n got %d bytes\nwant %d bytes", len(got), len(want))
	}

	// Sanity check: Debug and Descriptor bytes really are absent.
	if dbg := pickComponent(cap, componentNameDebug); dbg != nil {
		if bytes.Contains(got, dbg.Raw) {
			t.Error("default policy should exclude Debug.cap but its bytes appear in load image")
		}
	}
	if desc := pickComponent(cap, componentNameDescriptor); desc != nil {
		if bytes.Contains(got, desc.Raw) {
			t.Error("default policy should exclude Descriptor.cap but its bytes appear in load image")
		}
	}
}

// TestLoadImage_IncludeDebug_KeepsDebugBytes: when ExcludeDebug=false,
// Debug.cap is present in the output. Same shape for Descriptor.
func TestLoadImage_IncludeDebug_KeepsDebugBytes(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: []byte("x.y")})
	// defaultCAP does not include Debug.cap (it's optional);
	// add one explicitly so this test has bytes to look for.
	debugPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	zipBytes := defaultCAP(hp, nil).
		put(componentNameDebug, frameForComponent(ComponentTagDebug, debugPayload)).
		bytes(t)
	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}

	policy := DefaultLoadImagePolicy()
	policy.ExcludeDebug = false

	got, err := cap.LoadImage(policy)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}
	dbg := pickComponent(cap, componentNameDebug)
	if dbg == nil {
		t.Fatal("test fixture should contain Debug.cap")
	}
	if !bytes.Contains(got, dbg.Raw) {
		t.Error("Debug.cap bytes missing from load image when ExcludeDebug=false")
	}
}

func TestLoadImage_IncludeDescriptor_KeepsDescriptorBytes(t *testing.T) {
	cap := parsedDefaultCAP(t)
	policy := DefaultLoadImagePolicy()
	policy.ExcludeDescriptor = false

	got, err := cap.LoadImage(policy)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}
	desc := pickComponent(cap, componentNameDescriptor)
	if desc == nil {
		t.Fatal("test fixture should contain Descriptor.cap")
	}
	if !bytes.Contains(got, desc.Raw) {
		t.Error("Descriptor.cap bytes missing from load image when ExcludeDescriptor=false")
	}
}

// TestLoadImage_ExcludeApplet_OmitsAppletBytes: the IncludeApplet
// flag controls whether Applet.cap is included. Useful for the
// rare case of loading an applet CAP as a library; defaults to
// included so the common case is one-line.
func TestLoadImage_ExcludeApplet_OmitsAppletBytes(t *testing.T) {
	pkgAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
	appletAID := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x01, 0x01}
	hp := buildHeaderPayload(headerOpts{pkgAID: pkgAID, pkgName: []byte("x.y")})
	ap := buildAppletPayload([]appletEntry{{aid: appletAID, offset: 0x0042}})
	zipBytes := defaultCAP(hp, ap).bytes(t)
	cap, err := ParseCAP(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("ParseCAP: %v", err)
	}

	policy := DefaultLoadImagePolicy()
	policy.IncludeApplet = false
	got, err := cap.LoadImage(policy)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}
	applet := pickComponent(cap, componentNameApplet)
	if applet == nil {
		t.Fatal("test fixture should contain Applet.cap")
	}
	if bytes.Contains(got, applet.Raw) {
		t.Error("Applet.cap bytes should be absent when IncludeApplet=false")
	}
}

// TestLoadImage_PreservesLoadOrder confirms the output sequence
// follows the parser's normalized order. Cards stream LOAD blocks
// sequentially and trip up if components arrive out of order;
// validating the output order locks that contract.
func TestLoadImage_PreservesLoadOrder(t *testing.T) {
	cap := parsedDefaultCAP(t)
	got, err := cap.LoadImage(LoadImagePolicy{}) // include everything
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}

	// Walk got byte-by-byte; for each component in cap.Components
	// (the source-of-truth order), verify its Raw bytes appear at
	// the next expected offset.
	offset := 0
	for _, comp := range cap.Components {
		if offset+len(comp.Raw) > len(got) {
			t.Fatalf("load image truncated at component %s (expected offset %d+%d, image len %d)",
				comp.Name, offset, len(comp.Raw), len(got))
		}
		if !bytes.Equal(got[offset:offset+len(comp.Raw)], comp.Raw) {
			t.Errorf("component %s bytes at offset %d do not match Components order",
				comp.Name, offset)
		}
		offset += len(comp.Raw)
	}
	if offset != len(got) {
		t.Errorf("trailing bytes in load image: offset=%d image_len=%d", offset, len(got))
	}
}

// TestLoadImage_EmptyComponents_Errors: malformed input that has
// no components (parser would normally reject this; we synthesize
// directly to test the LoadImage error path in isolation).
func TestLoadImage_EmptyComponents_Errors(t *testing.T) {
	cap := &CAPFile{}
	_, err := cap.LoadImage(DefaultLoadImagePolicy())
	if err == nil {
		t.Fatal("expected error on empty Components")
	}
	if !errors.Is(err, ErrInvalidLoadImage) {
		t.Errorf("err = %v, want wrap of ErrInvalidLoadImage", err)
	}
}

// TestLoadImage_PolicyExcludesEverything_Errors: a policy with all
// the exclusion flags set on a CAP whose only component is one of
// the excluded ones produces a "policy excludes all components"
// error. Synthesize directly so we don't depend on what the
// fixture builder happens to emit.
func TestLoadImage_PolicyExcludesEverything_Errors(t *testing.T) {
	cap := &CAPFile{
		Components: []CAPComponent{
			{Name: componentNameDebug, Raw: []byte{0x01, 0x02, 0x03}},
		},
	}
	policy := LoadImagePolicy{ExcludeDebug: true}
	_, err := cap.LoadImage(policy)
	if err == nil {
		t.Fatal("expected error when all components are excluded")
	}
	if !errors.Is(err, ErrInvalidLoadImage) {
		t.Errorf("err = %v, want wrap of ErrInvalidLoadImage", err)
	}
}

// TestLoadImage_HeaderRequired confirms a load image without
// Header.cap is rejected. Header is required by every card runtime
// to validate the package AID; producing a no-Header image would
// be a host bug.
func TestLoadImage_HeaderRequired(t *testing.T) {
	cap := &CAPFile{
		Components: []CAPComponent{
			{Name: componentNameMethod, Raw: []byte{0x07, 0x00, 0x00}},
		},
	}
	_, err := cap.LoadImage(LoadImagePolicy{})
	if err == nil {
		t.Fatal("expected error when Header.cap is absent from load image")
	}
	if !errors.Is(err, ErrInvalidLoadImage) {
		t.Errorf("err = %v, want wrap of ErrInvalidLoadImage", err)
	}
}

// TestLoadImage_FreshAllocation confirms the returned bytes are
// not aliasing the underlying CAP component storage. Mutation of
// the returned slice should not corrupt the CAP.
func TestLoadImage_FreshAllocation(t *testing.T) {
	cap := parsedDefaultCAP(t)
	got, err := cap.LoadImage(DefaultLoadImagePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("load image is empty")
	}

	original := append([]byte(nil), cap.Components[0].Raw...)

	// Mutate the returned slice.
	for i := range got {
		got[i] ^= 0xFF
	}

	// Original CAP bytes should be unchanged.
	if !bytes.Equal(cap.Components[0].Raw, original) {
		t.Error("mutating LoadImage output corrupted CAP component storage (aliasing bug)")
	}
}

// TestLoadImageHashes_BothDigests verifies the helper computes
// SHA-256 and SHA-1 over the same bytes LoadImage returns. This
// is the integrity-envelope shape that destructive CLI flows
// will print before committing the install.
func TestLoadImageHashes_BothDigests(t *testing.T) {
	cap := parsedDefaultCAP(t)
	policy := DefaultLoadImagePolicy()

	image, err := cap.LoadImage(policy)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}
	want256 := sha256.Sum256(image)
	want1 := sha1.Sum(image) //nolint:gosec // see file header

	got256, got1, err := cap.LoadImageHashes(policy)
	if err != nil {
		t.Fatalf("LoadImageHashes: %v", err)
	}
	if !bytes.Equal(got256, want256[:]) {
		t.Errorf("SHA-256 mismatch\n got %x\nwant %x", got256, want256[:])
	}
	if !bytes.Equal(got1, want1[:]) {
		t.Errorf("SHA-1 mismatch\n got %x\nwant %x", got1, want1[:])
	}
}

// TestLoadImageHashes_PropagatesErrors: when LoadImage fails
// (e.g. policy excludes everything), LoadImageHashes returns the
// same error rather than swallowing it.
func TestLoadImageHashes_PropagatesErrors(t *testing.T) {
	cap := &CAPFile{} // no components
	_, _, err := cap.LoadImageHashes(DefaultLoadImagePolicy())
	if err == nil {
		t.Fatal("expected error to propagate from LoadImage")
	}
	if !errors.Is(err, ErrInvalidLoadImage) {
		t.Errorf("err = %v, want wrap of ErrInvalidLoadImage", err)
	}
}
