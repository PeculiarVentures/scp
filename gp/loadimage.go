package gp

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is a publication-required hash for legacy CA/B Forum integrity envelopes; not used for authentication
	"crypto/sha256"
	"fmt"
)

// LoadImagePolicy controls which CAP components are included in
// the load file data block emitted by CAPFile.LoadImage. The
// default policy excludes Debug.cap and Descriptor.cap because
// neither is needed for applet execution, both waste EEPROM, and
// some card runtimes reject the load when they're included
// (Oracle JCRE 3.0.x behavior is documented but enforcement
// varies by vendor; safer to omit by default).
type LoadImagePolicy struct {
	// ExcludeDebug, when true, omits Debug.cap from the load
	// image. Default: true (Debug carries source line numbers
	// and method names, useful for diagnostics on a developer
	// build but unused at runtime).
	ExcludeDebug bool

	// ExcludeDescriptor, when true, omits Descriptor.cap from
	// the load image. Default: true (Descriptor carries class
	// reflection metadata; required only for cards that allow
	// runtime introspection, which excludes most production
	// JCOPs and SafeNets).
	ExcludeDescriptor bool

	// IncludeApplet defaults to true. Library CAPs (no Applet
	// component) are unaffected by this flag; for an applet CAP,
	// setting this to false produces a library-only image, which
	// most card runtimes will accept as INSTALL [for load] but
	// will not produce a usable applet at INSTALL [for install]
	// stage. Useful only for testing the host-side LOAD chain
	// against cards that reject Applet-bearing loads.
	IncludeApplet bool
}

// DefaultLoadImagePolicy is the recommended policy for production
// applet loading: include all execution-relevant components,
// exclude debug and descriptor metadata. This matches the
// convention used by Oracle's reference converter, GP Pro
// (default), and SafeNet's load tool.
func DefaultLoadImagePolicy() LoadImagePolicy {
	return LoadImagePolicy{
		ExcludeDebug:      true,
		ExcludeDescriptor: true,
		IncludeApplet:     true,
	}
}

// LoadFileDataBlock assembles the Java Card Load File Data Block
// (LFDB) — the concatenation of the chosen CAP components in JC VM
// Spec load order. Each component contributes its full file content
// (tag byte + 2-byte size + payload), as the runtime expects to
// parse them sequentially.
//
// The LFDB is the bytes that go INSIDE the C4 wrapper at LOAD time.
// It is also the input to the Load File Data Block Hash field of
// INSTALL [for load] per GP §11.5.2.3 — the hash is over the LFDB
// alone, NOT over the C4-wrapped form. To get the complete wire-
// format Load File for streaming through LOAD, wrap the LFDB with
// gp.BuildPlainLoadFile.
//
// Returns ErrInvalidLoadImage if the policy excludes a required
// component (Header) or if the CAP has no components at all.
//
// The returned bytes are a fresh allocation; callers may modify or
// extend the slice without affecting the underlying CAP.
func (c *CAPFile) LoadFileDataBlock(policy LoadImagePolicy) ([]byte, error) {
	return c.LoadImage(policy)
}

// LoadFileDataBlockHashes computes the SHA-256 and SHA-1 digests
// over the Load File Data Block (NOT over the C4-wrapped wire-
// format Load File). Equivalent to gp.LoadFileDataBlockHashes
// applied to LoadFileDataBlock(policy), bundled here for callers
// that have a CAPFile in hand.
func (c *CAPFile) LoadFileDataBlockHashes(policy LoadImagePolicy) (sha256Sum, sha1Sum []byte, err error) {
	lfdb, err := c.LoadFileDataBlock(policy)
	if err != nil {
		return nil, nil, err
	}
	return LoadFileDataBlockHashes(lfdb)
}

// LoadImage is the legacy name for LoadFileDataBlock. It returns
// the Java Card Load File Data Block (LFDB), NOT the wire-format
// Load File — the previous version of this comment claimed the
// output was the byte stream the host streams through LOAD, which
// is wrong: the wire-format Load File requires the C4 wrapper
// (see gp.BuildPlainLoadFile). The function itself is correct;
// only the docstring needed updating.
//
// New code should call LoadFileDataBlock for clarity.
func (c *CAPFile) LoadImage(policy LoadImagePolicy) ([]byte, error) {
	if len(c.Components) == 0 {
		return nil, fmt.Errorf("%w: CAP has no components", ErrInvalidLoadImage)
	}

	keep := c.LoadImageComponents(policy)
	if len(keep) == 0 {
		return nil, fmt.Errorf("%w: policy excludes all components", ErrInvalidLoadImage)
	}

	// Header.cap is required: the card uses it to validate the
	// package AID before allocating storage. A CAP missing
	// Header is malformed (the parser would have rejected it),
	// but a policy that somehow excluded Header would produce
	// an unloadable image; flag that explicitly.
	hasHeader := false
	for _, comp := range keep {
		if comp.Name == componentNameHeader {
			hasHeader = true
			break
		}
	}
	if !hasHeader {
		return nil, fmt.Errorf("%w: Header.cap missing from load image", ErrInvalidLoadImage)
	}

	// Concatenate. Pre-size to avoid repeated reallocs on large
	// CAPs; total size is the sum of len(Raw) across kept
	// components.
	total := 0
	for _, comp := range keep {
		total += len(comp.Raw)
	}
	out := make([]byte, 0, total)
	for _, comp := range keep {
		out = append(out, comp.Raw...)
	}
	return out, nil
}

// LoadImageComponents returns the components that survive the
// policy filter, in load order. Used by callers that want to
// surface "what's actually in the image" before issuing a LOAD
// — for example, the gp install dry-run preflight prints the
// component list so the operator can verify Debug/Descriptor
// exclusion matches expectations. Does not allocate; returns a
// slice into the caller's CAPFile.Components.
func (c *CAPFile) LoadImageComponents(policy LoadImagePolicy) []CAPComponent {
	var keep []CAPComponent
	for _, comp := range c.Components {
		switch comp.Name {
		case componentNameDebug:
			if policy.ExcludeDebug {
				continue
			}
		case componentNameDescriptor:
			if policy.ExcludeDescriptor {
				continue
			}
		case componentNameApplet:
			if !policy.IncludeApplet {
				continue
			}
		}
		keep = append(keep, comp)
	}
	return keep
}

// LoadImageHashes is the legacy name for LoadFileDataBlockHashes.
// It computes both SHA-256 and SHA-1 over the LFDB (the bytes
// inside the C4 wrapper, NOT the wire-format Load File). Per the
// rename in CAPFile.LoadImage's doc, the function itself is
// correct — only the framing was misleading.
//
// New code should call LoadFileDataBlockHashes for clarity.
func (c *CAPFile) LoadImageHashes(policy LoadImagePolicy) (sha256Sum, sha1Sum []byte, err error) {
	image, err := c.LoadImage(policy)
	if err != nil {
		return nil, nil, err
	}
	s256 := sha256.Sum256(image)
	s1 := sha1.Sum(image) //nolint:gosec // see file header
	return s256[:], s1[:], nil
}

// ErrInvalidLoadImage indicates that the requested load image
// could not be assembled (CAP missing required components,
// policy excludes everything, etc.). Distinct from the parser's
// validation errors so callers can distinguish "this CAP is
// malformed" from "this policy is incompatible with this CAP."
var ErrInvalidLoadImage = errInvalidLoadImage{}

type errInvalidLoadImage struct{}

func (errInvalidLoadImage) Error() string { return "invalid load image" }
