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

// LoadImage assembles the byte stream that the host streams to the
// card via INSTALL [for load] + LOAD per GP §11.6. The output is
// the concatenation of the chosen CAP components in JC VM Spec
// load order; each component contributes its full file content
// (tag byte + 2-byte size + payload bytes), as the runtime
// expects to parse them sequentially.
//
// Returns ErrInvalidLoadImage if the policy excludes a required
// component (Header) or if the CAP has no components at all.
//
// The returned bytes are a fresh allocation; callers may modify
// or extend the slice without affecting the underlying CAP.
func (c *CAPFile) LoadImage(policy LoadImagePolicy) ([]byte, error) {
	if len(c.Components) == 0 {
		return nil, fmt.Errorf("%w: CAP has no components", ErrInvalidLoadImage)
	}

	// Filter components per policy. Order is preserved from the
	// parser's load-order normalization.
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

// LoadImageHashes computes both SHA-256 (preferred) and SHA-1
// (legacy compatibility) digests of the load image. The DAP
// signature path uses the SHA-256 hash; older cards may require
// SHA-1. Callers that don't need both should call LoadImage and
// hash the result themselves; this helper exists so destructive
// CLI flows can print both digests for operator verification
// before committing the install.
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
