package main

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is required by some legacy GP load-token policies
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// loadHashSpec is the parsed form of --load-hash. Algorithm names
// the digest applied to the load image; Bytes carries the digest
// for hex literal mode where the operator supplied raw bytes.
//
// Modes:
//
//	none      no hash sent on the wire; LoadHash is nil. Default.
//	sha1      SHA-1 of the load image, computed by the CLI.
//	sha256    SHA-256 of the load image, computed by the CLI.
//	hex:<hex> raw bytes the operator supplied, sent verbatim.
//
// The mode-and-bytes pairing rules out a CLI invocation that
// supplies both a named algorithm and a hex value: pick one.
type loadHashSpec struct {
	Algorithm string // "none" | "sha1" | "sha256" | "hex"
	Bytes     []byte // populated for "hex"; empty for "none"; computed lazily for sha1/sha256
}

// parseLoadHashFlag decodes the --load-hash CLI value. Empty
// means default (none). The returned spec is ready to be applied
// to a load image via Resolve.
func parseLoadHashFlag(value string) (loadHashSpec, error) {
	v := strings.TrimSpace(value)
	if v == "" || strings.EqualFold(v, "none") {
		return loadHashSpec{Algorithm: "none"}, nil
	}
	switch strings.ToLower(v) {
	case "sha1":
		return loadHashSpec{Algorithm: "sha1"}, nil
	case "sha256":
		return loadHashSpec{Algorithm: "sha256"}, nil
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(v), "hex:"); ok {
		// Accept the "hex:" prefix lowercase but decode the
		// original suffix to preserve case-irrelevant hex.
		idx := strings.Index(strings.ToLower(value), "hex:")
		raw := strings.TrimSpace(value[idx+4:])
		raw = strings.NewReplacer(":", "", " ", "").Replace(raw)
		b, err := hex.DecodeString(raw)
		if err != nil {
			return loadHashSpec{}, fmt.Errorf("--load-hash hex: invalid hex %q: %w", rest, err)
		}
		if len(b) == 0 {
			return loadHashSpec{}, fmt.Errorf("--load-hash hex: empty digest")
		}
		return loadHashSpec{Algorithm: "hex", Bytes: b}, nil
	}
	return loadHashSpec{}, fmt.Errorf("--load-hash: unrecognized value %q (expected none, sha1, sha256, or hex:<digest>)", value)
}

// Resolve returns the bytes to place in InstallOptions.LoadHash
// for this image. "none" returns nil. "sha1" and "sha256" hash
// the supplied image. "hex" returns the operator-supplied bytes
// regardless of the image content.
func (s loadHashSpec) Resolve(image []byte) []byte {
	switch s.Algorithm {
	case "sha1":
		sum := sha1.Sum(image) //nolint:gosec
		return sum[:]
	case "sha256":
		sum := sha256.Sum256(image)
		return sum[:]
	case "hex":
		out := make([]byte, len(s.Bytes))
		copy(out, s.Bytes)
		return out
	}
	return nil
}

// Label returns the algorithm name for reports and JSON output.
// "hex" surfaces with the byte length so the operator can
// confirm they supplied the digest they meant.
func (s loadHashSpec) Label() string {
	if s.Algorithm == "hex" {
		return fmt.Sprintf("hex (%d bytes)", len(s.Bytes))
	}
	return s.Algorithm
}
