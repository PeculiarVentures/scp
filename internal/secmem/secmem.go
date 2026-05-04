// Package secmem provides best-effort secure-memory primitives shared
// across the SCP03 / SCP11 / KDF code paths. It is internal because it
// is a leaf utility, not part of the public API surface — callers
// outside this module should reach for crypto/subtle.ConstantTimeXxx
// primitives or the mlock/secret-handling library of their choice.
//
// Best effort: Go gives us no real memory-zeroization primitive.
// Stack copies, escape analysis, and GC reachability all conspire to
// leave plaintext key bytes in memory longer than the source code
// suggests. The Zero function below uses //go:noinline +
// runtime.KeepAlive to keep the compiler from optimizing the write
// loop away, which is the most we can portably promise. It is not a
// replacement for OS-level mlock or hardware-backed key storage when
// those are appropriate.
package secmem

import "runtime"

// Zero overwrites b with zeros. Intended for clearing key material
// at the end of its useful life (Session.Close, KDF.Derive postlude,
// etc.). The //go:noinline directive plus runtime.KeepAlive is a
// defense against compiler dead-store elimination: without them, a
// loop that only writes to a slice that is never read again can be
// removed entirely by the optimizer.
//
// Zero is safe to call with a nil or empty slice (no-op).
//
//go:noinline
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
