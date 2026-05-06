package main

// Tests for sd keys export --chain-order: leaf detection,
// reorder semantics, and round-trip safety.
//
// The default 'as-stored' is an alias for 'whatever the card
// gave us' — it's a no-op. The interesting paths are 'leaf-last'
// (defensive against malformed cards; same as as-stored on
// conforming cards) and 'leaf-first' (compatibility with tooling
// that expects leaf-at-start).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeChainOrderTestChain builds a 3-cert chain: root → intermediate
// → leaf. Returned in a CALLER-SPECIFIED order so the test can
// place the leaf wherever it wants for reorder verification.
//
// Returns (root, intermediate, leaf) by reference — the caller
// composes the slice in whatever order the test needs.
func makeChainOrderTestChain(t *testing.T) (root, intermediate, leaf *x509.Certificate) {
	t.Helper()

	// Root.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("rootKey: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chain-order test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	root, _ = x509.ParseCertificate(rootDER)

	// Intermediate, signed by root.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("intKey: %v", err)
	}
	intTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "chain-order test intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intermediate, _ = x509.ParseCertificate(intDER)

	// Leaf, signed by intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leafKey: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "chain-order test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, intermediate, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)

	return root, intermediate, leaf
}

// TestReorderChain_AsStored_NoOp confirms 'as-stored' returns the
// input unchanged regardless of input order.
func TestReorderChain_AsStored_NoOp(t *testing.T) {
	root, inter, leaf := makeChainOrderTestChain(t)
	for _, in := range [][]*x509.Certificate{
		{root, inter, leaf},
		{leaf, inter, root},
		{inter, root, leaf},
	} {
		got, err := reorderChain(in, "as-stored")
		if err != nil {
			t.Fatalf("as-stored should never error: %v", err)
		}
		if len(got) != len(in) {
			t.Errorf("length changed: got %d want %d", len(got), len(in))
			continue
		}
		for i := range in {
			if got[i] != in[i] {
				t.Errorf("position %d: got %s want %s",
					i, got[i].Subject.CommonName, in[i].Subject.CommonName)
			}
		}
	}
}

// TestReorderChain_LeafLast_FromLeafFirst_Reorders confirms a
// leaf-first input gets reorganized to leaf-last.
func TestReorderChain_LeafLast_FromLeafFirst_Reorders(t *testing.T) {
	root, inter, leaf := makeChainOrderTestChain(t)
	in := []*x509.Certificate{leaf, inter, root}
	got, err := reorderChain(in, "leaf-last")
	if err != nil {
		t.Fatalf("leaf-last reorder: %v", err)
	}
	if got[len(got)-1] != leaf {
		t.Errorf("expected leaf at last position, got %s",
			got[len(got)-1].Subject.CommonName)
	}
}

// TestReorderChain_LeafLast_FromLeafLast_Stable confirms a
// leaf-last input stays leaf-last (the leaf goes to the end —
// where it already was).
func TestReorderChain_LeafLast_FromLeafLast_Stable(t *testing.T) {
	root, inter, leaf := makeChainOrderTestChain(t)
	in := []*x509.Certificate{root, inter, leaf}
	got, err := reorderChain(in, "leaf-last")
	if err != nil {
		t.Fatalf("leaf-last reorder: %v", err)
	}
	if got[len(got)-1] != leaf {
		t.Errorf("leaf should still be last, got %s",
			got[len(got)-1].Subject.CommonName)
	}
}

// TestReorderChain_LeafFirst_FromLeafLast_Reorders confirms a
// leaf-last input gets flipped to leaf-first.
func TestReorderChain_LeafFirst_FromLeafLast_Reorders(t *testing.T) {
	root, inter, leaf := makeChainOrderTestChain(t)
	in := []*x509.Certificate{root, inter, leaf}
	got, err := reorderChain(in, "leaf-first")
	if err != nil {
		t.Fatalf("leaf-first reorder: %v", err)
	}
	if got[0] != leaf {
		t.Errorf("expected leaf at first position, got %s",
			got[0].Subject.CommonName)
	}
}

// TestReorderChain_SingleCert_Trivial confirms single-cert chains
// pass through every order unchanged. Single-cert chains are
// simultaneously leaf-first and leaf-last so any order is correct.
func TestReorderChain_SingleCert_Trivial(t *testing.T) {
	_, _, leaf := makeChainOrderTestChain(t)
	for _, order := range []string{"as-stored", "leaf-last", "leaf-first"} {
		got, err := reorderChain([]*x509.Certificate{leaf}, order)
		if err != nil {
			t.Errorf("order=%s: unexpected error %v", order, err)
		}
		if len(got) != 1 || got[0] != leaf {
			t.Errorf("order=%s: single-cert reorder broke the chain", order)
		}
	}
}

// TestFindLeafIndex_ThreeCertChain finds the leaf in a normal
// root → intermediate → leaf chain.
func TestFindLeafIndex_ThreeCertChain(t *testing.T) {
	root, inter, leaf := makeChainOrderTestChain(t)
	// Try several input orderings — leaf detection is order-
	// independent.
	cases := []struct {
		name string
		in   []*x509.Certificate
		want int // index of leaf in input slice
	}{
		{"root-first", []*x509.Certificate{root, inter, leaf}, 2},
		{"leaf-first", []*x509.Certificate{leaf, inter, root}, 0},
		{"middle", []*x509.Certificate{root, leaf, inter}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := findLeafIndex(c.in)
			if err != nil {
				t.Fatalf("findLeafIndex: %v", err)
			}
			if got != c.want {
				t.Errorf("got index %d, want %d", got, c.want)
			}
		})
	}
}

// TestFindLeafIndex_AmbiguousChain_Errors covers the
// no-clear-leaf case: a chain containing two unrelated leaves
// (e.g. the on-card store accidentally has a leaf from a
// different chain mixed in). The function must error rather
// than silently picking one.
func TestFindLeafIndex_AmbiguousChain_Errors(t *testing.T) {
	_, _, leafA := makeChainOrderTestChain(t)
	_, _, leafB := makeChainOrderTestChain(t)
	// Two unrelated leaves: neither signs anything else in the
	// chain, so both look like leaves.
	in := []*x509.Certificate{leafA, leafB}
	_, err := findLeafIndex(in)
	if err == nil {
		t.Fatal("expected ambiguous-leaf error, got nil")
	}
}
