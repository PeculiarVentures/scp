// Package yubico provides the set of Yubico-published CA
// certificates needed to validate YubiKey attestation chains —
// including the SCP11 CERT.SD.ECKA chain emitted on YubiKey 5.7.4+.
//
// Two PEM bundles are embedded at build time, each a verbatim copy
// of a file Yubico publishes at developers.yubico.com/PKI:
//
//	trust/yubico/roots.pem          (yubico-ca-certs.txt)
//	trust/yubico/intermediates.pem  (yubico-intermediate.pem)
//
// As of 2026-05-04 the roots file contains five self-signed roots:
//
//	Yubico U2F Root CA Serial 457200631   (legacy FIDO U2F)
//	Yubico PIV Root CA Serial 263751      (legacy PIV attestation)
//	Yubico OpenPGP Attestation CA
//	Yubico FIDO Root CA Serial 450203556  (newer FIDO)
//	Yubico Attestation Root 1             (unified 2025 root, signs 5.7.4+)
//
// And the intermediates file contains ten sub-CAs issued under the
// 2025 unified root, including the per-product attestation issuers:
//
//	Yubico Attestation Intermediate {A,B} 1
//	Yubico FIDO Attestation        {A,B} 1
//	Yubico OPGP Attestation        {A,B} 1
//	Yubico PIV Attestation         {A,B} 1
//	Yubico SD Attestation          {A,B} 1   ← signs SCP11 SD attestation chains
//
// Why both are needed for SCP11: the YubiKey emits its SCP11 SD
// CERT.SD.ECKA leaf and one intermediate ("YubiKey SD Attestation")
// over BF21. That intermediate is signed by Yubico SD Attestation B 1
// (an intermediate issuer), which is signed by Yubico Attestation
// Intermediate B 1, which is signed by the unified 2025 root. Chain
// validation therefore needs every cert above the in-card pair —
// the SD Attestation issuer and the umbrella intermediate — present
// as known trust material. Treating Yubico's published intermediates
// as additional trust anchors (alongside the roots) keeps validation
// closed against this curated set without requiring callers to
// understand the chain shape.
//
// API surface:
//
//   - Roots()             *x509.CertPool of the actual self-signed roots
//   - Intermediates()     *x509.CertPool of the published intermediates
//   - Pool()              merged pool: roots + intermediates as one trust set.
//                         This is what callers want for SCP11 chain validation.
//   - RootCerts()         parsed roots
//   - IntermediateCerts() parsed intermediates
//   - PEM()               raw roots PEM (verbatim Yubico file, defensive copy)
//   - IntermediatesPEM()  raw intermediates PEM (verbatim, defensive copy)
//
// SHA-256 fingerprints of the embedded files are documented in the
// commit history so out-of-band integrity checks remain straightforward.
package yubico

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

//go:embed roots.pem
var embeddedRootsPEM []byte

//go:embed intermediates.pem
var embeddedIntermediatesPEM []byte

// PEM returns the verbatim roots PEM bundle as published by Yubico
// (yubico-ca-certs.txt). The returned slice is a fresh copy;
// mutating it does not affect future calls.
//
// To get the intermediates bundle, use IntermediatesPEM.
func PEM() []byte {
	out := make([]byte, len(embeddedRootsPEM))
	copy(out, embeddedRootsPEM)
	return out
}

// IntermediatesPEM returns the verbatim intermediates PEM bundle as
// published by Yubico (yubico-intermediate.pem). The returned slice
// is a fresh copy.
func IntermediatesPEM() []byte {
	out := make([]byte, len(embeddedIntermediatesPEM))
	copy(out, embeddedIntermediatesPEM)
	return out
}

// Certs parses the embedded roots bundle and returns every
// CERTIFICATE block as a parsed *x509.Certificate. The slice order
// matches the order of the PEM blocks in roots.pem.
//
// Equivalent to RootCerts; kept under the original name for callers
// already using it.
func Certs() ([]*x509.Certificate, error) { return RootCerts() }

// RootCerts parses the embedded roots bundle (yubico-ca-certs.txt)
// and returns every CERTIFICATE block as a parsed *x509.Certificate.
// Self-signed roots only — for the published intermediates, use
// IntermediateCerts.
func RootCerts() ([]*x509.Certificate, error) {
	return parseEmbeddedBundle(embeddedRootsPEM, "roots.pem")
}

// IntermediateCerts parses the embedded intermediates bundle
// (yubico-intermediate.pem) and returns every CERTIFICATE block as
// a parsed *x509.Certificate.
//
// SCP11 SD attestation chains issued by retail YubiKey 5.7.4+ pass
// through one of these intermediates ("Yubico SD Attestation B 1")
// before reaching the unified 2025 root, so a CertPool that lacks
// them cannot validate the card's CERT.SD.ECKA leaf.
func IntermediateCerts() ([]*x509.Certificate, error) {
	return parseEmbeddedBundle(embeddedIntermediatesPEM, "intermediates.pem")
}

// parseEmbeddedBundle is the shared parser for the two embedded
// PEM files. Reading is wired up via x509 rather than panicked so
// callers see a helpful message if a build embedded a corrupted
// bundle — the contents are vendored and should always parse, but
// fail-loud beats a runtime nil dereference.
func parseEmbeddedBundle(raw []byte, name string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Skip non-CERTIFICATE blocks rather than failing the
			// whole load. The published bundles have only
			// CERTIFICATE blocks today, but ignoring foreign
			// blocks keeps us forward-compatible if Yubico ever
			// inlines other artifacts (signatures, manifests).
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust/yubico: parse cert %d in %s: %w",
				len(certs)+1, name, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("trust/yubico: embedded %s contains no CERTIFICATE blocks", name)
	}
	return certs, nil
}

// Roots returns a *x509.CertPool populated with the self-signed
// roots from yubico-ca-certs.txt only. Most callers want Pool
// instead — Pool also includes the published intermediates, which
// is necessary for SCP11 SD attestation chains to validate.
//
// Roots remains exposed for callers that need a strict roots-only
// pool (for example, software that walks the full chain itself and
// only wants to terminate at actual roots).
func Roots() (*x509.CertPool, error) {
	certs, err := RootCerts()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// Intermediates returns a *x509.CertPool populated with the
// published intermediate CAs from yubico-intermediate.pem only.
// Useful as the Intermediates field of x509.VerifyOptions when the
// caller's verifier is set up to accept only the actual roots as
// trust anchors.
func Intermediates() (*x509.CertPool, error) {
	certs, err := IntermediateCerts()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// Pool returns a *x509.CertPool populated with both the published
// roots and the published intermediates. This is what SCP11 callers
// want for scp11.Config.CardTrustAnchors / trust.Policy.Roots:
// chain validation succeeds at any cert in this pool, so a card
// chain ending at "Yubico SD Attestation B 1" (an intermediate) is
// accepted without the verifier having to find a path all the way
// up to "Yubico Attestation Root 1".
//
// The expanded "trust set" model is correct for closed-system
// attestation where the issuance hierarchy is curated by Yubico
// and changes only when Yubico publishes a new bundle.
func Pool() (*x509.CertPool, error) {
	roots, err := RootCerts()
	if err != nil {
		return nil, fmt.Errorf("trust/yubico: load roots: %w", err)
	}
	inters, err := IntermediateCerts()
	if err != nil {
		return nil, fmt.Errorf("trust/yubico: load intermediates: %w", err)
	}
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	for _, c := range inters {
		pool.AddCert(c)
	}
	return pool, nil
}
