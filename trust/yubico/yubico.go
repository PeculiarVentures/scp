// Package yubico provides the set of Yubico-published root CAs that
// sign YubiKey attestation certificates, including the SCP11
// CERT.SD.ECKA chain emitted on YubiKey 5.7.4+.
//
// The roots are embedded at build time from
// trust/yubico/roots.pem, which is a verbatim copy of
// https://developers.yubico.com/PKI/yubico-ca-certs.txt. As of
// 2026-05-04 that file contains five certificates:
//
//	Yubico U2F Root CA Serial 457200631   (legacy FIDO U2F)
//	Yubico PIV Root CA Serial 263751      (legacy PIV attestation)
//	Yubico OpenPGP Attestation CA
//	Yubico FIDO Root CA Serial 450203556  (newer FIDO)
//	Yubico Attestation Root 1             (unified 2025 root, signs 5.7.4+)
//
// SCP11 callers want the unified 2025 root for current YubiKey 5.7.4+
// hardware. The package returns the full bundle (Roots) so callers
// don't have to pick — chain validation will use whichever root the
// card's chain actually leads to.
//
// The embedded file is also accessible verbatim via PEM() for callers
// that need to compute their own fingerprints or pass the raw bytes
// to other tooling. The file's SHA-256 is documented in the package's
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

// PEM returns the verbatim PEM bundle as published by Yubico. The
// returned slice is a fresh copy; mutating it does not affect future
// calls.
func PEM() []byte {
	out := make([]byte, len(embeddedRootsPEM))
	copy(out, embeddedRootsPEM)
	return out
}

// Certs parses the embedded bundle and returns every CERTIFICATE
// block as a parsed *x509.Certificate. The slice order matches the
// order of the PEM blocks in roots.pem. Returns an error if the
// embedded file isn't well-formed — that should never happen at
// runtime because the contents are vendored, but parsing is wired
// up rather than panicked so callers can surface a helpful message
// if a build accidentally embeds a corrupted file.
func Certs() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := embeddedRootsPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Skip non-CERTIFICATE blocks rather than failing the
			// whole load. The published bundle has only
			// CERTIFICATE blocks today, but ignoring foreign
			// blocks keeps us forward-compatible if Yubico ever
			// inlines other artifacts (signatures, manifests).
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust/yubico: parse cert %d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("trust/yubico: embedded roots.pem contains no CERTIFICATE blocks")
	}
	return certs, nil
}

// Roots returns a *x509.CertPool populated with every root in the
// embedded bundle. Suitable for use as scp11.Config.CardTrustAnchors
// or as the Roots field of a trust.Policy.
//
// SCP11b on YubiKey 5.7.4+ chains to "Yubico Attestation Root 1"
// (the unified 2025 root). Older YubiKeys may chain to the legacy
// PIV or FIDO roots; including all five in the pool means the same
// helper works across the whole product line without the caller
// having to identify which root applies.
func Roots() (*x509.CertPool, error) {
	certs, err := Certs()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}
