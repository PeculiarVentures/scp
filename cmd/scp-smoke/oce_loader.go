package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// loadOCEPrivateKey reads a PEM file containing an EC private key
// and returns it as an *ecdsa.PrivateKey. Handles both PKCS#8
// ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") encodings — Yubico
// reference fixtures use SEC1 but openssl/openssh tooling defaults
// to PKCS#8, so accepting both makes the CLI usable with whatever
// the operator already has.
//
// The key must be on the NIST P-256 curve. SCP11 mandates P-256
// (GP Amendment F §7.1.1.4); a key on any other curve would be
// rejected later by scp11.Open after a more confusing error chain,
// so failing fast here gives a clearer message.
func loadOCEPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OCE key %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("OCE key %q: no PEM block found", path)
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 — modern default from openssl genpkey.
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 OCE key: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("OCE key is not ECDSA (got %T)", k)
		}
		key = ec
	case "EC PRIVATE KEY":
		// SEC1 — what older openssl defaults to and what Yubico's
		// reference fixtures use.
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC1 OCE key: %w", err)
		}
		key = k
	default:
		return nil, fmt.Errorf("OCE key %q: unsupported PEM type %q (want PRIVATE KEY or EC PRIVATE KEY)", path, block.Type)
	}

	if key.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("OCE key %q: curve is %s, SCP11 requires P-256", path, key.Curve.Params().Name)
	}
	return key, nil
}

// loadOCECertChain reads a PEM file containing one or more X.509
// certificates concatenated and returns them in leaf-LAST order, as
// scp11.Config.OCECertificates expects. The caller is responsible
// for ensuring the leaf cert (the OCE's own certificate) is the
// final entry — this function just preserves whatever order is in
// the file. A single self-issued OCE cert is expressed as a
// one-element slice.
func loadOCECertChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OCE certs %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Skip unknown block types rather than fail — operators
			// sometimes prepend trust-store comments or paste keys
			// alongside certs by accident.
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse OCE cert in %q: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("OCE cert file contains no CERTIFICATE blocks")
	}
	return certs, nil
}
