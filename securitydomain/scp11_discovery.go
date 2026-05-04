// SCP11 card-public-key discovery.
//
// SCP11b-on-PIV (and any SCP11 channel against an applet other than the
// SD itself) requires the host to obtain PK.SD.ECKA before the
// handshake. The certificate that contains it lives on the Security
// Domain. The PIV applet rejects GET DATA BF21 with SW=6D00 because the
// data object isn't part of its dispatch table.
//
// This file provides the SD-side fetch path: select the SD
// unauthenticated, GET DATA BF21 for a key reference, validate the
// returned chain, and extract the leaf's ECDH public key. The returned
// key is what scp11.Config.PreverifiedCardStaticPublicKey wants.
//
// References:
//   - Yubico yubikit.securitydomain.get_certificate_bundle: same flow
//     in Python, except yubikit returns the cert chain and lets the
//     caller verify, where here we offer two surfaces (FetchCardCerts
//     for full control, FetchCardPublicKey for the common case).
//   - GP Card Spec v2.3.1 §11.3 (GET DATA), Amendment F (SCP11).

package securitydomain

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/transport"
	"github.com/PeculiarVentures/scp/trust"
)

// FetchCardPublicKeyOptions configures FetchCardPublicKey.
type FetchCardPublicKeyOptions struct {
	// KeyReference identifies the SCP11 key on the card whose
	// certificate to fetch. For YubiKey 5.7+ the SCP11b key is
	// at KID=0x13 (KeyIDSCP11b); the factory KVN is 0x01.
	KeyReference KeyReference

	// CardTrustPolicy validates the returned chain via the trust
	// package. Production callers should set this. Either this or
	// InsecureSkipCardAuthentication must be set.
	CardTrustPolicy *trust.Policy

	// InsecureSkipCardAuthentication accepts the leaf cert without
	// chain validation. Lab use only — it reduces SCP11b to
	// opportunistic encryption against any responder.
	InsecureSkipCardAuthentication bool
}

// FetchCardPublicKey opens a read-only Security Domain session, reads
// the certificate bundle for the given key reference, validates the
// chain, and returns the leaf's static ECDH public key. The returned
// value is suitable for scp11.Config.PreverifiedCardStaticPublicKey.
//
// The caller-supplied transport is used for the SD select and the GET
// DATA round trip; the SD session is closed before the function
// returns. Callers that need the raw certificate chain (for example,
// to inspect attestation extensions on a YubiKey) should use
// FetchCardCerts instead.
func FetchCardPublicKey(
	ctx context.Context,
	t transport.Transport,
	opts FetchCardPublicKeyOptions,
) (*ecdh.PublicKey, error) {
	if opts.CardTrustPolicy == nil && !opts.InsecureSkipCardAuthentication {
		return nil, errors.New(
			"securitydomain: FetchCardPublicKey requires CardTrustPolicy " +
				"or InsecureSkipCardAuthentication to be set",
		)
	}

	certs, err := FetchCardCerts(ctx, t, opts.KeyReference)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf(
			"securitydomain: no certificate stored for key reference KID=0x%02X KVN=0x%02X",
			opts.KeyReference.ID, opts.KeyReference.Version,
		)
	}

	leaf := certs[len(certs)-1]
	if opts.CardTrustPolicy != nil {
		if _, err := trust.ValidateSCP11Chain(certs, *opts.CardTrustPolicy); err != nil {
			return nil, fmt.Errorf("securitydomain: SCP11 chain validation: %w", err)
		}
	}

	pub, err := ecdhPublicKeyFromX509(leaf)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: extract leaf public key: %w", err)
	}
	return pub, nil
}

// FetchCardCerts opens a read-only Security Domain session and returns
// the raw certificate chain (leaf last) for the given key reference.
// The session is closed before returning.
//
// Returns nil with no error if the card has no certificate stored at
// the given reference (SW=6A88 — Reference Data Not Found).
func FetchCardCerts(
	ctx context.Context,
	t transport.Transport,
	ref KeyReference,
) ([]*x509.Certificate, error) {
	sd, err := OpenUnauthenticated(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("securitydomain: open SD: %w", err)
	}
	defer sd.Close()

	certs, err := sd.GetCertificates(ctx, ref)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// ecdhPublicKeyFromX509 extracts an ECDH public key from an X.509
// certificate, requiring an ECDSA NIST P-256 SubjectPublicKeyInfo.
// SCP11 is defined over P-256 only.
func ecdhPublicKeyFromX509(cert *x509.Certificate) (*ecdh.PublicKey, error) {
	ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(
			"certificate public key is %T, not *ecdsa.PublicKey",
			cert.PublicKey,
		)
	}
	if ecdsaPub.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf(
			"certificate public key is on curve %s, SCP11 requires P-256",
			ecdsaPub.Curve.Params().Name,
		)
	}
	pub, err := ecdsaPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert ECDSA public key to ECDH: %w", err)
	}
	return pub, nil
}
