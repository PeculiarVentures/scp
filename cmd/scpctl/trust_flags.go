package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	pivsession "github.com/PeculiarVentures/scp/piv/session"
	"github.com/PeculiarVentures/scp/scp11"
	"github.com/PeculiarVentures/scp/trust"
	"github.com/PeculiarVentures/scp/trust/yubico"
)

// trustFlags is the flag set every SCP11 command shares for
// configuring how the card's certificate is validated. There are
// three production-relevant configurations and one lab-only
// shortcut, and they are mutually exclusive:
//
//	--trust-roots <pem-path>   Validate the card cert chain against
//	                           the CA certs in the named PEM bundle.
//	                           Use this when validating against a
//	                           private root or a non-Yubico card.
//
//	--yubico-roots             Shortcut for the embedded
//	                           trust/yubico package — the bundle
//	                           Yubico publishes at
//	                           https://developers.yubico.com/PKI/yubico-ca-certs.txt,
//	                           including the unified 2025 root that
//	                           signs YubiKey 5.7.4+ attestations.
//	                           This is the production path for
//	                           retail YubiKey hardware.
//
//	--lab-skip-scp11-trust     Skip card cert validation entirely.
//	                           Wire-protocol smoke testing only;
//	                           against a real card this is opportunistic
//	                           encryption, not authenticated key
//	                           agreement.
//
//	(none set)                 Command reports a SKIP — refuses to
//	                           run rather than silently choosing one
//	                           behavior or the other.
//
// More than one set is a usage error.
type trustFlags struct {
	rootsPath   *string
	yubicoRoots *bool
	labSkip     *bool
}

// registerTrustFlags adds --trust-roots, --yubico-roots, and
// --lab-skip-scp11-trust to the given FlagSet. Returns a trustFlags
// handle to read parsed values and apply them to a scp11.Config.
func registerTrustFlags(fs *flag.FlagSet) *trustFlags {
	return &trustFlags{
		rootsPath: fs.String("trust-roots", "",
			"Path to PEM bundle of trusted SCP11 card-certificate root CAs. "+
				"Loaded into cfg.CardTrustAnchors so the card cert is verified "+
				"during the handshake. Mutually exclusive with --yubico-roots "+
				"and --lab-skip-scp11-trust."),
		yubicoRoots: fs.Bool("yubico-roots", false,
			"Use the embedded Yubico published root CA bundle (the same "+
				"file Yubico distributes at developers.yubico.com/PKI/yubico-ca-certs.txt). "+
				"Includes the unified 2025 root that signs YubiKey 5.7.4+ "+
				"attestations. Production path for retail YubiKey hardware. "+
				"Mutually exclusive with --trust-roots and --lab-skip-scp11-trust."),
		labSkip: fs.Bool("lab-skip-scp11-trust", false,
			"Skip SCP11 card certificate validation. Lab use only — "+
				"against a real card this is opportunistic encryption, not "+
				"authenticated key agreement. Mutually exclusive with "+
				"--trust-roots and --yubico-roots."),
	}
}

// applyTrust mutates cfg to reflect the trust-flag selection and
// reports the chosen mode through `report`. Returns:
//
//   - (true, nil)  — trust is configured (either real or lab-skip);
//     caller should proceed to scp11.Open.
//   - (false, nil) — neither flag set; report has a SKIP entry and
//     the caller should emit and return without
//     attempting to open. This matches the existing
//     "no trust roots configured" behavior.
//   - (false, err) — usage error (both flags set, or roots file
//     unreadable / empty / malformed). Caller should
//     return *usageError.
func (tf *trustFlags) applyTrust(cfg *scp11.Config, report *Report) (proceed bool, err error) {
	if err := tf.checkExclusion(); err != nil {
		return false, err
	}
	if *tf.labSkip {
		cfg.InsecureSkipCardAuthentication = true
		report.Pass("trust mode", "lab-skip (card cert NOT validated)")
		return true, nil
	}
	if *tf.yubicoRoots {
		pool, lerr := yubico.Roots()
		if lerr != nil {
			return false, &usageError{msg: fmt.Sprintf("--yubico-roots: %v", lerr)}
		}
		cfg.CardTrustAnchors = pool
		cfg.InsecureSkipCardAuthentication = false
		report.Pass("trust mode", "validating against embedded Yubico root bundle")
		return true, nil
	}
	if *tf.rootsPath != "" {
		pool, n, err := loadTrustRoots(*tf.rootsPath)
		if err != nil {
			return false, &usageError{msg: fmt.Sprintf("--trust-roots: %v", err)}
		}
		cfg.CardTrustAnchors = pool
		cfg.InsecureSkipCardAuthentication = false
		report.Pass("trust mode", fmt.Sprintf("validating against %d root(s) from %s", n, *tf.rootsPath))
		return true, nil
	}
	report.Skip("trust mode",
		"no trust roots configured; pass --yubico-roots for retail YubiKeys, "+
			"--trust-roots <pem> for a custom bundle, or --lab-skip-scp11-trust "+
			"for wire-protocol smoke")
	return false, nil
}

// checkExclusion enforces that at most one of --trust-roots,
// --yubico-roots, --lab-skip-scp11-trust is set. Returns a
// usage error listing the conflict if more than one was passed.
func (tf *trustFlags) checkExclusion() error {
	set := 0
	var which []string
	if *tf.labSkip {
		set++
		which = append(which, "--lab-skip-scp11-trust")
	}
	if *tf.yubicoRoots {
		set++
		which = append(which, "--yubico-roots")
	}
	if *tf.rootsPath != "" {
		set++
		which = append(which, "--trust-roots")
	}
	if set > 1 {
		return &usageError{msg: fmt.Sprintf(
			"%s are mutually exclusive; pass exactly one",
			strings.Join(which, ", "))}
	}
	return nil
}

// applyTrustToPIV mutates a piv/session.SCP11bPIVOptions to reflect
// the trust-flag selection, mirroring applyTrust's signature so the
// SCP11b-on-PIV smoke command reads the same way as the other smoke
// commands.
func (tf *trustFlags) applyTrustToPIV(opts *pivsession.SCP11bPIVOptions, report *Report) (proceed bool, err error) {
	policy, skip, proceed, err := tf.applyToPIVTrust(report)
	if err != nil || !proceed {
		return proceed, err
	}
	opts.CardTrustPolicy = policy
	opts.InsecureSkipCardAuthentication = skip
	return true, nil
}

// applyToPIVTrust is the trust-flag projection for piv/session's
// SCP11b helper, which takes a trust.Policy plus an explicit
// InsecureSkipCardAuthentication bool rather than an scp11.Config.
//
// Returns:
//   - (policy, false, true, nil) for --trust-roots: production path.
//   - (nil, true, true, nil) for --lab-skip-scp11-trust: lab.
//   - (nil, false, false, nil) for neither: caller should refuse to
//     proceed with a SKIP, the same shape applyTrust uses.
//   - (nil, false, false, err) for usage errors (both flags set, or
//     --trust-roots load failure).
//
// The report receives the same "trust mode" line applyTrust writes,
// so JSON output is consistent across raw and SCP11b paths.
func (tf *trustFlags) applyToPIVTrust(report *Report) (policy *trust.Policy, insecureSkip bool, proceed bool, err error) {
	if err := tf.checkExclusion(); err != nil {
		return nil, false, false, err
	}
	if *tf.labSkip {
		report.Pass("trust mode", "lab-skip (card cert NOT validated)")
		return nil, true, true, nil
	}
	if *tf.yubicoRoots {
		pool, lerr := yubico.Roots()
		if lerr != nil {
			return nil, false, false, &usageError{msg: fmt.Sprintf("--yubico-roots: %v", lerr)}
		}
		report.Pass("trust mode", "validating against embedded Yubico root bundle")
		return &trust.Policy{Roots: pool}, false, true, nil
	}
	if *tf.rootsPath != "" {
		pool, n, lerr := loadTrustRoots(*tf.rootsPath)
		if lerr != nil {
			return nil, false, false, &usageError{msg: fmt.Sprintf("--trust-roots: %v", lerr)}
		}
		report.Pass("trust mode", fmt.Sprintf("validating against %d root(s) from %s", n, *tf.rootsPath))
		return &trust.Policy{Roots: pool}, false, true, nil
	}
	report.Skip("trust mode",
		"no trust roots configured; pass --yubico-roots for retail YubiKeys, "+
			"--trust-roots <pem> for a custom bundle, or --lab-skip-scp11-trust "+
			"for wire-protocol smoke")
	return nil, false, false, nil
}

// loadTrustRoots reads a PEM file and returns an x509.CertPool
// containing every CERTIFICATE block parsed from it, plus the count.
// Empty file, no CERTIFICATE blocks, or parse errors are usage errors;
// the operator should know exactly what's in their trust bundle.
//
// Non-CERTIFICATE PEM blocks (e.g. an accidentally included private
// key) are reported as errors so a misnamed file doesn't silently
// produce an "empty" trust pool.
func loadTrustRoots(path string) (*x509.CertPool, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read %q: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, 0, fmt.Errorf("%q is empty", path)
	}
	pool := x509.NewCertPool()
	count := 0
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, 0, fmt.Errorf("%q: unexpected PEM type %q (want CERTIFICATE)", path, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("%q: parse certificate %d: %w", path, count+1, err)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("%q: no CERTIFICATE blocks found", path)
	}
	return pool, count, nil
}
