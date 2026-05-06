package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/PeculiarVentures/scp/piv"
	"github.com/PeculiarVentures/scp/piv/profile"
	"github.com/PeculiarVentures/scp/piv/session"
	"github.com/PeculiarVentures/scp/transport"
)

// cmdPIVKey dispatches `scpctl piv key <verb>`.
func cmdPIVKey(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv key <generate|attest> [flags]"}
	}
	switch args[0] {
	case "generate":
		return cmdPIVKeyGenerate(ctx, env, args[1:])
	case "attest":
		return cmdPIVKeyAttest(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv key <generate|attest>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown key subcommand %q", args[0])}
}

// cmdPIVCert dispatches `scpctl piv cert <verb>`.
func cmdPIVCert(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv cert <get|put|delete> [flags]"}
	}
	switch args[0] {
	case "get":
		return cmdPIVCertGet(ctx, env, args[1:])
	case "put":
		return cmdPIVCertPut(ctx, env, args[1:])
	case "delete":
		return cmdPIVCertDelete(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv cert <get|put|delete>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown cert subcommand %q", args[0])}
}

// cmdPIVObject dispatches `scpctl piv object <verb>`.
func cmdPIVObject(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv object <get|put> [flags]"}
	}
	switch args[0] {
	case "get":
		return cmdPIVObjectGet(ctx, env, args[1:])
	case "put":
		return cmdPIVObjectPut(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv object <get|put>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown object subcommand %q", args[0])}
}

// cmdPIVMgmt dispatches `scpctl piv mgmt <verb>`.
func cmdPIVMgmt(ctx context.Context, env *runEnv, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: "scpctl piv mgmt <auth|change-key> [flags]"}
	}
	switch args[0] {
	case "auth":
		return cmdPIVMgmtAuth(ctx, env, args[1:])
	case "change-key":
		return cmdPIVMgmtChangeKey(ctx, env, args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(env.out, "scpctl piv mgmt <auth|change-key>")
		return nil
	}
	return &usageError{msg: fmt.Sprintf("unknown mgmt subcommand %q", args[0])}
}

// resolveMgmtKey turns the (possibly empty) operator-supplied
// management-key flags into a piv.ManagementKey, deferring the
// algorithm choice to the session's active profile when the flag
// was left at its zero value.
//
// The fix here is to never default to AES-192 before knowing what
// card we're talking to. AES-192 is the YubiKey 5.4.2+ factory
// default; YubiKey pre-5.4.2 ships 3DES, and Standard PIV cards
// follow SP 800-78-4 which historically meant 3DES (with AES added
// in SP 800-78-5 but no spec-mandated default). Defaulting to
// AES-192 unconditionally would silently fail mutual auth on the
// other classes of card.
//
// Callers must call this with a constructed session so the profile
// is available. keyHex empty means "use the well-known factory
// default for the active profile's default algorithm". algoStr
// empty means "use the active profile's default algorithm". Both
// empty means "factory key, factory algorithm, whatever the profile
// says that is".
func resolveMgmtKey(sess sessionForMgmt, keyHex, algoStr string) (piv.ManagementKey, error) {
	caps := sess.Profile().Capabilities()

	// Algorithm: empty means "profile default".
	var algo piv.ManagementKeyAlgorithm
	if algoStr == "" {
		algo = caps.DefaultMgmtKeyAlg
	} else {
		var err error
		algo, err = piv.ParseManagementKeyAlgorithm(algoStr)
		if err != nil {
			return piv.ManagementKey{}, err
		}
	}

	// Key: empty means "factory default for the algorithm".
	if keyHex == "" {
		keyHex = "default"
	}

	mk, err := piv.ParseManagementKey(keyHex, algo.String())
	if err != nil {
		// piv.ParseManagementKey accepts the literal "default" only
		// when the algorithm is one whose key length matches the
		// 24-byte well-known value (3DES or AES-192). Surface a
		// clearer error for AES-128/AES-256 + "default" so the
		// operator knows to supply the actual key bytes.
		return piv.ManagementKey{}, fmt.Errorf("management key: %w", err)
	}
	return mk, nil
}

// sessionForMgmt is the minimal session interface resolveMgmtKey
// needs, so tests can pass a stub without standing up a real
// session.
type sessionForMgmt interface {
	Profile() profile.Profile
}

// scp11bChannelFlags is the cluster of flags every destructive or
// credential-bearing scpctl piv command exposes. The mode for the
// session is chosen by --scp11b (secure channel) versus
// --raw-local-ok (explicit raw-mode acknowledgement). Exactly one
// must be set; the absence of both is a usage error.
//
// Raw mode is the right choice for local-USB administration where
// the host running scpctl is in the operator's trust boundary.
// SCP11b is the right choice for APDU relays, browser-mediated
// sessions, remote provisioning, or any host path the operator
// does not control end to end. See docs/piv.md for the threat-
// model split.
type scp11bChannelFlags struct {
	scp11b     *bool
	rawLocalOK *bool
	trust      *trustFlags
}

// registerSCP11bChannelFlags adds --scp11b plus the shared trust
// flags (--trust-roots, --lab-skip-scp11-trust) plus --raw-local-ok
// to fs. Returns a handle that openPIVSession reads.
//
// The --raw-local-ok flag is the explicit acknowledgement that
// running raw (no secure channel) is acceptable for the operator's
// trust boundary. Default behavior is fail-closed: a destructive or
// credential-bearing scpctl piv command without either --scp11b or
// --raw-local-ok rejects with a clear error explaining the choice.
//
// The asymmetry (require positive assertion of raw mode rather than
// requiring --scp11b) is deliberate: SCP11b is the right answer for
// any environment that is not the operator's own machine in front of
// their own card, and an operator who hasn't thought about which
// they're in should not get raw mode by accident. Forcing a positive
// assertion either way prevents a silent downgrade.
func registerSCP11bChannelFlags(fs *flag.FlagSet) *scp11bChannelFlags {
	return &scp11bChannelFlags{
		scp11b: fs.Bool("scp11b", false,
			"Run this destructive operation over an SCP11b-on-PIV secure channel "+
				"instead of raw APDUs. Required for any host path that is not in the "+
				"operator's trust boundary (APDU relay, remote provisioning, "+
				"browser-mediated sessions). See docs/piv.md."),
		rawLocalOK: fs.Bool("raw-local-ok", false,
			"Explicitly assert that raw APDUs are acceptable for this invocation "+
				"because the host is in the operator's trust boundary (typical "+
				"local-USB administration). Required when --scp11b is not set. "+
				"Mutually exclusive with --scp11b."),
		trust: registerTrustFlags(fs),
	}
}

// validate is the early-return channel-mode check. Every handler
// that uses registerSCP11bChannelFlags should call this immediately
// after fs.Parse, before any handler-specific I/O. The reason for
// the early call is ordering: an operator who passes incompatible
// channel-mode flags should see that error before any downstream
// flag-reading-from-disk (like --cert <path> or --in <path>) gets
// a chance to fail with a different error. openPIVSession does the
// same check defensively, but every handler should call validate
// up front so the error surface is predictable.
func (f *scp11bChannelFlags) validate() error {
	switch {
	case *f.scp11b && *f.rawLocalOK:
		return &usageError{msg: "--scp11b and --raw-local-ok are mutually exclusive; pick one"}
	case !*f.scp11b && !*f.rawLocalOK:
		return &usageError{msg: "this command requires either --scp11b (secure channel) or --raw-local-ok (explicit raw-mode acknowledgement for local-USB administration); see docs/piv.md for the threat-model split"}
	}
	return nil
}

// openPIVSession is the session-construction path every destructive
// or credential-bearing scpctl piv handler uses. The channel mode is
// chosen by the flag pair (--scp11b, --raw-local-ok); exactly one
// must be set. The fail-closed default (neither set is a usage
// error) prevents a silent downgrade from secure-channel to raw
// transport when an operator forgets to type a flag.
//
// When --scp11b is set without a trust posture (no --trust-roots
// and no --lab-skip-scp11-trust), the report gets a SKIP entry
// (consistent with applyTrust elsewhere in the binary) and the
// function returns (nil, false, nil); the caller emits the report
// and returns without a transmit attempt.
//
// Returns (sess, true, nil) on success; the caller is responsible
// for sess.Close(). The bool is "proceed"; false plus nil err
// means a clean SKIP path.
func openPIVSession(
	ctx context.Context,
	t transportLike,
	flags *scp11bChannelFlags,
	report *Report,
) (*session.Session, bool, error) {
	switch {
	case *flags.scp11b && *flags.rawLocalOK:
		return nil, false, &usageError{msg: "--scp11b and --raw-local-ok are mutually exclusive; pick one"}
	case !*flags.scp11b && !*flags.rawLocalOK:
		return nil, false, &usageError{msg: "this command requires either --scp11b (secure channel) or --raw-local-ok (explicit raw-mode acknowledgement for local-USB administration); see docs/piv.md for the threat-model split"}
	}

	if *flags.rawLocalOK {
		// --raw-local-ok asserts the host running scpctl is in the
		// operator's trust boundary. The transport itself reports
		// whether it can carry that assertion: PC/SC is local-by-
		// definition, gRPC relay is not, and anything that doesn't
		// declare its boundary (mocks, future custom transports
		// that haven't opted in) defaults to TrustBoundaryUnknown
		// and is refused. This is the difference between an
		// operator assertion and a system-level guarantee: the flag
		// alone is the assertion, the transport-reported boundary
		// is what backs the assertion with infrastructure.
		//
		// Tests that need to exercise raw paths against a mock
		// transport route through an explicit override wrapper
		// (rawLocalAcknowledgedTransport in cmd_piv_ops_test.go);
		// production code paths cannot reach this branch with a
		// non-local transport because pcscConnect is the only
		// transport factory wired into main.
		boundary := t.TrustBoundary()
		if boundary != transport.TrustBoundaryLocalPCSC {
			return nil, false, &usageError{msg: fmt.Sprintf(
				"--raw-local-ok refused: transport reports trust boundary %q, not %q. Raw mode requires a transport whose host-to-card path is in the operator's trust boundary (local PC/SC). Use --scp11b for relayed or remote transports.",
				boundary, transport.TrustBoundaryLocalPCSC)}
		}
		report.TransportSecurity = TransportSecurityRawPCSC
		report.Pass("channel mode", "raw (operator asserted local-USB trust)")
		sess, err := session.New(ctx, t, session.Options{})
		if err != nil {
			return nil, false, err
		}
		return sess, true, nil
	}

	policy, insecureSkip, proceed, err := flags.trust.applyToPIVTrust(report)
	if err != nil {
		return nil, false, err
	}
	if !proceed {
		return nil, false, nil
	}
	sess, err := session.OpenSCP11bPIV(ctx, t, session.SCP11bPIVOptions{
		CardTrustPolicy:                policy,
		InsecureSkipCardAuthentication: insecureSkip,
	})
	if err != nil {
		return nil, false, fmt.Errorf("scp11b open: %w", err)
	}
	report.TransportSecurity = TransportSecurityScp11bPIV
	report.Pass("channel mode", "scp11b-on-piv")
	return sess, true, nil
}

// transportLike is the minimal Transport interface session.New and
// session.OpenSCP11bPIV both accept. Defined locally so the helper
// signature does not pull a transport import into every caller.
type transportLike = transport.Transport

// readCertPEM reads a PEM-encoded certificate from disk and parses
// the first CERTIFICATE block. Helper shared by cert put and similar
// flows that take a cert on the command line.
func readCertPEM(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// readPublicKeyPEM reads a PEM-encoded SubjectPublicKeyInfo from
// disk and returns the parsed public key (any algorithm).
func readPublicKeyPEM(path string) (interface{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
