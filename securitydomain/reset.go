package securitydomain

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/transport"
)

// ResetSecurityDomain triggers a factory reset of the card's
// Security Domain by opening an unauthenticated SD session and
// brute-forcing every installed key into AUTH_METHOD_BLOCKED state.
// After every key is blocked, the card auto-restores factory state:
//
//   - Default SCP03 keys at KVN=0xFF (KID=0x01,0x02,0x03)
//   - Freshly-generated SCP11b key at KID=0x13/KVN=0x01
//   - All custom OCE/SCP11a/SCP11c material removed
//
// PIV applet state — slots, certificates, PIN, PUK, management key —
// is unaffected. SD reset and PIV reset are separate operations on
// separate applets.
//
// This entry point exists for the recovery case where the card has
// custom keys installed (e.g. a partial bootstrap) but its factory
// SCP03 keys have been consumed and no authentication is possible.
// yubikit's reset routine is similarly auth-free: it works by
// sending wrong credentials until each key locks itself out, which
// doesn't require knowing the right credentials in the first place.
//
// Ref: yubikit-python SecurityDomainSession.reset(),
// Yubico .NET SecurityDomainSession.Reset().
func ResetSecurityDomain(ctx context.Context, t transport.Transport) error {
	if t == nil {
		return fmt.Errorf("securitydomain: ResetSecurityDomain requires a non-nil transport")
	}

	sd, err := OpenUnauthenticated(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("securitydomain: open SD for reset: %w", err)
	}
	defer sd.Close()

	if err := sd.Reset(ctx); err != nil {
		return fmt.Errorf("securitydomain: reset: %w", err)
	}
	return nil
}
