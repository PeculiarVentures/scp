// Package yubikey collects YubiKey-specific configuration helpers
// for the SCP03 and SCP11 protocol packages. Importing this package
// is the path callers take when they want to talk to a YubiKey
// without assembling SCP03 / SCP11 Config values by hand.
//
// # Why a separate package
//
// The core scp03 and scp11 packages are vendor-neutral: their
// types describe GP Card Spec / Amendment D / Amendment F surfaces,
// and the choices they default to (full security level, receipt
// verification required for SCP11b, channel-layer empty-data
// pad-and-encrypt) are spec-defensible. Card-specific knobs like
// "the factory key version YubiKey 5.x ships with" or "the SCP11
// SD slot KIDs YubiKey allocates" live here so the protocol
// packages do not carry a single vendor's name in their public
// API surface.
//
// As additional verified card profiles graduate, they each get
// their own peer package (e.g., a future jcop4/ or nxp/), and
// callers select the profile package they need rather than
// importing a card-neutral profile constructor with a card
// argument. That layout matches the existing securitydomain/profile/
// and piv/profile/ shape one level up.
package yubikey

// FactoryKeyVersion is the SCP03 KVN YubiKey 5.3+ ships with from
// the factory and the KVN a YubiKey returns to after
// securitydomain.Reset. Per Yubico tech manual, "SCP specifics".
//
// Always pair with scp03.DefaultKeys (the GP test keys, also the
// Yubico factory keys) and rotate the key set immediately on first
// connection. Using FactoryKeyVersion outside of that bootstrap
// window means the channel has no security: the keys are publicly
// known.
const FactoryKeyVersion byte = 0xFF
