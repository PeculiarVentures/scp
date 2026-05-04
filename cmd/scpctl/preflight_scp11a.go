package main

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/scp/securitydomain"
	"github.com/PeculiarVentures/scp/transport"
)

// preflightSCP11aSDKey checks whether the card has the requested
// SCP11a SD key (sdKID, sdKVN) installed. The check uses an
// unauthenticated Security Domain session to read the Key
// Information Template; KIT does not require authentication on any
// card the SCP library targets.
//
// Return value:
//
//   - true  → emit the report as-is and exit the smoke (the report
//             carries a SKIP that names the missing reference).
//   - false → preflight is satisfied, or it was inconclusive in a
//             way that should not block the smoke. The caller
//             continues to OpenSCP11.
//
// Inconclusive cases (KIT fetch fails for transport or card-status
// reasons, e.g. a card that refuses unauthenticated KIT) downgrade
// to a SKIP-with-warning rather than a hard fail. We never fail the
// smoke on a preflight error alone — the actual SCP11 open below is
// the source of truth for whether the card can or cannot complete
// the handshake.
func preflightSCP11aSDKey(ctx context.Context, t transport.Transport, sdKID, sdKVN byte, report *Report) bool {
	sd, err := securitydomain.OpenUnauthenticated(ctx, t)
	if err != nil {
		report.Skip("SCP11a SD key preflight",
			fmt.Sprintf("could not open unauthenticated SD: %v; proceeding to open anyway", err))
		return false
	}
	defer sd.Close()

	keys, err := sd.GetKeyInformation(ctx)
	if err != nil {
		// Some cards refuse GET DATA [Key Information] without
		// authentication. Leave preflight inconclusive and let the
		// SCP11 open path surface the real result.
		report.Skip("SCP11a SD key preflight",
			fmt.Sprintf("GetKeyInformation: %v; proceeding to open anyway", err))
		return false
	}

	// Match policy:
	//
	//   - sdKVN == 0x00: spec literal for "any version" — match on
	//     KID alone. The open below carries the literal 0x00 to the
	//     card; we just need to confirm the KID exists somewhere.
	//   - sdKVN != 0x00: exact (KID, KVN) match.
	for _, k := range keys {
		if k.Reference.ID != sdKID {
			continue
		}
		if sdKVN == 0x00 || k.Reference.Version == sdKVN {
			report.Pass("SCP11a SD key preflight",
				fmt.Sprintf("found %s on card", k.Reference))
			return false
		}
	}

	// Not present. Emit a SKIP that names exactly which reference
	// is missing and lists what the card actually has, so the
	// operator can match against their provisioning state without
	// reading raw bytes.
	listed := make([]string, 0, len(keys))
	for _, k := range keys {
		listed = append(listed, k.Reference.String())
	}
	report.Skip("SCP11a SD key preflight",
		fmt.Sprintf("requested SD key KID=0x%02X KVN=0x%02X not installed; "+
			"card has: %v. Install it with: "+
			"`scpctl smoke bootstrap-scp11a-sd --reader \"...\" --out /tmp/sd-pub.pem --confirm-write` "+
			"(uses Yubico on-card keygen by default; pass --mode=import to PUT KEY a host-supplied keypair).",
			sdKID, sdKVN, listed))
	return true
}
