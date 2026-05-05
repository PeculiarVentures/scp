# APDU trace archive

This directory holds wire-level APDU traces captured from real hardware sessions, archived as reference artifacts. Each trace is a complete record of one smoke-command run against a specific reader: every command sent, every response received, with timing.

## What these are for

Three uses, in roughly the order we reach for them:

1. **Reference for debugging.** When SCP11a or a bootstrap flow breaks on a card or firmware we haven't seen before, diff the new trace against the matching archived trace to localize the failure to an exchange. "We get a different SW on exchange 7" beats "it doesn't work" by a wide margin.

2. **Documentation source.** The GlobalPlatform Card Specification is dense; a real wire trace is concrete. When someone asks "how does SCP11a actually work," pointing them at a captured session walks faster than the spec.

3. **Customer onboarding and product demos.** When pitching GoodKey, ForgeIQ, or any product that depends on SCP11a working correctly against silicon, "here is a complete session captured byte-by-byte against retail hardware" is more credible than a spec citation. These traces are publishable.

## Trace schema

Traces are emitted by the `--apdu-trace <path>` flag on most `scpctl smoke` commands. The format is JSON with this shape:

```json
{
  "schema": "scp-trace/v1",
  "captured_at": "<ISO 8601 UTC timestamp>",
  "profile": "<smoke command name>",
  "reader": "<PC/SC reader name>",
  "notes": "<free-form context>",
  "determinism": {},
  "exchanges": [
    {
      "i": 0,
      "kind": "Transmit",
      "cla": "00", "ins": "a4", "p1": "04", "p2": "00",
      "command_hex": "00a4040008a00000015100000000",
      "response_hex": "6f17...9000",
      "sw": "9000",
      "duration_ns": 1131166,
      "aid_name": "GP ISD (Issuer Security Domain)"
    }
  ]
}
```

Fields:

- `schema` — version tag. Bump if the wire format changes incompatibly.
- `profile` — which smoke command produced the trace; pairs with `reader` to identify the exact run.
- `notes` — context the operator captured this for (a bug being chased, a release validation, etc.).
- `determinism` — reserved for flags that pin host-side randomness (host challenges, ephemeral keys) when reproducing a session is the goal. Empty in non-deterministic captures.
- `exchanges[].command_hex` / `response_hex` — full APDU bytes including any 61xx GET RESPONSE chaining. Status word at the end of `response_hex` is also surfaced as `sw`.
- `exchanges[].aid_name` — populated when `command_hex` decodes as a SELECT and the AID matches a known applet.

## Privacy and what's safe to share

These traces contain card-specific identifiers — Yubico SD attestation cert serial numbers, the card's per-instance SD public key, ephemeral OCE keys, and so on. They do NOT contain SCP03 or SCP11 session keys (those are derived host-side and never put on the wire), nor PIV PINs (we don't capture VERIFY PIN flows here), nor any persistent OCE private key material.

A captured trace pins the YubiKey serial number indirectly via the SD attestation cert serial. If that's a concern for the specific card you traced (e.g. a customer's production card), redact `command_hex` / `response_hex` for the SD attestation chain retrieval exchanges before sharing externally. For the test cards in this archive, no redaction is needed — they're lab cards reset many times in this session, with no production data.

OCE leaf certs sent on the wire are visible in plaintext within the PSO exchanges. The CN strings used in scpctl's smoke fixtures (`scpctl known-good OCE Root` / `scpctl known-good OCE Leaf`) intentionally announce themselves as test material.

## Capturing new traces

```bash
scpctl smoke <subcommand> ... --apdu-trace /tmp/<descriptive-name>.json
```

Any smoke command that touches the card supports `--apdu-trace`. The flag is non-destructive: it observes APDUs as they're sent and writes the JSON file at command exit. It does not change wire behavior or timing in a meaningful way (capture overhead is sub-microsecond per APDU on a modern Mac).

Add archived traces to this directory with a filename of the form:

```
<command>-<card>-<firmware>.json
```

For example: `scp11a-sd-read-yubikey-5.7.4.json`. If the same command was captured against multiple firmwares or in multiple states, append a state qualifier: `bootstrap-scp11a-yubikey-5.7.4-pristine.json`.

Each archived trace gets a one-paragraph entry in the catalog below.

## Catalog

### scp11a-sd-read-yubikey-5.7.4.json

A complete SCP11a session against a freshly-bootstrapped retail YubiKey 5.7.4. Captured immediately after `bootstrap-scp11a` on the same card, with the OCE chain and CA SKI registered at KID=0x10/KVN=0x03 and the SCP11a SD key generated on-card at KID=0x11/KVN=0x01.

Both halves of mutual authentication are visible in the wire:

- **Card-to-OCE trust** at exchanges 3–7: the card returns its SD attestation chain — sub-CA "YubiKey SD Attestation B 1" issued by "Yubico SD Attestation B 1," then leaf "YubiKey SD Attestation 11:01" issued by the sub-CA. The chain comes back over five exchanges via the card's 61xx GET RESPONSE chaining.

- **OCE-to-card trust** at exchanges 8–9: the host sends its OCE leaf + root to the card via PSO 0x90/0x10/0x2A, split across two transport chunks (255 + 183 bytes) with CLA chaining bits 0x90 / 0x80. The card validates against the OCE CA pubkey + SKI registered during bootstrap.

- **Mutual ECKA** at exchange 10: INTERNAL AUTHENTICATE (INS=0x82) with P2=0x11 selecting the SCP11a SD key. Carries an A6 control ref (KID=0x11, KVN=0x01) and a 0x5F49 OCE ephemeral pubkey (65 bytes uncompressed P-256). Card responds with its own ephemeral SD pubkey.

- **Confirmation** at exchange 11: GET DATA tag 0xE0 with CLA=0x84 (secure messaging set). Encrypted + R-MAC'd. Successful unwrap on the host means the session keys derived on both sides agree, which is the binding proof that both parties were authentic — a forged peer at either end would have produced different session keys and this command would have failed with a MAC error.

This is the canonical reference for how SCP11a mutual authentication actually works against the YubiKey, byte by byte.
