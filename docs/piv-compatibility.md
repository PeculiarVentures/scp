# PIV hardware compatibility

Tracks which PIV operations have been exercised end to end against which cards. The matrix is the source of truth for the README's assurance tier claims about cross-card coverage.

## Status legend

- **verified** — exercised against the listed hardware and confirmed working. Test artifacts in CI mock suite plus at least one human-driven hardware run logged in commit history.
- **spec** — protocol-implemented and refused by no profile rule, but not yet hardware-verified end to end. The library's wire bytes are correct by code review.
- **n/a** — not applicable to this card class (the card class doesn't claim the capability).
- **—** — not yet attempted.

## Matrix

| Card / Profile | SELECT | PIN ops | Generate | Import | Put cert | Reset | Attest | SCP11b PIV |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| YubiKey 5.7.2+ | verified | verified | verified | verified | verified | verified | verified | verified |
| YubiKey pre-5.7 | verified | verified | verified | verified | verified | verified | verified | n/a |
| Standard PIV (generic) | spec | spec | spec | n/a | spec | n/a | n/a | — |
| Unknown card | probe only | — | — | — | — | — | — | — |

## What `verified` means for the YubiKey rows

The YubiKey rows are verified against retail YubiKey 5 series tokens via `cmd/scpctl smoke ...` runs. The smoke suite (`scpctl smoke test`) covers SELECT, PIN verify, the SCP03/11b/11a SD reads, and the SCP11b-wrapped PIV verify. Generate, put cert, attest, and reset are exercised by `scpctl smoke piv-provision` and `scpctl smoke piv-reset` against the same hardware. SCP11b PIV requires firmware 5.7+; older firmware shows up as `n/a`, not as a regression.

## What `spec` means for the Standard PIV row

The library emits the SP 800-73-4 instruction subset for Standard PIV operations (SELECT, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERATE ASYMMETRIC KEY PAIR, GENERAL AUTHENTICATE, PUT DATA, GET DATA). The host-side capability gate refuses YubiKey-proprietary instructions under the Standard PIV profile, so a Standard PIV card cannot be issued an INS byte it does not understand.

What is **not** yet validated:

- Whether a specific Standard PIV card accepts the exact TLV shape the library builds for GENERATE KEY, PUT DATA (certificate object), GENERAL AUTHENTICATE (mutual auth), or RESET RETRY COUNTER.
- Whether the card returns `63Cx` or the bare `63xx` form for wrong-PIN responses (the library accepts both).
- Whether the card's factory management-key algorithm matches the SP 800-78-4 default (3DES) or has been pre-rotated by the issuer.

To promote `StandardPIV` from `spec` to `verified`, drive a non-YubiKey PIV card through:

1. `scpctl piv info` — confirms SELECT and probe fall through to Standard PIV (the `profile` field in the report should read `standard-piv`).
2. `scpctl piv key generate --slot 9a --confirm-write --raw-local-ok` followed by `scpctl piv cert put --slot 9a --cert <pem> --expected-pubkey <pem> --confirm-write --raw-local-ok` — confirms generate, put cert, and the cert-to-public-key binding check work end to end. The active profile is selected by the probe, not by a CLI flag.
3. PIN verify and PUK unblock paths via `scpctl piv pin verify`, `scpctl piv pin change`, and `scpctl piv pin unblock`.
4. RESET RETRY COUNTER for both PIN and PUK (exercised through `scpctl piv pin unblock` and the equivalent PUK flow).

Log the run in commit history and update this file's matrix to `verified`.

## What "Unknown card" means

A card that responds to SELECT AID PIV but does not return a YubiKey GET VERSION response, and is not on the explicit `verified` or `spec` list. The library treats it as `StandardPIVProfile` (the safe default) and the CLI surfaces this in `scpctl piv info` output. Operations work to the extent the card implements SP 800-73-4. Don't run destructive flows against an unknown card without first verifying behavior.

## Cards explicitly out of scope today

- Smart cards that don't expose a PIV applet (PKCS#15-only cards, FIDO-only tokens, etc).
- Cards that implement PIV-like but non-conforming applets (some legacy CAC/PIV-D cards). These should appear as "Unknown card" via probe and the operator should treat results with caution.

## Reporting compatibility issues

If a card class is not in this matrix and you've validated behavior, open a PR adding it with a description of the test methodology. If a card claims to be Standard PIV and fails an operation listed as `spec`, that's a real bug; file an issue with the SELECT response, the failing APDU, and the card's status-word response so the library or the matrix can be corrected.
