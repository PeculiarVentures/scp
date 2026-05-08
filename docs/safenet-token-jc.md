# SafeNet eToken / Token JC investigation notes

This document captures what we learned investigating the SafeNet Token JC family in May 2026, so the next person who plugs one of these in has the answers waiting instead of repeating the same searches.

In short, the card is discoverable and inventory-readable, but in its current state it refuses SCP03 establishment at INITIALIZE UPDATE. The rejection occurs before card cryptogram exchange, so key material is not the active gate. `scpctl probe` works fully against the Token JC, and the structured Card Capability decode added in #138 is byte-exact against gppro for the same response. Authentication is a separate question, layered: even with the right GP-layer keys (which aren't published anywhere we could find for this SKU), the card's current state would still refuse `INITIALIZE UPDATE` with SW=6982. The "What happens when we try to authenticate" section walks through both observed phases and what we know vs hypothesize about the transition between them.

## Card identification

The card under investigation:

```
ATR:        3BFF9600008131FE4380318065B0855956FB120FFE82900000
AID:        A000000018434D00 (Card Manager AID; GemPlus-registered RID per ISO/IEC 7816-5)
CPLC ICType: 7897
SCP advertised: SCP01 i=05/15, SCP02 i=05/15/45/55, SCP03 i=00/10 (AES-128/192/256)
KIT (KVN=0xFF, AES-128, factory-key indicator)
```

This corresponds to the Thales-shipped retail SKU sold under several names:

- SafeNet eToken 5110 CC (940 / 940B / 940C variants)
- SafeNet Token JC (the SAC-displayed name when the card is unprovisioned or locked)
- DigiCert Hardware Token (the same hardware, OEM-resold)

Underneath it is the Athena IDProtect platform, a Java Card OS shipped by Athena Smartcard Inc. on Atmel/Microchip secure microcontrollers. The platform is FIPS 140-2 Level 3 certified; the [non-proprietary Security Policy](https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp1883.pdf) (CMVP cert #1883) is the architectural reference for everything below.

## What probe validates

`scpctl gp probe` against this card is a clean PASS for everything the probe inventory covers:

- ISD selection (AID `A000000018434D00`)
- CPLC, IIN, CIN, KDD, SSC reads via GET DATA
- Card Capability Information (tag 0x67) read and structured parse
- Card Recognition Data inspection
- Profile classification (categorized as `standard-sd` per the post-#130 classifier)
- KIT advertisement (one entry, KVN=0xFF, AES-128)

The structured Card Capability decode added in #138 is byte-exact against gppro v25.10.20 for SCP entries (versions and i-parameter values) and hash algorithm names. Privilege bitmaps and cipher suite bitmaps surface as raw hex pending GP §H.4 cross-reference (see the package doc on `gp/cardcaps` for why).

What probe does NOT validate against this card, because it's behind authentication:

- Card registry (KLOC, KLCC reads) requires an authenticated session
- INSTALL / LOAD / DELETE applet management requires authentication
- PUT KEY for SCP03 key set rotation requires authentication
- STORE DATA for personalization data requires authentication

These flows work in the library against YubiKey 5.x and our mock infrastructure. Validation against this specific Athena IDProtect platform is a future-fixture item.

## What happens when we try to authenticate

There are two distinct failure modes we've observed against this card, and they reveal something important about its state. The library now distinguishes them via separate error types (`InitializeUpdateError` vs `CryptogramMismatchError`, both wrapping `ErrAuthFailed`); the section below explains why both matter.

### Phase 1: cryptogram mismatch (initial state)

The first session against this card with the GP test key (`404142434445464748494A4B4C4D4E4F`) got past `INITIALIZE UPDATE`. The card returned a 32-byte response including a card challenge and card cryptogram, the host computed its own cryptogram from the (wrong) keys, and the values didn't match. gppro reported:

```
[WARN] GPSession - Pseudorandom card challenge does not match
                   expected: 6FF816013FF37079 vs 05033DA41B31F39E
Failed to open secure channel: Card cryptogram invalid!
Received: 76532D72CF9DE05F
Expected: B2F392D2CFB9A459
!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!
```

This is the cryptogram-mismatch path documented in #137. Bytes are surfaced, brick warning is explicit, the right error type recovers via `errors.As`.

### Phase 2: 6982 at INITIALIZE UPDATE (current state)

A subsequent investigation could not get past `INITIALIZE UPDATE`. The card returns `SW=6982` (Security status not satisfied) before any cryptogram exchange. Tested against:

- `--scp03-key 404142434445464748494A4B4C4D4E4F` (GP test key): 6982
- `--scp03-key 47454D5850524553534F53414D504C45` (`GEMXPRESSOSAMPLE`): 6982
- gppro with `--key-kdf visa2 --key-ver 255` and various keys: 6982
- `INITIALIZE UPDATE` with P2=00, P2=01, P2=02 (in case the card required an explicit KID in P2): 6982 in all three cases

Keys are not the gate. The card is refusing SCP03 establishment at the policy level rather than at the key-verification level.

### What changed between phases

This is a hypothesis, not a confirmed finding. We don't have a lifecycle/status read of the Card Manager between the two phases, so we can't prove what state the SD was in. What we can say is that the card moved from "responds to INITIALIZE UPDATE with a 32-byte challenge/cryptogram payload" to "rejects INITIALIZE UPDATE with SW=6982" between sessions, and that's a state change consistent with the Card Manager transitioning to a more restrictive state.

Several causes are consistent with the observed transition, listed roughly in order of plausibility:

- **Failed-auth state change.** The Phase 1 cryptogram-mismatch attempt may have transitioned the SD into a locked or blocking lifecycle state. Per GP Card Spec §11.5, SCP establishment can be refused with 6982 when the SD is in a state that doesn't permit host-initiated authentication, and per the FIPS Security Policy §5.7.2 this card's authentication mechanism includes "a counter of failed authentication and a blocking mechanism." A single failed cryptogram check may not flip the SD into the blocking state on most cards; whether this firmware does so on the first failure is unconfirmed.
- **Vendor-mediated precondition.** The card may have always required a vendor-specific precondition before host-initiated SCP03 is permitted, and that precondition was satisfied in Phase 1 (perhaps as a side effect of running scpctl probe earlier in the same session) but not in Phase 2. SafeNet Authentication Client mediates a token-level handshake before opening Card Manager-level operations on cards in the field, and that handshake may set transient state the card requires before accepting `INITIALIZE UPDATE`. Without source access to SAC's protocol, this stays a possibility we can't disprove.
- **Card lifecycle progression independent of failed auth.** The card may have been in `OP_READY` (or a similar state permitting open SCP03 establishment) during Phase 1 and progressed to `INITIALIZED` or `SECURED` state by Phase 2 through some unrelated event. Less plausible without a triggering action, but not ruled out.

What we'd need to disambiguate: a `GET STATUS` read of the SD between attempts (would tell us the Card Manager lifecycle state), or a successful Phase-2-style trace from a different card in the same family (would tell us whether the 6982 behavior is per-card-state or platform-wide). Neither was available in this investigation.

### Diagnostic surface in the library

After #140 and #142, both failure modes get distinct error types in the library, with attempt context preserved on the error:

```go
sess, err := scp03.Open(ctx, transport, cfg)
switch {
case errors.As(err, &iue):
    // *InitializeUpdateError. Phase-2 Token JC behavior. iue.SW()
    // returns the status word; iue.Diagnostic names the GP-spec
    // interpretation; iue.RetryDifferentKeys is false for
    // state/policy SWs and true for SWs that name wrong key
    // material (6A88, 63CX). iue.KeyVersion, iue.KeyIdentifier,
    // and iue.AID preserve the attempt context (P1, P2, and
    // SELECTed AID respectively). Don't cycle keys when
    // RetryDifferentKeys is false.
case errors.As(err, &cm):
    // *CryptogramMismatchError. Phase-1 Token JC behavior. The
    // bytes are recoverable via cm.Expected and cm.Received for
    // diagnostic comparison.
case errors.Is(err, scp03.ErrAuthFailed):
    // Some other auth failure mode.
}
```

The Token JC's current state surfaces as `*InitializeUpdateError` with `SW=6982` and `RetryDifferentKeys=false`. The rendered error names the SW, the attempt context, and the operator-facing interpretation: "Security status not satisfied. SCP03 establishment was refused before cryptographic verification, so key material was not tested. Consistent with locked/vendor-managed SD, missing vendor precondition, lifecycle restriction, or policy-blocked INITIALIZE UPDATE; lifecycle/status read needed to confirm which."

### About the failed-auth counter

Per the FIPS Security Policy §5.7.2, the platform's default threshold for the failed-authentication counter is **80** (not the more common GP default of 10). Per the same section, the counter "is decremented prior to any attempt to authenticate and is only reset to its threshold (maximum value) upon successful authentication." Whether SW=6982 at INITIALIZE UPDATE counts as "an attempt to authenticate" for counter-decrement purposes is firmware-specific and unconfirmed for this card. Operators should treat the counter as potentially decrementing on each attempt and budget accordingly. From the current state, even with sourced keys, the card likely won't open until something resets the SD lifecycle. A SAC-mediated reinitialization is the conventional path that puts the SD back into a state where `INITIALIZE UPDATE` succeeds, but we haven't confirmed this against this specific card.

## The keys question, clearly

A common confusion when researching this card is the relationship between two separate sets of credentials. They are stored in different security layers and they don't help each other.

### User-level credentials (PKCS#11 layer)

These are what DigiCert, GlobalSign, and SafeNet's own documentation talk about:

- **Administrator Password.** Default: forty-eight ASCII zeros (`30 30 30 30 ...` × 24, or 48 characters of `'0'`). This is a PKCS#11 Security Officer PIN managed by SafeNet Authentication Client. Five wrong tries and the card permanently locks (different counter from the ISD's 80).
- **Token Password.** A PKCS#11 User PIN. Default varies; some OEMs ship a per-card random value, some ship a fixed default. Used to access the certificate store on the card.

These are SafeNet Authentication Client credentials. They authenticate SAC's own applet (the eToken Applet Suite) for high-level operations like initializing a token store, generating an RSA key pair, or installing a code-signing certificate. They are **not** the GlobalPlatform SCP03 keys.

### GP-layer keys (Card Manager layer)

These are the AES-128/192/256 keys we'd need for INITIALIZE UPDATE / EXTERNAL AUTHENTICATE:

- **ISD-KENC.** AES-128/192/256 key the Card Manager uses to derive the session encryption key per GP §6.2.2 / Amendment D §4.1.5.
- **ISD-KMAC.** AES-128/192/256 key the Card Manager uses to derive the session MAC and response-MAC keys.
- **ISD-KDEK.** AES-128/192/256 data decryption key the Card Manager uses for PUT KEY operations.

Per the FIPS Security Policy §10.2, these keys are set by SAC during initial card configuration. They live in EEPROM, encrypted under an OS-level master key (OS-MKEK) that itself is derived on first power-on. There is no documented public default.

The Administrator Password (forty-eight zeros) is a SAC concept and has no role in Card Manager authentication. Re-running INITIALIZE UPDATE with `00 00 00 ... 00` AES keys would consume an attempt off the 80-counter and not succeed. This is a real failure mode that's worth being explicit about, because the search-engine output is heavily dominated by the user-level password and it's easy to assume "default = 48 zeros" for the GP layer too.

### Where the GP keys actually live

Three places in practice:

1. **Whoever personalized the card.** For a DigiCert-shipped code-signing token, that's DigiCert's CA infrastructure. For a GlobalSign-shipped token, that's GlobalSign's. They typically don't share the GP-layer keys with end users; the user only ever sees the SAC-layer Administrator and Token passwords.
2. **A Thales NDA developer kit.** Thales sells an Athena IDProtect developer kit with documented test keys for application development. We didn't pursue this; cost and lead time make it not a small effort.
3. **An unprovisioned developer SKU.** Some retailers (less commonly than the OEM-resold tokens) ship cards with documented default keys for development use. We did not find one for the Token JC SKU specifically.

For an open-ended hardware-validation effort, route 2 is the realistic path. For one-off interop testing, route 1 (asking whoever owns the card to share keys, under whatever access agreement is appropriate) is the only one that doesn't cost money and lead time.

## Reference comparison with gppro

gppro v25.10.20 is the closest reference implementation we have for this card. Notable agreements and disagreements:

| Behavior | gppro | This library | Resolution |
|---|---|---|---|
| Card Capabilities decode (SCP versions, hash algorithms) | matches | matches (#138) | byte-exact for the parts both implement |
| Doubled-67 wrapper handling | strips silently with warning | strips silently | both accept the firmware quirk |
| AES-192 label for 0x02 key-size bit | "AES-196" (typo) | "AES-192" | ours is right per AES standard |
| CPLC date resolution | produces future dates from 1-digit-year encodings | uses decade heuristic | ours is closer to reality (gppro resolves Y=7 D=090 to 2027 instead of 2017) |
| Cryptogram mismatch diagnostic | shows expected vs received with brick warning | matches (#137) | log-comparable with gppro now |
| INITIALIZE UPDATE rejection diagnostic | reports SW with `[WARN]` markers | matches (#140) with `InitializeUpdateError` carrying SW + interpretation + retry flag | post-#140 the library distinguishes 6982 (state-block) from 6A88 (missing KVN) from 63CX (counter) |
| Pseudorandom card challenge prediction (SCP03 i=0x10) | computed and warned on mismatch | not implemented | future work, see Amendment D §6.2.3.1 |

## Captured fixtures

For a future investigator who wants to confirm against the same bytes:

- `gp/cplc/cplc_test.go` has two SafeNet eToken Fusion CPLC fixtures (`safeNetEtokenFusionCPLCHex`, `safeNetEtokenFusion2CPLCHex`) covering two distinct cards from the family, plus the captured CPLC for the Token JC under test here is in the test that pins the structured-decode behavior against the doubled-67 wrapper.
- `gp/cardcaps/cardcaps_test.go` has the full 64-byte Token JC Card Capabilities response (`safeNetTokenJCCardCapabilitiesHex`) and asserts the structural decode against gppro's text decode of the same bytes.

These are sufficient to extend the parser to Tier 2 (named privileges and named ciphers) the moment somebody reads GP §H.4 carefully and writes a bit-to-name table.

## Regression fixture status

Treat this card as a regression fixture for the unauthenticated probe path:

| Path | Expected outcome |
|---|---|
| `gp probe --discover-sd` | PASS, classifies as `standard-sd`, surfaces structured Card Capabilities |
| `sd keys list --sd-aid A000000018434D00` | PASS, returns three KVN=0xFF AES-128 entries (KID 01/02/03) |
| `scp03.Open` with any key set | FAIL with `*scp03.InitializeUpdateError`, SW=6982, RetryDifferentKeys=false |

The third row is what the post-#140 library produces deterministically. If a future change made `scp03.Open` against this card produce a different shape (stop returning `InitializeUpdateError`, or change the SW classification, or recommend retries), that would be a regression worth catching.

## What would unlock further validation

In rough order of effort:

1. **Reset the card's SD state via SAC.** SafeNet Authentication Client's reinitialize flow may put the Card Manager back into a state where host-initiated SCP03 is permitted. This is the prerequisite to any further investigation against this specific card; even the right GP-layer keys probably won't open it from the current 6982 state.
2. **Source the GP-layer keys for one card from this family in a known-good state.** With keys plus an unlocked SD, every authenticated probe path lights up against this platform. A factory-fresh developer SKU is the cleanest path; an OEM-personalized card with the keys delegated by the personalizer would also work.
3. **Implement pseudorandom card challenge prediction per GP Amendment D §6.2.3.1.** This is a diagnostic improvement (not security-required) but it's the piece gppro has and we don't, and it would warn on a key mismatch one exchange earlier than the cryptogram check does. Particularly useful if we eventually do test sourced keys against an unlocked card from this family.
4. **Tier 2 cardcaps decode** (named privileges and named ciphers) once GP §H.4 is cross-referenced directly.
5. **Vendor key diversification helpers** if Thales documents their KMC-based scheme. We have `DiversifySP800108v1`; whether Thales uses something compatible or something proprietary isn't currently known.

None of these are blockers for the work that already lands at #137 / #138 / #139 / #140 plus the probe path.
