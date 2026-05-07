# SafeNet eToken / Token JC investigation notes

This document captures what we learned investigating the SafeNet Token JC family in May 2026, so the next person who plugs one of these in has the answers waiting instead of repeating the same searches.

In short, `scpctl probe` works fully against the Token JC, and the structured Card Capability decode added in #138 is byte-exact against gppro for the same response. Authenticating to the card's Issuer Security Domain (INITIALIZE UPDATE / EXTERNAL AUTHENTICATE) is a separate question, gated on GP-layer keys that aren't published anywhere we could find. That part of the inventory stays unvalidated until somebody supplies keys.

## Card identification

The card under investigation:

```
ATR:        3BFF9600008131FE4380318065B0855956FB120FFE82900000
AID:        A000000018434D00 (Gemalto Card Manager)
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

## Why we can't authenticate

The card uses GP SCP03 with AES-128/192/256 keys. Running INITIALIZE UPDATE / EXTERNAL AUTHENTICATE with the wrong keys produces the cryptogram-mismatch error path documented in #137 (bytes surfaced, brick warning explicit). We tried once with the GP test keys (`404142434445464748494A4B4C4D4E4F`) against this card and gppro reported:

```
[WARN] GPSession - Pseudorandom card challenge does not match
                   expected: 6FF816013FF37079 vs 05033DA41B31F39E
Failed to open secure channel: Card cryptogram invalid!
Received: 76532D72CF9DE05F
Expected: B2F392D2CFB9A459
!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!
```

The card's failed-authentication counter is the protective mechanism. Per the FIPS Security Policy §5.7.2, the default threshold on this platform is **80** (not the more common GP default of 10). One attempt has been used. 79 remain before the ISD locks permanently.

That gives us slack for a future attempt with sourced keys, but no point in burning more attempts blind.

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
| Pseudorandom card challenge prediction (SCP03 i=0x10) | computed and warned on mismatch | not implemented | future work, see Amendment D §6.2.3.1 |

## Captured fixtures

For a future investigator who wants to confirm against the same bytes:

- `gp/cplc/cplc_test.go` has two SafeNet eToken Fusion CPLC fixtures (`safeNetEtokenFusionCPLCHex`, `safeNetEtokenFusion2CPLCHex`) covering two distinct cards from the family, plus the captured CPLC for the Token JC under test here is in the test that pins the structured-decode behavior against the doubled-67 wrapper.
- `gp/cardcaps/cardcaps_test.go` has the full 64-byte Token JC Card Capabilities response (`safeNetTokenJCCardCapabilitiesHex`) and asserts the structural decode against gppro's text decode of the same bytes.

These are sufficient to extend the parser to Tier 2 (named privileges and named ciphers) the moment somebody reads GP §H.4 carefully and writes a bit-to-name table.

## What would unlock further validation

In rough order of effort:

1. Source the GP-layer keys for one card from this family. With keys, every authenticated probe path lights up against this platform.
2. Implement pseudorandom card challenge prediction per GP Amendment D §6.2.3.1. This is a diagnostic improvement (not security-required) but it's the piece gppro has and we don't, and it would warn on a key mismatch one exchange earlier than the cryptogram check does.
3. Tier 2 cardcaps decode (named privileges and named ciphers) once GP §H.4 is cross-referenced directly.
4. Vendor key diversification helpers if Thales documents their KMC-based scheme. We have `DiversifySP800108v1`; whether Thales uses something compatible or something proprietary isn't currently known.

None of these are blockers for #137 / #138 / the probe-level work that already lands.
