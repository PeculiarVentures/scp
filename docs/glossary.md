# Glossary

Definitions for the GlobalPlatform, ISO 7816, and PKI terms that appear throughout this library's docs and godoc. Package docs use this vocabulary directly rather than re-defining it inline. Where a term has both a brief operational gloss and a deeper specification definition, this glossary gives the operational gloss; for the spec-level definition see the cited GlobalPlatform or ISO document.

## A

**AID (Application Identifier).** A 5–16 byte identifier that names an applet on the card. The host activates an applet by sending `SELECT [AID]`; everything afterward goes to that applet until another SELECT runs. The Issuer Security Domain has a well-known AID (`A0 00 00 01 51 00 00 00`); see the [`aid`](../aid) package for a curated database of common AIDs.

**APDU (Application Protocol Data Unit).** The unit of communication between host and card, defined by ISO 7816-4. The host sends a *command APDU* (CAPDU: header, optional data, expected response length); the card returns a *response APDU* (RAPDU: optional data, two-byte status word). All SCP traffic moves as APDUs.

## B

**BER-TLV.** Tag-length-value encoding per ISO/IEC 8825-1 Basic Encoding Rules. GlobalPlatform uses BER-TLV for most structured payloads (CRD, certificate stores, control reference templates). The [`tlv`](../tlv) package handles the GP-relevant subset.

**BF21.** The BER-TLV tag (`0xBF 0x21`) the card returns from `GET DATA` to deliver its SCP11 certificate store. The chain inside is what the host validates against `trust.Policy`.

## C

**CAPDU.** Command APDU. See [APDU](#a).

**CCID.** USB device class for smart card readers (USB-IF spec 1.1). Most USB-attached YubiKeys and PIV cards present as CCID devices; PC/SC drivers wrap them.

**CLA.** First byte of an APDU header. Encodes the class of command (interindustry vs proprietary), whether the command carries secure messaging, the logical channel, and the chaining bit. ISO 7816-4 §5.4.1 defines the encoding; the [`channel`](../channel) package centralizes the parsing.

**C-MAC (Command MAC).** The integrity tag attached to commands sent over secure messaging. Computed by the host using the session MAC key (S-MAC) and verified by the card. Truncated to 8 bytes (S8 mode) or kept full at 16 bytes (S16 mode).

**C-ENC / C-DECRYPTION.** Command encryption: the host encrypts command data with the session encryption key (S-ENC) before sending. The card *decrypts* the same data, which is why the GlobalPlatform spec calls the negotiated bit "C-DECRYPTION" from the card's point of view; the host-side name is C-ENC.

**CRD (Card Recognition Data).** Structured data the card returns from `GET DATA` tag `0x66`, identifying the GP version, supported SCP profiles, and platform OIDs. CRD is *advisory*: it tells you what the card claims about itself before any authentication runs. It is not a trust signal. The [`cardrecognition`](../cardrecognition) package parses it.

## D

**DEK (Data Encryption Key).** A symmetric key the card uses to wrap key material when receiving `PUT KEY`. In SCP03 it is one of the three static keys (ENC, MAC, DEK); in SCP11 it is derived from the session and exposed only to the [`securitydomain`](../securitydomain) package, never to generic callers through the public `Session` interface.

## E

**ECDH.** Elliptic Curve Diffie-Hellman key agreement. SCP11 derives session keys from two parallel ECDHs: one between ephemeral keys (forward secrecy) and one between static keys (authentication). See [ECKA](#e) for the GlobalPlatform name.

**ECKA (Elliptic Curve Key Agreement).** GlobalPlatform's term for ECDH used inside SCP11 (Amendment F §5). Functionally identical to standard ECDH per BSI TR-03111.

**EKU (Extended Key Usage).** X.509 certificate extension constraining what the certified key may be used for. `trust.Policy.ExpectedEKUs` lets a caller refuse SCP11 cards whose certificate doesn't carry the expected EKU OIDs.

**Extended APDU.** ISO 7816-4 §5.1 framing that allows command data and expected response length up to 65535 bytes (instead of 255). Required for SCP11 OCE certificate upload because real X.509 OCE certs run 300–800 bytes. Reader and card both have to support it; modern USB CCID and NFC readers do, some constrained NFC paths and legacy contact readers do not.

## G

**GET DATA.** APDU command (`0x80 0xCA P1 P2`) that asks the card for a structured object identified by P1/P2. Heavily used: tag `0x66` for CRD, tag `BF21` for the SCP11 certificate store, tag `0x00E0` for key information.

**GP (GlobalPlatform).** The standards body that publishes the GP Card Specification and SCP amendments. Specifications cited by this library: GP Card Specification 2.3.1, Amendment D (SCP03) v1.2, Amendment F (SCP11) v1.4.

## H

**HostID / CardGroupID.** Optional SCP11 fields that bind a session to a specific host or group of cards via the AUTHENTICATE parameter bit and tag `0x84` TLV. The wire-side encoding is an [expansion target](../README.md#expansion-targets); today `Open` fails closed if either field is set.

## I

**INITIALIZE UPDATE.** First APDU of the SCP03 handshake. Carries the host challenge and asks the card for its challenge plus the derivation cryptogram. See the protocol-flow diagram in [`scp03/scp03.go`](../scp03/scp03.go).

**INTERNAL AUTHENTICATE.** APDU used in SCP11b and SCP11a/c handshakes to drive the ECDH key agreement and (for SCP11a/c) carry the receipt that authenticates the card.

**`Insecure*` flags.** Library-wide naming convention: any config field, function name, or escape hatch prefixed with `Insecure` disables a security default. These exist for tests, lab use, and migration scenarios; they should never be set in production code paths. Examples: `InsecureSkipCardAuthentication`, `InsecureAllowSCP11bWithoutReceipt`, `InsecureAllowPartialSecurityLevel`, `InsecureExportSessionKeysForTestOnly`.

**ISD (Issuer Security Domain).** The root [Security Domain](#s) on every GlobalPlatform card; AID `A0 00 00 01 51 00 00 00`. Holds the master key set and authorizes management of subordinate Security Domains.

**ISO 7816-4.** International standard for smart card commands. Defines APDU framing, CLA encoding, secure messaging bits, logical channels, and command chaining. The library targets the 2020 edition.

## K

**KDF (Key Derivation Function).** SCP03 uses NIST SP 800-108 KDF in counter mode with AES-CMAC as the PRF. SCP11 uses X9.63 KDF with SHA-256/384/512. Both derive session keys from a shared secret plus diversification context.

**Key set.** A bundle of keys on the card (typically ENC, MAC, DEK for SCP03, or an EC key pair plus optional CA certificate references for SCP11) identified by a [KVN](#k) and addressed by a [KID](#k) within the set. A card can hold multiple key sets at different KVNs; the host targets one in INITIALIZE UPDATE / INTERNAL AUTHENTICATE.

**KID (Key Identifier).** One byte; identifies which key within a [key set](#k) the card should use. Not the same as KVN.

**KVN (Key Version Number).** One byte; identifies which key set on the card the host is targeting. The factory key set on a YubiKey is KVN `0xFF`; rotated key sets typically use `0x01` and up. KVN `0x00` is "any version" in INITIALIZE UPDATE.

## L

**Logical channel.** ISO 7816-4 mechanism for multiplexing several applet sessions over a single card connection. Channels 0–3 in first-interindustry encoding (CLA bits 0–1); channels 4–19 in further-interindustry encoding (CLA bits 0–3 plus bit 6). The [`channel`](../channel) package decodes both.

## M

**MAC chain.** Sequence of MACs across an SCP03 session where each command's MAC input includes the previous response's MAC. Breaks under message reordering or loss, so transports have to deliver responses in order. The [remote APDU transport guide](./remote-apdu-transport.md) lists this as a transport requirement.

## N

**NIST P-256.** The elliptic curve (`secp256r1`) used by SCP11 in this library's verified profile. P-384 and P-521 are protocol-supported by Amendment F but currently expansion targets here.

## O

**OCE (Off-Card Entity).** The host side of an SCP session. In SCP03 the OCE holds the symmetric keys; in SCP11 the OCE holds an EC private key (and, for SCP11a/c, a certificate chain). The "off" is from the card's point of view.

## P

**PC/SC.** Personal Computer / Smart Card; cross-platform API for talking to smart card readers. Linux/macOS implementation is `pcsclite` plus the `pcscd` daemon; Windows ships `winscard.dll` natively. The [`transport/pcsc`](../transport/pcsc) package wraps it.

**PIV (Personal Identity Verification).** NIST SP 800-73-4 standard for credentials on smart cards. Defines slots, key types, PINs, and the applet's APDU surface. The [`piv`](../piv) package implements the host side.

**PSO (PERFORM SECURITY OPERATION).** APDU command (`0x80 0x2A P1 P2`) used in SCP11a and SCP11c handshakes to upload the OCE certificate to the card before the ECDH step. Each cert goes in one extended-length APDU.

## R

**RAPDU.** Response APDU. See [APDU](#a).

**R-MAC / R-ENC (Response MAC / Response ENC).** The response-direction analogues of [C-MAC and C-ENC](#c). Whether they're present in a session depends on the negotiated [security level](#s).

**Receipt.** Authentication tag in SCP11 that proves the card actually performed the ECDH (rather than replaying a pre-recorded handshake). Required by default for SCP11b in Amendment F v1.4 and modern YubiKey behavior; older v1.3 cards that omit it need `InsecureAllowSCP11bWithoutReceipt`.

## S

**S8 / S16.** SCP03 MAC truncation modes. S8 truncates each MAC to 8 bytes (the spec default and the YubiKey-verified profile); S16 keeps the full 16-byte AES-CMAC output. Both are protocol-supported here; S16 is currently an expansion target for hardware verification.

**SCP (Secure Channel Protocol).** GlobalPlatform's family of protocols for authenticated, encrypted host-card communication. This library implements SCP03 (Amendment D, symmetric) and SCP11 (Amendment F, asymmetric). SCP01 and SCP02 are deprecated; SCP04 is newer than SCP03 but rare in the field.

**SCP11a / SCP11b / SCP11c.** Three variants of SCP11. SCP11a is mutual auth (both sides present certificates). SCP11b is card-to-host only. SCP11c is mutual auth with support for pre-computed scripts that can be replayed against a group of cards. See the [README's SCP11 section](../README.md#scp11-usage) for the variant table.

**SD (Security Domain).** A logical container on a GP card holding a key set and authorizing card-content management. The [Issuer Security Domain](#i) is the root SD; cards can carry subordinate SDs with delegated authority. The [`securitydomain`](../securitydomain) package implements the typed management surface.

**SE (Secure Element).** Tamper-resistant hardware component executing isolated code and storing keys; smart cards, eSIMs, embedded SEs in phones, YubiKeys, and YubiHSMs are all SEs in different form factors. SCP is one way to talk to them.

**Secure Messaging.** GlobalPlatform's term for the wire-level wrapping that SCP applies to APDUs after the handshake completes. Implemented by the [`channel`](../channel) package; transparently driven by `Session.Transmit`.

**Security level.** SCP03 negotiates one of: C-MAC; C-DEC + C-MAC; C-MAC + R-MAC; C-DEC + C-MAC + R-MAC; or full (C-DEC + C-MAC + R-ENC + R-MAC). The `LevelFull` constant is the default and the recommended profile; partial security levels are gated behind `InsecureAllowPartialSecurityLevel`.

**SELECT.** APDU command (`00 A4 04 00 [AID]`) that activates an applet on the card. Every SCP session opens with a SELECT against the applet whose key set the handshake authenticates against.

**Session key.** Per-session keys derived during the handshake from the master/static keys plus host and card challenges (SCP03) or from the dual-ECDH shared secrets (SCP11). Three of them: S-ENC, S-MAC, S-RMAC. Not exposed through the public `scp.Session` interface.

**SKI (Subject Key Identifier).** X.509 extension carrying a hash of the subject public key. `trust.Policy.ExpectedSKI` lets a caller pin the SCP11 card identity to a specific SKI.

**SP 800-108 / SP 800-38B / SP 800-56A.** NIST publications: 800-108 defines the KDF used by SCP03; 800-38B defines AES-CMAC; 800-56A defines the EC key agreement primitive used by SCP11.

**Static key.** A key persistently stored on the card and in the host's key custody. SCP03 has three (ENC, MAC, DEK); SCP11 has the card's static EC key pair (`PK.SD.ECKA` / `SK.SD.ECKA`) and, for mutual-auth variants, the OCE's static EC key pair.

**Status word.** The two-byte trailer on every response APDU encoding success or failure. `9000` is success; `61xx` and `6Cxx` are continuation indications; `6982`, `6985`, `6A88`, `6A82`, `6A86` and others encode specific failure conditions. The [`piv`](../piv) package's `CardError` type and predicates parse the common ones.

## T

**TLV.** See [BER-TLV](#b).

## X

**X9.63 KDF.** ANSI X9.63 single-step key derivation function used by SCP11 to derive session keys from the ECDH shared secret. SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521.
