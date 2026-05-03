# External test vectors and provenance

This directory documents the upstream conformance material this library
is verified against. The goal is to avoid validating the implementation
only against its own mock card: mock cards are useful for state-machine
coverage, but independent transcripts are needed for protocol
compatibility and cryptographic regressions.

For each upstream source we record the repository, the specific commit
the vectors were verified against, the license, the upstream file
paths, what the corresponding test in this library does with those
bytes, and any porting notes.

If you regenerate or update vectors, update both the SHA in the
"Verified at" row and the date. Permalink URLs in this document use
the recorded SHA so anyone reading later can fetch the exact bytes
that were imported.

---

## 1. Samsung OpenSCP-Java

**Source repository:** [`Samsung/OpenSCP-Java`](https://github.com/Samsung/OpenSCP-Java)
**License:** Apache-2.0
**Default branch:** `main`
**Verified at:** `b9876fc36a5b18fb90ce03d0894f39edb08a905b` (committed 2025-07-31, verified 2026-05-03)

Why this source: Samsung's OpenSCP-Java team [explicitly notes][samsung-readme] that publishable SCP test vectors are scarce, and they manually
recalculated SCP03 reference vectors covering AES-128/192/256 across S8
and S16 modes plus SCP11a P-256/AES-128/S8 transcripts. That makes this
the most thorough public corpus for protocol-level conformance.

[samsung-readme]: https://github.com/Samsung/OpenSCP-Java#test-vectors

### Imported files

All paths below are at SHA `b9876fc36a5b18fb90ce03d0894f39edb08a905b`.

| Upstream file | Used by | Coverage |
|---|---|---|
| [`src/test/java/com/samsung/openscp/Scp03Tests.java`][s1] | `scp03/transcript_vectors_test.go` | SCP03 INITIALIZE UPDATE / EXTERNAL AUTHENTICATE driver test |
| [`src/test/java/com/samsung/openscp/testdata/InputTestData.java`][s2] | `scp03/transcript_vectors_test.go` | Static keys, host challenges, card challenges |
| [`src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S8ModeEmulation.java`][s3] | `scp03/transcript_vectors_test.go` (`TestSCP03_SamsungOpenSCP_AES128_S8_FullTranscript`) | Byte-exact APDU pairs for AES-128 / S8 mode |
| [`src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S16ModeEmulation.java`][s4] | `scp03/transcript_vectors_test.go` (`TestSCP03_SamsungOpenSCP_AES128_S16_FullTranscript`) | Byte-exact APDU pairs for AES-128 / S16 mode |
| `src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes192S8ModeEmulation.java` | `scp03/transcript_vectors_test.go` (`TestSCP03_SamsungOpenSCP_AES192_S8_FullTranscript`) | AES-192 / S8 |
| `src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes256S8ModeEmulation.java` | `scp03/transcript_vectors_test.go` (`TestSCP03_SamsungOpenSCP_AES256_S8_FullTranscript`) | AES-256 / S8 |
| [`src/test/java/com/samsung/openscp/Scp11Tests.java`][s5] | `session/samsung_scp11a_transcript_test.go` | SCP11a driver |
| [`src/test/java/com/samsung/openscp/testdata/SmartCardScp11aP256Aes128S8ModeEmulation.java`][s6] | `session/samsung_scp11a_transcript_test.go` (`TestSCP11a_SamsungTranscript_ByteExact`) | Byte-exact SCP11a P-256 / AES-128 / S8 |

[s1]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/Scp03Tests.java
[s2]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/testdata/InputTestData.java
[s3]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S8ModeEmulation.java
[s4]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S16ModeEmulation.java
[s5]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/Scp11Tests.java
[s6]: https://github.com/Samsung/OpenSCP-Java/blob/b9876fc36a5b18fb90ce03d0894f39edb08a905b/src/test/java/com/samsung/openscp/testdata/SmartCardScp11aP256Aes128S8ModeEmulation.java

### Porting notes

* **Bytes preserved verbatim.** CAPDUs and RAPDUs are extracted from
  the Samsung Java fixtures byte-for-byte and embedded as Go `[]byte`
  literals (decoded from the upstream hex strings). They are
  known-answer inputs, not values for the local mock card to derive.
* **Static keys, host challenges, card challenges** are likewise
  copied verbatim from `InputTestData.java` and the per-mode
  `*Emulation.java` files.
* **PSO certificate upload framing intentionally differs.** Samsung's
  Java reference uses GP CLA-chaining (`0x90` / `0x80`) to chunk a
  single OCE certificate across multiple APDUs. This library follows
  Yubico's reference and sends one extended-length APDU per
  certificate. Both are spec-valid; only the framing differs. The
  Samsung SCP11a test asserts byte-exact match on the GET DATA chain,
  the MUTUAL_AUTHENTICATE APDU, and the wrapped LIST_PACKAGES — not
  on the PSO frames, since those legitimately diverge.
* **OCE ephemeral key pinning.** SCP11a's MUTUAL_AUTHENTICATE depends
  on the OCE's ephemeral key. The byte-exact assertion uses
  `InsecureTestOnlyEphemeralKey` to pin Samsung's published
  `eSK.OCE.ECKA.P256` value; without that pin the APDU is
  non-deterministic and a byte-exact comparison would be meaningless.

---

## 2. GlobalPlatformPro

**Source repository:** [`martinpaljak/GlobalPlatformPro`](https://github.com/martinpaljak/GlobalPlatformPro)
**License:** LGPL-3.0-or-later
**Default branch:** `next`
**Verified at:** `6d6c154dd55b3dc5406d980345d44c8e4ed01a72` (committed 2026-05-01, verified 2026-05-03)

Why this source: real-card APDU dumps from a JCOP4 card under a mature,
widely-used GlobalPlatform implementation. Cross-checks the library
against actual card behavior, not just another implementation's
expected behavior.

### Imported files

All paths below are at SHA `6d6c154dd55b3dc5406d980345d44c8e4ed01a72`.

| Upstream file | Used by | Coverage |
|---|---|---|
| [`nextgen/src/test/resources/scp03-init-update-jcop4.dump`][g1] | `scp03/transcript_vectors_test.go` (`TestSCP03_GlobalPlatformPro_JCOP4_MACOnlyTranscript`) | Real-card SCP03 INITIALIZE UPDATE response |
| [`nextgen/src/test/resources/scp03-auth-jcop4.dump`][g2] | `scp03/transcript_vectors_test.go` (`TestSCP03_GlobalPlatformPro_JCOP4_MACOnlyTranscript`) | Real-card SCP03 EXTERNAL AUTHENTICATE response |
| [`nextgen/src/test/java/pro/javacard/gp/ng/TestGlobalPlatformCookbook.java`][g3] | reference for the test data interpretation | How GPP parses these dumps; static keys, expected derivation |

[g1]: https://github.com/martinpaljak/GlobalPlatformPro/blob/6d6c154dd55b3dc5406d980345d44c8e4ed01a72/nextgen/src/test/resources/scp03-init-update-jcop4.dump
[g2]: https://github.com/martinpaljak/GlobalPlatformPro/blob/6d6c154dd55b3dc5406d980345d44c8e4ed01a72/nextgen/src/test/resources/scp03-auth-jcop4.dump
[g3]: https://github.com/martinpaljak/GlobalPlatformPro/blob/6d6c154dd55b3dc5406d980345d44c8e4ed01a72/nextgen/src/test/java/pro/javacard/gp/ng/TestGlobalPlatformCookbook.java

### Porting notes

* **Dumps preserved verbatim** (hex content of the `.dump` files
  inlined as Go `[]byte`). The dumps contain the card's INITIALIZE
  UPDATE response (key diversification data, sequence counter, card
  challenge, card cryptogram) and the EXTERNAL AUTHENTICATE response.
* **MAC-only mode.** This vector exercises C-MAC without C-DEC; the
  test asserts that our INITIALIZE UPDATE / EXTERNAL AUTHENTICATE
  command bytes match what GPP would send given the same static
  keys and host challenge.

---

## 3. Yubico yubikit-android

**Source repository:** [`Yubico/yubikit-android`](https://github.com/Yubico/yubikit-android)
**License:** Apache-2.0
**Default branch:** `main`
**Verified at:** `f46268563437ac52910001222a77741d229b9b99` (committed 2026-04-01, verified 2026-05-03)

Behavioral reference, not a vector import. yubikit is the canonical
reference for how a YubiKey expects to be talked to:

* **Empty-data SCP03 wrapping.** `EmptyDataEncryption = EmptyDataYubico`
  (default) matches yubikit's `ScpState.encrypt` behavior of padding
  empty plaintext to a full AES block before encrypt. The alternative
  policy `EmptyDataGPLiteral` matches a stricter reading of the GP
  spec. `channel/channel_test.go::TestEmptyData_YubicoDefault_PadsAndEncrypts`
  pins the YubiKey-compatible default.
* **SCP11a PSO certificate framing.** One extended-length APDU per
  certificate, P1 high-bit clear on every cert except the leaf.
  `mockcard/scp11_ephemeral_key_test.go::TestSCP11a_PSO_WireFormat`
  documents this layout and the GP §7.5.2 / yubikit alignment.
* **Factory-key behavior.** YubiKey factory SCP03 uses
  `KeyVersionNumber = 0xFF` and well-known default AES-128 key bytes.
  `scp03.YubiKeyFactoryKeyVersion` and `scp03.FactoryYubiKeyConfig()`
  reflect that.
* **A6/90 KID byte.** The KID encoded in the A6/90 control reference
  during SCP11 MUTUAL_AUTHENTICATE is hardcoded to `0x11` to match
  yubikit, regardless of the KID configured at session level.
  `channel/channel_test.go` (and `session/hardening_test.go`) cover
  this; `channel/channel.go::buildA6Tlv` documents the rationale.

This library does not import literal vector bytes from yubikit, so
no per-file table is needed; the citations are inline in the test
files that exercise the behavior.

---

## Refresh procedure

To re-verify against newer upstream commits:

1. Update the "Verified at" SHA and date in this document for the
   relevant source.
2. Update the permalink URLs to use the new SHA (search-and-replace
   on the SHA fragment).
3. Run `go test ./scp03/... ./session/... ./channel/... ./mockcard/...`
   to confirm the imported bytes still match the upstream files.
4. If any upstream file has moved or been deleted, capture the
   pre-move SHA in a "Last verified at" row and either re-import
   from the new path or pin to the older SHA.

## Out of scope

This document covers external transcripts and behavioral references
only. Internal test fixtures (mock cards, generated keys, synthetic
certificates) live in the test files alongside the code they exercise
and don't need provenance — they're library-authored.
