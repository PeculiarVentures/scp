# Independent SCP test vectors

This directory documents the external conformance material used by the unit tests.

The goal is to avoid validating the implementation only against its own mock card.
Mock cards are still useful for state-machine tests, but independent transcripts are
needed for protocol compatibility and security regressions.

## Sources

### Samsung OpenSCP-Java

Source repository: `Samsung/OpenSCP-Java`

Relevant files:

- `src/test/java/com/samsung/openscp/Scp03Tests.java`
- `src/test/java/com/samsung/openscp/testdata/InputTestData.java`
- `src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S8ModeEmulation.java`
- `src/test/java/com/samsung/openscp/testdata/SmartCardScp03Aes128S16ModeEmulation.java`
- `src/test/java/com/samsung/openscp/Scp11Tests.java`
- `src/test/java/com/samsung/openscp/testdata/SmartCardScp11aP256Aes128S8ModeEmulation.java`

License: Apache-2.0.

These vectors are especially useful because they cover SCP03 AES-128/192/256,
S8/S16, and multiple SCP11 variants. The first imported tests focus on SCP03
because they directly catch the EXTERNAL AUTHENTICATE and S16 issues.

### GlobalPlatformPro

Source repository: `martinpaljak/GlobalPlatformPro`

Relevant files:

- `nextgen/src/test/resources/scp03-init-update-jcop4.dump`
- `nextgen/src/test/resources/scp03-auth-jcop4.dump`
- `nextgen/src/test/java/pro/javacard/gp/ng/TestGlobalPlatformCookbook.java`

License: LGPL-3.0-or-later.

These are real-card JCOP4 APDU dumps and provide a sanity check against a mature
GlobalPlatform implementation.

## Import strategy

The tests intentionally preserve the upstream CAPDU and RAPDU bytes verbatim.
They should be treated as known-answer tests, not as examples to refactor into
the local mock-card behavior.

