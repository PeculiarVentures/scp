# Security Policy

This library handles cryptographic key material on behalf of its callers. Vulnerabilities in it can expose private keys, allow forged authentication against real cards, or destabilize a host that's communicating with an untrusted card. We take security reports seriously and respond on a defined timeline.

## Scope

Reports about the following are in scope:

- Code in this repository, including all Go packages under `github.com/PeculiarVentures/scp/...`, the `scpctl` CLI under `cmd/scpctl/`, and the gRPC and PC/SC transports under `transport/`.
- Cryptographic flaws: incorrect protocol implementation, key-derivation errors, MAC verification bypasses, receipt-validation failures, side-channel leaks of session keys, mishandling of ECDH outputs, parser bugs in untrusted-input paths (TLV, APDU response, certificate store) that lead to memory corruption, infinite loops, unbounded allocation, or arbitrary control over downstream parsers.
- Authentication and authorization flaws: anything that allows an unauthorized session to open against a card, that bypasses the documented profile capability gates, or that allows a hostile card to coerce the host into emitting bytes the operator did not authorize.
- Information disclosure: any code path that writes session-key material, OCE private keys, SCP03 static keys, or other secrets to logs, files, or error messages.

The following are out of scope:

- Vulnerabilities in third-party dependencies. Report those to the upstream project. We will pick up dependency fixes in releases as they become available.
- Vulnerabilities in cards or hardware. Report those to the vendor.
- Issues that require a malicious local user with already-elevated privileges (e.g., reading a private-key file the operator placed at a known path with mode 0644).
- Denial-of-service caused by a card the operator chose to insert. The transport layer documents resource ceilings; reports should demonstrate an exceeded ceiling, not just "the card returned a lot of data."

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:** open a draft advisory at <https://github.com/PeculiarVentures/scp/security/advisories/new>. This routes the report to the maintainers without disclosing it publicly.

**Or email:** `security@peculiarventures.com`. PGP key on request.

**Do not** open a public GitHub issue, send a pull request that exposes the vulnerability, or post to social media before a coordinated disclosure timeline has been agreed.

A useful report includes:

1. The affected version(s) or commit hash.
2. The package, file, and function involved.
3. A minimal proof-of-concept (Go test case, APDU trace, or reproducer script). For parser bugs, the input bytes that trigger the issue.
4. The impact: what an attacker can do given the bug, and what they need to control to do it.
5. Your suggested fix, if you have one.

## Response timeline

We commit to:

- **Acknowledgment within 3 business days.** A maintainer will confirm we received the report and is investigating.
- **Triage assessment within 10 business days.** We will respond with whether we consider the issue a vulnerability, our severity rating, and an estimated timeline for a fix.
- **Coordinated disclosure.** Once a fix is ready, we agree a disclosure date with the reporter. Default is 90 days from initial report or fix availability, whichever is sooner. We can extend or compress that window by mutual agreement when there are deployment constraints on either side.
- **Public advisory.** We publish a GitHub Security Advisory with CVE assignment for any vulnerability rated medium or higher. The advisory credits the reporter unless they request anonymity.

## Recognition

If you'd like recognition in the published advisory, say so in your report and we will name you. We do not currently run a bug-bounty program.

## Verifying released artifacts

This repository is published as a Go module. To verify the integrity of a downloaded version, check the module against the public checksum database:

```
GOSUMDB=sum.golang.org go mod download github.com/PeculiarVentures/scp@<version>
```

A mismatch between the local module cache and `sum.golang.org` is grounds for a security report.

## Supported versions

The most recent minor release is supported with security fixes. Older minor releases are supported on a best-effort basis when the fix backports cleanly. We do not promise indefinite support for unsupported versions; security fixes will land on `main` and in the next release.
