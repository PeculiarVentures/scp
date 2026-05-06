# `scpctl` — administrative CLI

`scpctl` is the unified administrative CLI for `github.com/PeculiarVentures/scp`. Grouped command structure with four operator-distinct groups plus a small set of top-level utilities.

For the operator-facing reference (build, examples, per-command flags), see [`cmd/scpctl/README.md`](../cmd/scpctl/README.md). This document covers design decisions and the command structure rationale.

## Why `scpctl` and not `scp`

The bare name `scp` shadows OpenSSH's `scp` command on every Unix system. Naming a CLI that ships into operator `$PATH` after a core system command is a foot-gun even when the project name happens to match.

`scpctl` makes the function explicit (this is a control tool, not a scheme name), avoids the OpenSSH conflict, and matches the conventional `<thing>ctl` naming used by `systemctl`, `kubectl`, `etcdctl`, and similar tools.

## Group structure

Five groups plus a small set of top-level utilities:

- **`test`** — hardware regression checks. Read-only against real cards: validates the SCP library produces wire bytes the card accepts, and that the wire layer carries through higher-level applet protocols. Used in CI to catch regressions before they ship.
- **`piv`** — PIV operator surface. PIN/PUK lifecycle, management-key authentication and rotation, slot key generation, certificate install/read/delete, raw object I/O, attestation, full applet reset, and the SCP11b-secured `provision` flow. These commands write to the card; safety is documented in [`piv.md`](piv.md).
- **`sd`** — Security Domain operator surface. `info` reads CRD and key-info template (with `--full` for a GP §11.4.2 registry walk); `reset` factory-resets SD key material; `lock` / `unlock` toggle the ISD between SECURED and CARD_LOCKED via GP SET STATUS (recoverable, `--confirm-write` gate); `terminate` transitions the ISD to TERMINATED — IRREVERSIBLE — gated by a distinct `--confirm-terminate-card` flag so a careless `--confirm-write` invocation can never brick a card; `bootstrap-oce` / `bootstrap-scp11a` / `bootstrap-scp11a-sd` are the day-1 provisioning flows that install OCE material and the SCP11a SD ECDH key on fresh cards.
- **`oce`** — off-card OCE certificate diagnostics. `verify` validates a chain off-card; `gen` produces a fresh known-good chain. Host-only — does not touch a card.
- **`gp`** — generic GlobalPlatform card-content management. `probe` is the gp-tagged form of the unauthenticated SD probe; `registry` walks the GP registry (ISD, Applications, LoadFiles+Modules) over an authenticated SCP03 session and produces the same JSON registry shape as `sd info --full`; `cap inspect` is a host-only CAP file inspector that prints package AID, applet AIDs, and component sizes. The boundary against `sd`: `sd` is YubiKey-flavored Security Domain identity and bootstrap; `gp` is generic GP card-content management with a future destructive surface (install/delete) that lives behind hardware and key-vector prerequisites.

Top-level utilities (`readers`, `probe`, `version`, `help`) sit outside any group because they're the things you run before deciding which group you're in.

The split is along an operator mental-model axis: "is this a regression check," "am I operating PIV," "am I operating the Security Domain," "am I doing host-side OCE work," "am I doing generic GP applet management."

## Output shape

Every subcommand emits a `Report` with the same structure:

```
{
  "subcommand": "<group> <sub>" | "<sub>",
  "reader": "...",
  "checks": [
    {"name": "...", "result": "PASS|FAIL|SKIP", "detail": "..."}
  ],
  "data": { /* subcommand-specific structured payload */ }
}
```

Human-readable mode renders the same data as a header line plus one indented line per check. The `data` block (when present) pretty-prints below the checks.

Lab-trust skips appear in JSON as `"lab_skip_scp11_trust": true` somewhere in the report payload. Auditing pipelines should reject any run carrying that field unless the run is explicitly tagged as lab work.

## Exit codes

- `0` — all checks passed (or the subcommand has no checks and ran cleanly).
- `1` — one or more checks failed, or the subcommand returned an error.
- `2` — usage error (unknown subcommand, bad flags).

The distinction between `1` and `2` matters for CI: bad-flag errors are operator-fixable, check failures are signal about the card or the library.
