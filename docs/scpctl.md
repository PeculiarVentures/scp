# `scpctl` — administrative CLI

`scpctl` is the unified administrative CLI for `github.com/PeculiarVentures/scp`. It replaces the original `scp-smoke` binary with a grouped command structure that scales as the PIV and Security Domain operation surface grows.

For the operator-facing reference (build, examples, per-command flags), see [`cmd/scpctl/README.md`](../cmd/scpctl/README.md). This document covers design decisions, the migration map from `scp-smoke`, and the command structure rationale.

## Why `scpctl` and not `scp`

The bare name `scp` shadows OpenSSH's `scp` command on every Unix system. Naming a CLI that ships into operator `$PATH` after a core system command is a foot-gun even when the project name happens to match.

`scpctl` makes the function explicit (this is a control tool, not a scheme name), avoids the OpenSSH conflict, and matches the conventional `<thing>ctl` naming used by `systemctl`, `kubectl`, `etcdctl`, and similar tools.

## Why grouped commands

The original `scp-smoke` had a flat command list of ten subcommands. As PIV provisioning landed and Security Domain bootstrap got its own subcommand, the flat list crossed the readable threshold: an operator running `scp-smoke help` saw a table that mixed protocol-correctness checks, hardware probes, and destructive provisioning paths with no visible structure.

The three groups in `scpctl` correspond to three different operator mental models:

- **`smoke`**: "Is the library correct against this hardware?" Pre-deployment validation, regression testing, troubleshooting wire-level issues.
- **`piv`**: "Provision and operate a PIV credential on this card." User-facing day-to-day operations.
- **`sd`**: "Bootstrap or inspect this card's Security Domain." Card admin operations that don't touch PIV.

Top-level utilities (`readers`, `probe`, `version`, `help`) sit outside any group because they're the things you run before deciding which group you're in.

## Migration map from `scp-smoke`

Every `scp-smoke` subcommand is reachable as `scpctl smoke <same-name>`. Names are preserved verbatim, including the hyphenation:

| Old | New |
| --- | --- |
| `scp-smoke readers` | `scpctl smoke readers` (or `scpctl readers`) |
| `scp-smoke probe` | `scpctl smoke probe` (or `scpctl probe`) |
| `scp-smoke scp03-sd-read` | `scpctl smoke scp03-sd-read` |
| `scp-smoke scp11b-sd-read` | `scpctl smoke scp11b-sd-read` |
| `scp-smoke scp11a-sd-read` | `scpctl smoke scp11a-sd-read` |
| `scp-smoke scp11b-piv-verify` | `scpctl smoke scp11b-piv-verify` |
| `scp-smoke bootstrap-oce` | `scpctl smoke bootstrap-oce` |
| `scp-smoke piv-provision` | `scpctl smoke piv-provision` |
| `scp-smoke piv-reset` | `scpctl smoke piv-reset` |
| `scp-smoke test` | `scpctl smoke test` |

All flags carry over unchanged. JSON output shape is unchanged except the report header, which now reads `scpctl smoke probe` rather than `scp-smoke probe`.

## Group-vs-smoke split for new commands

The `piv` and `sd` groups are intentionally minimal today. Only `piv info` and `sd info` are wired; the SCP-secured provisioning paths still live under `smoke`. The split is deliberate:

- The `info` commands are the safe-by-default starting point: read-only, no auth, no state change. Operators can run them on any card without risk.
- The provisioning paths under `smoke` are SCP-wrapped, destructive-with-confirm, and depend on infrastructure (OCE keys, trust roots) that is operationally distinct from `info`. Migrating them under `piv` and `sd` is staged work that needs the `piv/session` library to grow change-PIN, change-management-key, import, and detailed cert operations first.

When a `smoke` provisioning subcommand has a clean `piv/session` equivalent, it migrates. Until then, the smoke version is the right path. The README's per-command reference notes which path to use for each operation.

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
