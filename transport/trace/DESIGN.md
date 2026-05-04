# transport/trace — design notes

A record/replay decorator for `transport.Transport`. Records APDU
exchanges to JSON; replays them back deterministically for tests.

This is the highest-leverage piece of infrastructure for the
"profile-driven generic SCP library" story. It bridges hardware
testing and CI, gives us regression protection for vendor quirks,
and lets contributors submit traces from cards we don't own.

## Goals

1. **Record** any flow against any `Transport` (real card via PC/SC,
   mock card, relay) without the library knowing or caring.
2. **Replay** a recorded flow as a `Transport`, byte-exact, with
   clear errors on divergence.
3. **Check traces in.** The on-disk format is the artifact; it has to
   survive review, diff cleanly, and not silently rot.
4. **Compose with `Transport`.** `Recorder{Inner: pcsc}` and
   `Replayer{}` both implement `transport.Transport`. Nothing in the
   library above transport needs to change.

## Non-goals (v1)

- **Sanitization/redaction.** Belongs in a separate pass over the
  trace JSON, not the recorder. SCP traffic doesn't carry long-term
  secrets on the wire (static AES keys never leave the host; OCE
  private keys never leave the controller). What it *does* carry is
  card identity material — certs, serials, ephemerals, receipts —
  which is privacy-sensitive but not secret. Treat that as a
  reviewer concern, not a library concern, until we have a concrete
  use case that needs it.
- **Fuzzy matching / variable byte ranges.** Tempting and wrong. The
  right answer is determinism at the source (see below), not
  tolerant comparison at the sink. Tolerant comparison turns into a
  silent escape hatch for protocol regressions.
- **Conversion between trace formats** (PC/SC trace dumps, gp.jar
  output). Out of scope for v1; can be added as a separate `cmd/`
  tool later if useful.

## The determinism problem

SCP handshakes contain caller-side randomness:

- **SCP03**: 8- or 16-byte host challenge in INITIALIZE UPDATE.
- **SCP11**: ephemeral OCE EC key pair (and the corresponding
  `ePK.OCE.ECKA` sent on the wire).

If the recorder captures a flow with a fresh random host challenge,
re-running the same code under the replayer will send a *different*
challenge in INITIALIZE UPDATE, and replay will reject with a command
mismatch.

Three options:

1. **Determinism at the source.** The SCP library already exposes
   `InsecureTestOnlyEphemeralKey` for SCP11 and accepts
   `HostChallenge` on `scp03.Config`. Tests that use the replayer
   must set these explicitly; recordings document them in the
   header. *This is what we do.* It's the only option that doesn't
   silently weaken the protocol contract being tested.

2. **Wildcard byte ranges in the trace.** Pollutes the format,
   shifts the maintenance burden onto every new test, and makes
   "did the bytes change?" a fuzzy question. No.

3. **Recorder rewrites the trace to use the replay's randomness.**
   Inverts the relationship — the trace is no longer a faithful
   record of what happened, it's a synthesized fixture. Fine for
   some uses; not what we want here.

The recorder and replayer themselves make no assumption about
randomness. Determinism is the test author's responsibility. The
header carries enough metadata that a stale trace produces a clear
diagnostic instead of a mysterious MAC failure.

## On-disk format

JSON, one file per flow. UTF-8, hex-encoded byte fields, stable key
ordering on write. Indented for review-friendliness — these are
artifacts that reviewers will read by eye.

Top-level shape:

```json
{
  "schema": "scp-trace/v1",
  "captured_at": "2026-05-03T18:00:00Z",
  "profile": "yubikey",
  "reader": "Yubico YubiKey OTP+FIDO+CCID 0",
  "card_atr": "3bfd1300008131fe1580730e0207904c00400000a4",
  "notes": "SCP03 factory open + KVN rotation, host challenge fixed",
  "determinism": {
    "host_challenge_hex": "0102030405060708",
    "oce_ephemeral_seed_hex": null
  },
  "exchanges": [
    {
      "i": 0,
      "kind": "Transmit",
      "cla": "00", "ins": "a4", "p1": "04", "p2": "00",
      "command_hex": "00a4040008a000000151000000",
      "response_hex": "...9000",
      "sw": "9000",
      "duration_ns": 4200000,
      "annotation": "SELECT ISD"
    },
    {
      "i": 1,
      "kind": "TransmitRaw",
      "command_hex": "8050ff0008<host-challenge>00",
      "response_hex": "...",
      "sw": "9000",
      "duration_ns": 7100000,
      "annotation": "INITIALIZE UPDATE"
    }
  ]
}
```

Field notes:

- `schema` is required and exact-match. Schema bumps are migrations,
  not soft-compat negotiations.
- `profile` is informational. The replayer doesn't enforce it; the
  conformance harness uses it to filter.
- `kind` distinguishes `Transmit` (parsed APDU went in) from
  `TransmitRaw` (opaque bytes). Replayer must match the same call
  the test makes — calling `TransmitRaw` against a `Transmit`-recorded
  exchange is a mismatch. We do *not* normalize between them; the
  parsed/raw distinction is part of the contract under test.
- The parsed APDU header fields (`cla`, `ins`, `p1`, `p2`) are
  derived and redundant with `command_hex`. They exist for diff
  readability and are *not* checked by the replayer (so a
  hand-edited annotation can't drift from reality). On read, the
  replayer recomputes them; on write, the recorder fills them.
- `sw` is the trailing two bytes of `response_hex`, broken out for
  the same reason.
- `duration_ns` is informational. Not enforced.
- `annotation` is human-only. Recorder leaves it empty; reviewers
  fill it in by hand for checked-in fixtures. Replayer ignores it.

## Recorder semantics

```go
rec := trace.NewRecorder(inner, trace.RecorderConfig{
    Profile: "yubikey",
    Reader:  "Yubico YubiKey OTP+FIDO+CCID 0",
    Notes:   "SCP03 factory open + KVN rotation",
})
defer rec.Close() // flushes JSON to writer

sess, err := scp03.Open(ctx, rec, &scp03.Config{
    HostChallenge: fixedChallenge,
    Keys:          scp03.DefaultKeys,
})
```

- Recorder transparently forwards every call to `inner`.
- Records on success *and* on error returns from `inner`. A non-nil
  error is recorded with `error: "..."` instead of `response_hex`.
  Tests of error paths need to be replayable too.
- Recording is best-effort: if the JSON writer fails, the recorder
  surfaces the error from `Close()`, not from `Transmit`. We do not
  want a logging failure to cause a card operation to fail.
- Concurrency: `transport.Transport` is documented as
  one-outstanding-APDU-at-a-time (see `docs/remote-apdu-transport.md`).
  The recorder honors that — no internal locking, no buffering across
  exchanges.

## Replayer semantics

```go
rep, err := trace.NewReplayer("testvectors/hardware/yubikey/scp03_factory_open.json")
if err != nil { ... }

sess, err := scp03.Open(ctx, rep, &scp03.Config{
    HostChallenge: rep.RecordedHostChallenge(), // helper from determinism block
    Keys:          scp03.DefaultKeys,
})
```

- Strict matching by default. Command bytes must match the recorded
  bytes exactly. Mismatch returns a structured error showing
  (expected, got, exchange index, annotation).
- The replayer's `Close` returns an error if not all exchanges were
  consumed — under-consumption is a regression signal too.
- `RecordedHostChallenge()` and `RecordedOCEEphemeralSeed()` surface
  the determinism block to the test; null when not set.

## Open questions

- **Should we record `Close()`?** Probably not — it's not a wire
  exchange. Skip.
- **What happens when `inner.Transmit` returns a partial response?**
  PC/SC doesn't really have this case; the response is whole or it's
  an error. Recorder records what `inner` returned and moves on.
- **Trace size.** OCE certs are 300–800 bytes; a full SCP11a flow
  with PSO upload of a 3-cert chain plus key gen plus cert store is
  on the order of 10–20 exchanges, maybe 5–10 KB of hex. Fine for
  git. If we ever want compression, gzip on disk is the obvious
  answer; the JSON format doesn't change.
- **Multiple flows per file?** No. One flow per file. Composition
  happens at the test level. Single-purpose files diff cleanly,
  delete cleanly, and have unambiguous failure attribution.
- **Schema versioning.** v1 is what's in this doc. Any change to
  field semantics (not additions of optional fields) bumps to v2 and
  a migration tool ships at the same time. We do not silently accept
  multiple versions.

## What ships first

- `transport/trace/format.go` — types + JSON marshal/unmarshal.
- `transport/trace/recorder.go` — `NewRecorder` + `Recorder.Close`.
- `transport/trace/replayer.go` — `NewReplayer` + matching logic +
  structured error.
- `transport/trace/trace_test.go` — round-trip test against
  `scp03.MockCard` and `mockcard.Card`.
- One real fixture: `testvectors/hardware/yubikey/scp03_factory_select.json`.
  Just SELECT — proves the round-trip end-to-end against a real
  YubiKey. Fuller flows follow once the format is reviewed and
  stable.

Two things explicitly *not* in the first cut: a CLI for trace
record/replay (right scope is the harness, not a tool), and the
`profiles` package (separate work, separate review).
