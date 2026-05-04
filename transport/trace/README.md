# transport/trace

Record/replay decorators for `transport.Transport`. Capture an APDU
flow against any underlying transport (PC/SC, mock card, relay) to a
JSON file; replay that JSON byte-exact in a test as a transport.

This package is the bridge between hardware testing and CI. It lets
us:

- Check evidence of real-card behavior into the repo.
- Get deterministic regression coverage for vendor quirks without
  the test machine needing the card.
- Accept contributed traces from cards we don't physically own.

## Usage

### Recording

```go
import (
    "github.com/PeculiarVentures/scp/scp03"
    "github.com/PeculiarVentures/scp/transport/trace"
    "github.com/PeculiarVentures/scp/transport/pcsc"
)

reader, _ := pcsc.Open("Yubico YubiKey OTP+FIDO+CCID 0")
defer reader.Close()

rec := trace.NewRecorder(reader, trace.RecorderConfig{
    Profile: "yubikey",
    Reader:  "Yubico YubiKey OTP+FIDO+CCID 0",
    Notes:   "SCP03 factory open",
    Determinism: trace.Determinism{
        HostChallenge: fixedChallenge, // pin if you want the trace to be replayable
    },
})

sess, err := scp03.Open(ctx, rec, &scp03.Config{
    Keys:          scp03.DefaultKeys,
    HostChallenge: fixedChallenge,
})
// ... drive the flow ...
sess.Close()
rec.Close()
rec.FlushFile("testvectors/hardware/yubikey/scp03_factory_open.json")
```

### Replaying

```go
rep, err := trace.NewReplayer("testvectors/hardware/yubikey/scp03_factory_open.json")
if err != nil {
    t.Fatal(err)
}

sess, err := scp03.Open(ctx, rep, &scp03.Config{
    Keys:          scp03.DefaultKeys,
    HostChallenge: rep.HostChallenge(), // the pinned value from the trace
})
// ... drive the same flow ...
sess.Close()

if err := rep.Close(); err != nil {
    t.Errorf("unconsumed exchanges: %v", err)
}
```

## Determinism is the test author's responsibility

The recorder and replayer make no assumptions about randomness. SCP
flows contain caller-side randomness (SCP03 host challenge, SCP11
OCE ephemeral key); if the recording was made with a fresh random
challenge, replay will mismatch on INITIALIZE UPDATE.

The fix is to pin randomness explicitly when capturing a trace
intended for replay. The `Determinism` block in the trace header
documents what was pinned, and the replayer surfaces those values
through `HostChallenge()` and `OCEEphemeralSeed()` for the
replay-side test to consume.

We deliberately do *not* support fuzzy matching or wildcard byte
ranges. Tolerant comparison is a silent escape hatch for protocol
regressions; strict matching plus pinned randomness is the contract.

## What the trace contains

A trace is a JSON file. One flow per file. UTF-8, lowercase hex,
indented for readable diffs. See `DESIGN.md` (in the package source
tree) for the schema.

What's recorded:

- Every `Transmit` and `TransmitRaw` call, with its command bytes,
  the response bytes, the trailing SW, and a duration.
- The transport method (`Transmit` vs `TransmitRaw`) — these are
  matched separately on replay.
- Errors from the underlying transport, with the error string.
- Caller-supplied metadata: profile, reader name, card ATR, notes,
  pinned randomness.

What's NOT recorded:

- Anything that wasn't on the wire. Static SCP03 keys, derived
  session keys, OCE private keys never reach the transport layer
  and never appear in a trace.
- Any guess at semantic structure beyond CLA/INS/P1/P2 (which are
  derived from the bytes for diff readability and ignored on
  replay).

## When not to use this

- **Performance testing.** Replay is in-memory and lies about
  timing. Use the real transport.
- **Conformance against a moving target.** A trace captures one
  card's behavior at one moment. If the card's behavior is what
  you're testing for stability, fine; if you're testing your code's
  ability to handle vendor variance, you need traces from multiple
  cards.
- **Anything where the trace is sensitive material.** Card serials,
  ATRs, and OCE certificates may carry deployment fingerprints. If
  you can't check the trace into a public repo, don't record one
  with this tool — sanitize the source data, or capture against a
  test card.
