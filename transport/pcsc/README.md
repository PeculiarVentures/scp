# transport/pcsc

PC/SC-backed `transport.Transport` implementation for the [`scp`](../..) protocol engine. Connects to USB CCID and NFC readers via the platform's PC/SC service (`winscard.dll` on Windows, `pcsclite` on Linux/macOS).

## Why a separate module?

This subpackage has its own `go.mod` so the main `scp` module stays CGO-free. Consumers that bring their own transport (in-memory test, gRPC relay, USB HID) don't need PC/SC headers on their build host. Only consumers that import `transport/pcsc` pull in the [`ebfe/scard`](https://github.com/ebfe/scard) dependency.

## Platform setup

| Platform | Headers | Service |
|---|---|---|
| Windows | bundled | Smart Card service (auto-starts) |
| macOS | bundled | `pcscd` (auto-starts) |
| Debian/Ubuntu | `apt install libpcsclite-dev` | `apt install pcscd && systemctl enable --now pcscd` |
| Fedora/RHEL | `dnf install pcsc-lite-devel` | `dnf install pcsc-lite && systemctl enable --now pcscd` |

CGO is required.

## Usage

```go
import (
    "context"

    "github.com/PeculiarVentures/scp/scp11"
    "github.com/PeculiarVentures/scp/transport/pcsc"
)

// Pick the first connected reader (single-YubiKey case).
t, err := pcsc.OpenFirstReader()
if err != nil {
    return err
}
defer t.Close()

// Or address one by name (use pcsc.ListReaders() to discover them).
// t, err := pcsc.OpenReader("Yubico YubiKey OTP+FIDO+CCID 00 00")

cfg := scp11.YubiKeyDefaultSCP11bConfig()
cfg.CardTrustAnchors = myYubicoSCP11Roots // ← required for production
sess, err := scp11.Open(context.Background(), t, cfg)
```

## Sentinel errors

```go
errors.Is(err, pcsc.ErrNoReaders) // no readers connected
errors.Is(err, pcsc.ErrNoCard)    // reader present, no card inserted
```

## Reading list

`pcsc.ListReaders()` returns the platform's list without connecting.

## Wait-for-card

`pcsc.WaitForCard(ctx, readerName)` blocks until a card is inserted or `ctx` is done. Useful for "plug in your YubiKey now" prompts.

## Concurrency

`Transport` is **not** safe for concurrent use. The SCP session layer already serializes `Transmit` per session; do not share one `Transport` across goroutines.

## Example program

`example/` builds a tiny demo. With a card inserted:

```
$ go run ./example
connected to: Yubico YubiKey OTP+FIDO+CCID 00 00
handshake complete — protocol: SCP11b
```

With no card or no reader, it prints a clear next step. Pass `list` to dump readers without connecting.
