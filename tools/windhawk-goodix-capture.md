# Windhawk Goodix WBDI Capture Notes

These notes document the Windows capture path used for the Goodix `27c6:521d`
reader. The goal was to observe the Windows UMDF/WBDI driver at the same time
as the lower USB transport so the Linux `goodixtls52xd` implementation could be
matched to the stock-firmware Windows behavior.

Raw captures can contain biometric image data, provisioning state, and PSK
material. Keep the raw `C:\goodix-capture` output and imported archive artifacts
out of git unless they have been explicitly scrubbed.

**If you only need the PSK, try `psk_recovery.md` first.** The sealed blob can
be read off the device and unsealed offline against a mounted Windows volume:
no Windows boot, no injection. This document is the fallback for when that route
is blocked: BitLocker, a wiped or reinstalled Windows, or a sensor moved to
another machine. It is also still the reference for the capture path itself.

## Windhawk Mod

The Windhawk mod is `tools/windhawk_goodix_winusb_dump.wh.cpp`. It targets the
64-bit `WUDFHost.exe` process because the Goodix Windows driver is hosted by the
UMDF driver host. Install or paste the mod into Windhawk, enable it for
`WUDFHost.exe`, then exercise Windows Hello enrollment or verification.

The mod hooks exactly two `WBDI.DLL` internal functions
(`PresetPskPskGet`, `PresetPskPskSet`, see "WBDI Internal Hooks" below) and
writes the 32-byte session PSK to:

```text
C:\goodix-capture\psk32.bin
```

Disable the mod after collection and exclude `WUDFHost.exe` from further
Windhawk injection before returning Windows to normal use.

## Capture Attempts (history)

This section documents how the WBDI-level hook point was found; the layers it
describes below (USBPcap, WinUSB export hooks, IOCTL/completion interception)
are no longer part of the shipped mod, which now implements only the WBDI PSK
hooks this investigation led to.

The first Windows capture attempts used USBPcap and Goodix driver logs. USBPcap
was useful for device enumeration and controller selection, but on this system
it did not capture the target Goodix message-pack, TLS, bulk OUT, or bulk IN
payloads needed for the Linux driver work.

The next attempt hooked `WINUSB.DLL` exports from inside `WUDFHost.exe`:

- `WinUsb_WritePipe`
- `WinUsb_ReadPipe`
- `WinUsb_ControlTransfer`
- `WinUsb_GetOverlappedResult`
- wait and IO completion APIs used by async transfers

This showed stable outbound Goodix traffic, including many 64-byte `0xa0`
message frames and some outbound TLS records. It still did not capture received
messages: no useful inbound `WinUsb_ReadPipe`, control-input, wait-result, or
IOCP-completion payloads appeared. In practice, the WinUSB export hooks were
enough to identify the outgoing command sequence, but not the sensor replies.

The following revision intercepted lower-level IOCTL calls:

- `DeviceIoControl`
- `NtDeviceIoControlFile`
- async completion paths through overlapped results, IO completion ports, wait
  APIs, and pending-transfer scans

That exposed the UMDF/WinUSB IOCTL layer. The repeated IN-pipe request was
visible as IOCTL `0x0350401e` with selector bytes `00 83`, and the OUT-pipe
request was visible as IOCTL `0x03508021` with selector bytes `00 01`. This
confirmed where the bulk transfers were going, and later pending scans produced
more `ioctl_out` completions. However, those completions were still mostly
small status or configuration buffers. The large received Goodix payloads, TLS
records, and image buffers were not copied through buffers visible at this hook
level.

The useful capture required combining low-level IOCTL interception with
higher-level `WBDI.DLL` internal hooks. The low-level hooks preserved transport
context and timing, while the WBDI hooks captured the command objects after the
Goodix driver had assembled or decrypted them.

## WBDI Internal Hooks

The mod hooks two internal `WBDI.DLL` functions by RVA for the driver version
used during this analysis, both of which write `psk32.bin`:

- `Wbdi!PresetPskPskGet` at RVA `0x78658` -> writes psk32.bin (fallback path)
- `Wbdi!PresetPskPskSet` at RVA `0x787CC` -> writes psk32.bin (primary path)

These offsets are version-specific. Re-check them after a driver update before
trusting the capture.

An earlier revision of the mod also hooked `Wbdi!IoHubExec` (RVA `0x5c550`) to
capture command/TLS buffers for protocol reverse-engineering
(`0xd0 REQUEST_TLS_CONNECTION`, `0x20 MCU_GET_IMAGE`, sensor/FDT commands,
etc). That hook and its buffer capture output are not needed for PSK
extraction and have been removed from the shipped mod; see git history if
protocol-level capture is needed again.

## PSK Capture

Two hooks cover the session PSK, both writing to `C:\goodix-capture\psk32.bin`
(owner + administrators only) with length-only logging: the mod produces no
other output file, and the secret never enters the Windhawk log:

- `Wbdi!PresetPskPskSet @ 0x787CC` (primary, deterministic): after the original
  stores the driver-verified plaintext PSK in the session ctx, the hook
  re-reads it via the original `PskGet` (pure memcpy-from-ctx, no device I/O)
  into a stack buffer it zeroes after writing. Immune to the ~200ms
  `PskSet -> PskGet` race; needs only the `PskSet` call itself.
- `Wbdi!PresetPskPskGet @ 0x78658` (fallback): post-return copy as before.

Expect `PSK captured via PskSet: len 32` (or `PSK captured: len 32`) in the
Windhawk log, then `psk32.bin` at exactly 32 bytes.

Verify by length only, then hand `psk32.bin` to the libsecret installer and
delete the file from both sides immediately after. Do not commit or print the
raw PSK. Validate out-of-band that the installed 32-byte secret matches the
known 52xd/10034 PMK hash; the PMK hash is not itself the OpenSSL TLS PSK, it
only confirms the captured secret is the Windows driver PSK for the stock
10034 path.

## Practical Workflow

Ordering matters more than anything else: the 521D host runs
`ProcessPsk -> PskSet -> PskGet` once per host lifetime (~200ms after start,
pre-login), while Windhawk starts at user login. A boot-first capture always
misses it. Always force the fresh session *after* Windhawk is up:

1. Start from a clean `C:\goodix-capture` directory.
2. Enable the Windhawk mod for `WUDFHost.exe` and confirm Windhawk is running.
3. Force a fresh observed session: admin PowerShell
   `tools\goodix-fresh-session.ps1` (restarts `WbioSrvc`, reports the new host
   pid; fallback is Device Manager disable/enable on the Goodix device).
4. Confirm the Windhawk log shows both `hooked internal` lines for the new pid.
   If either is missing, stop; the session will not yield a PSK.
5. Exercise Windows Hello enrollment or verification once.
6. Stop after Windows returns to an idle state.
7. Expect `C:\goodix-capture\psk32.bin` at exactly 32 bytes.
8. Disable the mod and exclude `WUDFHost.exe` from Windhawk injection.
9. Hand `psk32.bin` to `tools/goodix_521d_psk.py --store --psk-file`, then
   delete the file from both sides (see "PSK Capture" above).

The capture investigation (see "Capture Attempts"
above) showed no single layer was sufficient to find the PSK hook point:
USBPcap and WinUSB hooks gave little or no receive data, async completion
interception still missed the large returned buffers, and the final usable
hook point required high-level WBDI command interception. The shipped mod
only needs the two WBDI PSK hooks that investigation found.
