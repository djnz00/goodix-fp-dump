# Windhawk Goodix WBDI Capture Notes

These notes document the Windows capture path used for the Goodix `27c6:521d`
reader. The goal was to observe the Windows UMDF/WBDI driver at the same time
as the lower USB transport so the Linux `goodixtls52xd` implementation could be
matched to the stock-firmware Windows behavior.

Raw captures can contain biometric image data, provisioning state, and PSK
material. Keep the raw `C:\goodix-capture` output and imported archive artifacts
out of git unless they have been explicitly scrubbed.

## Windhawk Mod

The Windhawk mod is `tools/windhawk_goodix_winusb_dump.wh.cpp`. It targets the
64-bit `WUDFHost.exe` process because the Goodix Windows driver is hosted by the
UMDF driver host. Install or paste the mod into Windhawk, enable it for
`WUDFHost.exe`, then exercise Windows Hello enrollment or verification.

The mod writes JSONL metadata and buffer dumps under:

```text
C:\goodix-capture\windhawk-winusb\events.jsonl
C:\goodix-capture\windhawk-winusb\buffers\*.bin
C:\goodix-capture\windhawk-winusb\buffers\*.hex
```

Each event records the source API, direction, pipe or synthetic pipe ID, IOCTL
code or WBDI command tag, requested length, actual length, status, and paths to
the binary and hex buffer artifacts.

Disable the mod after collection and exclude `WUDFHost.exe` from further
Windhawk injection before returning Windows to normal use.

## Capture Attempts

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

The mod currently hooks two internal `WBDI.DLL` functions by RVA for the driver
version used during this analysis:

- `Wbdi!IoHubExec` at RVA `0x5c550`
- `Wbdi!PresetPskPskGet` at RVA `0x78658`

These offsets are version-specific. Re-check them after a driver update before
trusting the capture.

`Wbdi!IoHubExec` receives command objects with a work type, command ID, outbound
buffer, inbound buffer, and completion status. Capturing around this function
finally exposed the driver-level messages that the lower hooks missed:

- `0xd0 REQUEST_TLS_CONNECTION` with a two-byte zero payload before TLS starts.
- Outbound TLS records on WBDI work type `5`.
- `0x20 MCU_GET_IMAGE` requests with 10-byte calibration payloads.
- `0x20` image replies with 10240-byte payloads.
- `0xd2` command-level replies with 10240-byte payloads.
- Sensor setup and FDT commands such as `0x80`, `0x36`, `0x32`, `0x34`,
  `0xc4`, `0xd6`, `0x90`, and `0xac`.

The WBDI layer is therefore the most useful place to understand command
semantics, while the IOCTL layer is useful for correlating those commands to the
actual driver-host transport behavior.

## PSK Capture

The TLS PSK was captured by hooking `Wbdi!PresetPskPskGet`. After the original
function returned successfully, the hook copied the output buffer indicated by
the function's output-length argument. The mod writes that buffer as a
`wbdi_psk` event with synthetic pipe ID `0xfa` and tag `0x50534b00`.

The observed buffer was exactly 32 bytes. The analysis summary records only the
length and SHA-256 of the captured PSK; the raw value remains in the controlled
archive buffer artifact. Do not commit or print the raw PSK. For local
experiments, derive `LIBFPRINT_GOODIXTLS_PSK_HEX` from the raw `wbdipsk` buffer
inside the private archive, then clear it from shell history and logs.

The captured PSK hashes to the known 52xd/10034 PMK hash used as validation
evidence. The PMK hash is not itself the OpenSSL TLS PSK; it only confirms that
the captured 32-byte secret is the Windows driver PSK for the stock 10034 path.

## Practical Workflow

1. Start from a clean `C:\goodix-capture` directory.
2. Enable the Windhawk mod for `WUDFHost.exe`.
3. Restart the Windows biometric service or reconnect the reader so the Goodix
   UMDF host loads with the hook installed.
4. Exercise Windows Hello enrollment or verification.
5. Stop after Windows returns to an idle state.
6. Disable the mod and exclude `WUDFHost.exe` from Windhawk injection.
7. Import `C:\goodix-capture` into the private `arc/` archive.
8. Summarize sensitive artifacts by length and hash only.

The important lesson from the capture sequence is that no single layer was
sufficient. USBPcap and WinUSB hooks gave little or no receive data, async
completion interception still missed the large returned buffers, and the final
usable trace required both low-level IOCTL capture and high-level WBDI command
interception.
