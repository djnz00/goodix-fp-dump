## Summary

Inventory refreshed 2026-09-07 for the `goodix-fp-dump` checkout on branch `psk-tooling-cleanup`. The project is a Python 3.10+ collection of Goodix fingerprint sensor tools, targeting the 521d (`27c6:521d`, stock `APP_10034`) only; the other device families (51x0, 51x7, 53x5, 53xd, 5503, 55x4) were removed from the tree. `driver_52xd.py` is the driver flow, `run_521d.py` the hardware entrypoint, and `tools/psk.py` the single-command PSK recovery tool. Shared transport, protocol, image, and firmware helpers live in `protocol.py`, `goodix.py`, `wrapless.py`, `tool.py`, and `preprocessor.py`; shared services live in the `goodix_fp_dump/` package.

Environment management is uv-only: `uv sync` from `pyproject.toml` + `uv.lock`, run anything through `uv run`.

## Coding style and conventions

Legacy code uses plain Python modules; the `goodix_fp_dump/` package holds shared archive, preflight, firmware, image, safety, and TLS-proxy services. Functions use `snake_case`; protocol constants and byte blobs use uppercase names such as `PSK`, `DEVICE_CONFIG`, and `PMK_HASH_LENGTH` (`driver_52xd.py`). New modules use type annotations where useful. Indentation is 4 spaces. Fail-closed checks in the 52xd path use plain asserts (verification_status history records the earlier custom-message style as superseded).

## Detailed findings

### Entrypoint and PSK tooling

`run_521d.py` calls `driver_52xd.cli(0x521d)`. Default mode is a read-only probe (no PSK needed); `--live --psk-file FILE` runs live capture, where the PSK file is verified against the device's live hash readback before use (`driver_52xd.py`, `_verify_and_get_psk`). `tools/psk.py` recovers the PSK in one command: sealed blob off the device, DPAPI unseal against `--mount`, `sha256` verified against a fresh device readback, then written `0600`. No hardcoded unit hash exists anywhere; the device is the oracle (`tools/psk_recovery.md`).

### USB, SPI, and message protocol layers

`protocol.py` defines an abstract `Protocol` interface with `write`, `read`, and `disconnect` methods. `USBProtocol` locates and communicates with USB devices; `SPIProtocol` handles SPI transfers. `goodix.py` provides classic Goodix message packing, checksum, ACK, MCU, firmware, register, TLS-request, and PSK command helpers. `wrapless.py` provides another message layer with `Message`, `Device`, and `GTLSContext` abstractions.

### 52xd driver

`driver_52xd.py` carries read-only probing, single-shot capture, and live capture. There is no PSK write, firmware erase, or flash path: the write path was unreachable behind a `raise` and has been removed, and the old `check_psk`/`write_psk`/`erase_firmware`/`update_firmware`/`run_driver`/`main` family-driver skeleton is gone along with the other families. The libsecret lookup is gone too; the PSK comes from a file (`--psk-file`) verified against the device hash readback.

### Image and shared services

`tool.py` contains console warnings, TLS socket connection bridging, PGM image encode/decode helpers, and image file IO. `preprocessor.py` implements crop, threshold, histogram, mean-filter, subtraction, and histogram equalization operations with a CLI. `goodix_fp_dump/archive.py` creates controlled run directories and manifests; `device_info.py` records system and USB preflight facts; `firmware.py` and `safety.py` implement compatibility checks and destructive-operation gates; `image.py` validates image buffers before decoding; `tls_proxy.py` wraps `openssl s_server` lifecycle management; `production.py` and `cli.py` provide the production-read variants probe. Tests under `tests/` cover archive creation, preflight collection, OTP classification, safety gates, firmware compatibility, flash plans, image validation, TLS cleanup, and marker-based hardware/flash/manual skips. Default tests must not require hardware.

### Phase 8 Goodix 521d findings

Windows driver analysis of `Wbdi.dll` shows that `PresetPskReadSpecDataR` sends command `0xe4` with an 8-byte `{selector, 0}` request and expects a response shaped as `status + selector + length + payload`. The older Linux helper sends `length + offset + selector + 0`, so the package includes `read-production-variants` (`goodix_fp_dump/cli.py`) to probe both layouts without printing raw production data. A 2026-05-23 hardware run against `27c6:521d` returned the clean MCU negative `0x01 0x00` for all read variants and selectors; the later finding (2026-09-05) is that the 16-byte request form succeeds under stock `APP_10034`, which is what `tools/psk.py` uses.

The same Windows path has a separate provisioning branch: when PSK validation fails, `PresetPskWriteKey` generates a random 32-byte PSK, stores a host-sealed `0xbb010002` TLV plus a whitebox-encrypted `0xbb010003` TLV through command `0xe0`, then validates by reading `0xbb020001` or `0xbb020007` before setting the in-memory TLS PSK.

### Firmware, logs, and Wireshark helpers

The `firmware/` directory is a submodule containing firmware blobs and metadata. `log/README.md` and `log/goodix_enable_logs.reg` document Windows-side logging artifacts. Lua dissectors in `wireshark/` decode Goodix messages for packet analysis.

## Code references

- `README.md` - setup (uv), run commands, project layout.
- `tools/psk.py` - one-command PSK recovery (device -> DPAPI -> verify -> file).
- `tools/psk_recovery.md` - the recovery walkthrough, chain, and scope warnings.
- `protocol.py` - abstract protocol interface, USB and SPI transports.
- `goodix.py` - classic Goodix `Device` command wrapper.
- `wrapless.py` - wrapless `Device` wrapper and GTLS context.
- `driver_52xd.py` - 52xd driver runtime flow (probe, capture, PSK self-check).
- `goodix_fp_dump/cli.py` - production-read variants probe and other subcommands.

## Open questions

- Hardware-specific execution paths were documented from source plus attended hardware sessions; no automated hardware tests run in CI.

## Phase 4 evidence pointers (redacted, 2026-09-03)

- Windows capture hook points: `tools/windhawk_goodix_winusb_dump.wh.cpp` (`Wbdi!PresetPskPskGet` at `0x78658`, `Wbdi!IoHubExec` at `0x5c550`; `TlsConfPsk` point disabled as unproven). Event log shape: `<capture-dir>\windhawk-winusb\events.jsonl` with command-out/command-in and IOCTL classes; no persistent provisioning records expected for the cached-credential session.
- Linux credential scope: the paired driver is a separate repository, [`LuvHakii/libfprint`](https://github.com/LuvHakii/libfprint). `libfprint/drivers/goodixtls/goodix52xd.c` (`goodix52xd_get_tls_psk`) reads exactly one 32-byte PSK from a root-owned file under fprintd's `StateDirectory` (`/var/lib/fprint/<driver-id>-27c6-521d.psk`) and fails closed on missing, malformed, wrong-length or wrong-mode input; libsecret is unreachable because fprintd runs as root on the system bus with no session. `goodix52xd_policy.h` accepts `GFUSB_GM168SEC_APP_10034` only. Policy tests: `tests/test-goodixtls52xd-policy.c` in that repo.
- Destructive paths: none. libfprint has no persistent PSK, credential-write, or firmware erase/update path, and `driver_52xd.py` no longer carries one. The safety gates in `goodix_fp_dump/safety.py` and `goodix_fp_dump/firmware.py` stay, with their own tests.
