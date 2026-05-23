## Summary

Research conducted on 2026-05-23 and refreshed for the `goodix-fp-dump` checkout on branch `stabilize-goodix-interoperability`. No `source.yaml` was present in this repository, so this report uses a fresh repository source inventory of Python, shell, Lua, Markdown, requirements, logs metadata, and firmware submodule metadata. The project is a Python 3.10+ collection of Goodix fingerprint sensor tools. Top-level `run_<device>.py`, `dump_<device>.py`, and `flash_<device>.py` files dispatch into device-family driver modules. Shared legacy transport, protocol, image, and firmware helpers live in `protocol.py`, `goodix.py`, `wrapless.py`, `tool.py`, `preprocessor.py`, `dumper_53x5.py`, and `flasher_53x5.py`; new phase work lives in the `goodix_fp_dump/` package.

## Coding style and conventions

The legacy code uses plain Python modules, while the stabilization branch adds a small `goodix_fp_dump/` package for shared archive, preflight, firmware, image, safety, and TLS-proxy services. Device-family modules are named by product family, such as `driver_52xd.py`, `driver_53x5.py`, and `driver_55x4.py`; entrypoints are thin files named for product IDs, such as `run_521d.py` and `run_5395.py`. Functions use `snake_case`; protocol constants and byte blobs use uppercase names such as `PSK`, `DEVICE_CONFIG`, and `FIRMWARE_CHUNK_SIZE` (`driver_52xd.py:17`, `wrapless.py:15`). New modules use type annotations where useful. Indentation is 4 spaces.

## Detailed Findings

### Entrypoints and device dispatch

The README documents interactive use through product-specific scripts after creating a virtual environment and installing `requirements.txt` (`README.md:11`). `run_521d.py` imports `driver_52xd`, while `run_538d.py` and `run_532d.py` import `driver_53xd`; `run_5395.py` and `run_5385.py` import `driver_53x5`. The scripts provide the device-specific product selection layer and delegate behavior to `main(product)` functions in their driver modules (`driver_52xd.py:314`, `driver_53xd.py:271`, `driver_53x5.py:479`).

### USB, SPI, and message protocol layers

`protocol.py` defines an abstract `Protocol` interface with `write`, `read`, and `disconnect` methods (`protocol.py:10`). `USBProtocol` locates and communicates with USB devices (`protocol.py:29`, `protocol.py:108`, `protocol.py:118`), while `SPIProtocol` handles SPI transfers (`protocol.py:147`, `protocol.py:159`). `goodix.py` provides classic Goodix message packing, checksum, ACK, MCU, firmware, register, TLS-request, and PSK command helpers (`goodix.py:45`, `goodix.py:88`, `goodix.py:146`, `goodix.py:699`, `goodix.py:788`). `wrapless.py` provides another message layer with `Message`, `Device`, and `GTLSContext` abstractions (`wrapless.py:19`, `wrapless.py:74`, `wrapless.py:596`).

### Device-family drivers

Classic family drivers `driver_51x0.py`, `driver_51x0_spi.py`, `driver_51x7.py`, `driver_52xd.py`, `driver_53xd.py`, `driver_5503.py`, and `driver_55x4.py` share a structure: constants for PSK/configuration data, `init_device`, `check_psk`, `write_psk`, `erase_firmware`, `update_firmware`, `run_driver`, and `main` (`driver_52xd.py:46`, `driver_52xd.py:54`, `driver_52xd.py:65`, `driver_52xd.py:76`, `driver_52xd.py:80`, `driver_52xd.py:116`). `driver_53x5.py` uses `wrapless.Device`, dataclass calibration parameters, OTP hash helpers, configuration checksum helpers, base image generation, FDT operations, and finger up/down waits (`driver_53x5.py:97`, `driver_53x5.py:204`, `driver_53x5.py:276`, `driver_53x5.py:365`, `driver_53x5.py:462`).

### Firmware dump, flash, and image tools

`dumper_53x5.py` reads IAP/app firmware, parses flash metadata, dumps OTP, USB PID, and option bytes (`dumper_53x5.py:18`, `dumper_53x5.py:29`, `dumper_53x5.py:50`, `dumper_53x5.py:104`, `dumper_53x5.py:116`). `flasher_53x5.py` provides a firmware update entrypoint (`flasher_53x5.py:8`). `tool.py` contains console warnings, TLS socket connection bridging, PGM image encode/decode helpers, and image file IO (`tool.py:7`, `tool.py:12`, `tool.py:36`, `tool.py:49`, `tool.py:61`). `preprocessor.py` implements crop, threshold, histogram, mean-filter, subtraction, and histogram equalization operations with a CLI (`preprocessor.py:6`, `preprocessor.py:14`, `preprocessor.py:28`, `preprocessor.py:51`, `preprocessor.py:104`).

### Stabilization package and tests

`goodix_fp_dump/archive.py` creates controlled run directories and manifests. `device_info.py` records system and USB preflight facts. `firmware.py` and `safety.py` implement compatibility checks and destructive-operation gates. `image.py` validates image buffers before decoding, and `tls_proxy.py` wraps `openssl s_server` lifecycle management. Tests under `tests/` cover archive creation, preflight collection, OTP classification, safety gates, firmware compatibility, flash plans, image validation, TLS cleanup, and marker-based hardware/flash/manual skips. Default tests must not require hardware.

### Firmware, logs, and Wireshark helpers

The `firmware/` directory is a submodule containing device-family firmware blobs and metadata. `log/README.md` and `log/goodix_enable_logs.reg` document Windows-side logging artifacts. Lua dissectors in `wireshark/` decode Goodix messages for packet analysis; `wireshark/goodix_message.lua` contains protocol command annotations and parsing logic, and `wireshark/wrapless_goodix_message.lua` covers the wrapless message format.

## Code References

- `README.md:11` - Setup and run commands for the tool collection.
- `requirements.txt:1` - Runtime dependencies including `pyusb`, `crcmod`, `python-periphery`, `spidev`, `pycryptodome`, and `crccheck`.
- `protocol.py:10` - Abstract protocol interface.
- `goodix.py:146` - Classic Goodix `Device` command wrapper.
- `wrapless.py:74` - Wrapless `Device` command wrapper.
- `wrapless.py:596` - GTLS context and handshake handling.
- `driver_52xd.py:116` - 52xd driver runtime flow.
- `driver_53x5.py:479` - 53x5 main entrypoint.
- `dumper_53x5.py:18` - 53x5 firmware dump flow.

## Architecture Documentation

The project architecture remains script-driven for compatibility. Product-specific entrypoints choose a driver module and product ID. Driver modules open a transport through `protocol.py`, wrap that transport with either `goodix.Device` or `wrapless.Device`, then execute sensor initialization, PSK checks/writes, firmware operations, configuration upload, FDT scanning, and image handling. New shared services in `goodix_fp_dump/` provide testable archive, preflight, TLS, image, firmware, and safety helpers without moving the legacy entrypoints. The firmware submodule supplies binary inputs used by update and flash flows.

## Open Questions

- `source.yaml` was not present, so no definitive manifest of intended research files was available.
- Hardware-specific execution paths were documented from source only; no device scripts were run.
