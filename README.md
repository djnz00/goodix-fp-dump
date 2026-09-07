# Goodix FP Dump

Goodix fingerprint sensor research and companion tooling for Linux driver
development. The scripts in this repository are useful for protocol inspection,
diagnostics, firmware metadata handling, image experiments, and Wireshark
analysis. The production Linux runtime work belongs in the paired libfprint
Goodix TLS driver.

Community discussion happens in the Discord channel
[Goodix Fingerprint Linux Development](https://discord.com/invite/6xZ6k34Vqg).

## Current status

This tree is hardware-facing research software, targeting the 521d
(`27c6:521d`, stock `APP_10034`) only. The production Linux runtime belongs to
the paired libfprint `goodixtls52xd` driver.

## Setup

```sh
git submodule update --init --recursive
uv sync          # Python 3.10+ and uv required
```

`uv sync` creates the project environment from `pyproject.toml` + `uv.lock`
and installs everything, including dev tools. Run anything with `uv run
<command>`.

## Running device scripts

Identify the attached Goodix USB product ID:

```sh
sudo lsusb -vd "27c6:" | grep "idProduct"
```

Then choose the matching entrypoint:

```sh
sudo -E uv run run_521d.py            # read-only probe (default)
sudo -E uv run run_521d.py --live --psk-file /path/to/psk.bin   # live capture
```

This tree targets the 521d only (`27c6:521d`, stock `APP_10034`).

## Project layout

- `run_521d.py` is the hardware entrypoint; `driver_52xd.py` the driver flow.
- `goodix_fp_dump/` contains shared archive, preflight, firmware, image,
  safety, production-read, USB-reset, Windows-capture, and TLS helper code.
- `firmware/` is a submodule with firmware data and metadata.
- `wireshark/` contains Goodix protocol dissectors.
- `log/` contains Windows logging helpers, not raw local logs.
- `tools/windhawk_goodix_winusb_dump.wh.cpp` and
  `tools/windhawk-goodix-capture.md` document the Windhawk/WBDI capture path
  used to inspect the Windows driver and capture the stock 52xd/10034 TLS PSK
  into an archive.
- `tools/psk.py` recovers the 521d TLS PSK in one command (device blob ->
  DPAPI unseal -> device-hash verify -> file). The 521d ships
  Windows-provisioned with a random PSK, so it cannot be provisioned from a
  hardcoded constant. `tools/psk_recovery.md` is the walkthrough and records the
  scope warning; read it first.

## Tests and lint

Default validation avoids hardware, flash, and manual tests:

```sh
uv run pytest -m "not hardware and not flash and not manual"
uv run ruff check .
```

Hardware, flash, and manual tests are intentionally opt-in. Enable them only
when the local sensor is attached, the expected target is selected, and the
operation is acceptable for that machine.

## Data handling

Raw USB captures, firmware dumps, enrolled-print artifacts, biometric images,
and local logs should stay out of git. Keep run artifacts in an untracked
archive directory and scrub logs before sharing them.

## Credits

- [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev): the original
  `goodix-fp-dump` this tree forks. The USB protocol core and the image
  preprocessor.
- [djnz00](https://github.com/djnz00): the `goodix_fp_dump/` package.
  Archive handling, production reads, TLS probe and proxy, Windows capture,
  firmware metadata, USB reset, and the safety gates.
- [impacket](https://github.com/fortra/impacket): DPAPI blob and LSA secret
  decryption behind `tools/psk.py`.
- [lbssousa](https://github.com/lbssousa): the SIGFM matcher implementation
  (`libfprint/sigfm/`, from `goodix-538d-sigfm-gtls`), vendored and wired into
  the paired libfprint driver.
- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint): the driver
  framework the production runtime targets.
- [Windhawk](https://windhawk.net): mod format and hooking API for the WBDI
  capture path.
