# Goodix FP Dump

Goodix fingerprint sensor research and companion tooling for Linux driver
development. The scripts in this repository are useful for protocol inspection,
diagnostics, firmware metadata handling, image experiments, and Wireshark
analysis. The production Linux runtime work belongs in the paired libfprint
Goodix TLS driver.

Community discussion happens in the Discord channel
[Goodix Fingerprint Linux Development](https://discord.com/invite/6xZ6k34Vqg).

## Current status

This tree is still hardware-facing research software. Default tests and helper
modules are designed to be safe without a sensor attached, but top-level
`run_*.py`, `dump_*.py`, and `flash_*.py` scripts talk directly to devices.
Read the target script before running it.

The 52xd/521d path is kept as a companion diagnostic lane for the libfprint
`goodixtls52xd` driver. Firmware erase, write, update, and flash flows are
opt-in only and require explicit hardware/flash test markers or script-level
confirmation.

## Setup

```sh
git submodule update --init --recursive
python --version # Must be Python 3.10 or newer
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

If you cloned the repository manually, clone with submodules or run the
submodule command above before using firmware-related tooling.

## Running device scripts

Identify the attached Goodix USB product ID:

```sh
sudo lsusb -vd "27c6:" | grep "idProduct"
```

Then choose the matching entrypoint, for example:

```sh
sudo -E .venv/bin/python run_521d.py
```

Use the product ID in the script name where available, such as `run_5110.py`,
`run_521d.py`, `run_538d.py`, `run_5395.py`, or `run_55b4.py`. Dump and flash
entrypoints are more invasive than run entrypoints; do not run `flash_*.py`
unless you have a verified restore path for that exact device.

## Project layout

- `run_<device>.py`, `dump_<device>.py`, and `flash_<device>.py` are hardware
  entrypoints.
- `driver_52xd.py`, `driver_53xd.py`, `driver_53x5.py`, and related modules
  contain legacy device-family flows.
- `goodix_fp_dump/` contains shared archive, preflight, firmware, image,
  safety, production-read, USB-reset, Windows-capture, and TLS helper code.
- `firmware/` is a submodule with firmware data and metadata.
- `wireshark/` contains Goodix protocol dissectors.
- `log/` contains Windows logging helpers, not raw local logs.

## Tests and lint

Default validation avoids hardware, flash, and manual tests:

```sh
python -m pytest -m "not hardware and not flash and not manual"
python -m ruff check .
```

Hardware, flash, and manual tests are intentionally opt-in. Enable them only
when the local sensor is attached, the expected target is selected, and the
operation is acceptable for that machine.

## Data handling

Raw USB captures, firmware dumps, enrolled-print artifacts, biometric images,
and local logs should stay out of git. Keep run artifacts in an untracked
archive directory and scrub logs before sharing them.
