from __future__ import annotations

import importlib.metadata as metadata
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import usb.core

from .usb_backend import backend_info, get_libusb_backend


WINDOWS_TOOL_CANDIDATES = {
    "git": [r"C:\Program Files\Git\cmd\git.exe"],
    "openssl": [
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
    ],
    "tshark": [r"C:\Program Files\Wireshark\tshark.exe"],
    "USBPcapCMD": [r"C:\Program Files\USBPcap\USBPcapCMD.exe"],
}


def resolve_tool(name: str) -> str:
    found = shutil.which(name)
    if found and Path(found).suffix.lower() == ".exe":
        return found
    if sys.platform == "win32":
        for candidate in WINDOWS_TOOL_CANDIDATES.get(name, []):
            if Path(candidate).exists():
                return candidate
    return found or name


def run_command(args: list[str], timeout: float = 5) -> dict[str, Any]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        return {
            "command": args,
            "missing": True,
            "error": str(error),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": args,
            "timeout": timeout,
            "stdout": error.stdout,
            "stderr": error.stderr,
        }

    return {
        "command": args,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def package_versions(names: list[str]) -> dict[str, str | None]:
    versions = {}
    for name in names:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def repo_commit(path: Path | str) -> dict[str, Any]:
    path_ = Path(path)
    git = resolve_tool("git")
    head = run_command([git, "-C", str(path_), "rev-parse", "HEAD"])
    branch = run_command([git, "-C", str(path_), "branch", "--show-current"])
    dirty = run_command([git, "-C", str(path_), "status", "--short"])
    return {
        "path": str(path_),
        "head": head.get("stdout") if head.get("returncode") == 0 else None,
        "branch": branch.get("stdout") if branch.get("returncode") == 0 else None,
        "dirty": dirty.get("stdout", ""),
    }


def usb_device_info(vendor: int, product: int) -> dict[str, Any]:
    info: dict[str, Any] = {
        "vendor_id": f"{vendor:04x}",
        "product_id": f"{product:04x}",
        "found": False,
    }
    device = usb.core.find(
        idVendor=vendor,
        idProduct=product,
        backend=get_libusb_backend(),
    )
    if device is None:
        return info

    info.update(
        {
            "found": True,
            "bus": getattr(device, "bus", None),
            "address": getattr(device, "address", None),
            "manufacturer": _safe_attr(device, "manufacturer"),
            "product": _safe_attr(device, "product"),
            "active_kernel_drivers": _active_kernel_drivers(device),
        }
    )
    return info


def collect_preflight(
    vendor: int,
    product: int,
    command_path: str,
    repo_root: Path | str,
) -> dict[str, Any]:
    repo_root_ = Path(repo_root)
    parent = repo_root_.parent
    libfprint = parent / "libfprint"
    repos = {"goodix-fp-dump": repo_commit(repo_root_)}
    if libfprint.exists():
        repos["libfprint"] = repo_commit(libfprint)

    return {
        "command_path": command_path,
        "platform": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "system": platform.system(),
        },
        "python": {
            "executable": sys.executable,
            "version": sys.version,
            "packages": package_versions(
                [
                    "pyusb",
                    "libusb-package",
                    "crcmod",
                    "python-periphery",
                    "spidev",
                    "pycryptodome",
                    "crccheck",
                ]
            ),
        },
        "tools": {
            "lsusb": run_command(
                [resolve_tool("lsusb"), "-d", f"{vendor:04x}:{product:04x}"]
            ),
            "openssl": run_command([resolve_tool("openssl"), "version"]),
            "tshark": run_command([resolve_tool("tshark"), "--version"], timeout=10),
            "USBPcapCMD": run_command([resolve_tool("USBPcapCMD"), "--help"]),
        },
        "pyusb_backend": backend_info(),
        "usb": usb_device_info(vendor, product),
        "repos": repos,
    }


def _safe_attr(obj: object, name: str) -> Any:
    try:
        return getattr(obj, name)
    except Exception as error:  # USB string descriptors can fail on permissions.
        return {"error": str(error)}


def _active_kernel_drivers(device: object) -> list[dict[str, Any]]:
    try:
        config = device.get_active_configuration()
    except Exception as error:
        return [{"error": str(error)}]

    drivers = []
    for interface in config:
        number = getattr(interface, "bInterfaceNumber", None)
        try:
            active = device.is_kernel_driver_active(number)
        except Exception as error:
            active = {"error": str(error)}
        drivers.append(
            {
                "interface": number,
                "active": active,
            }
        )
    return drivers
