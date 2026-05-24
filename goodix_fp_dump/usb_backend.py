from __future__ import annotations

from typing import Any

import usb.backend.libusb1


def libusb_library_path() -> str | None:
    try:
        import libusb_package
    except ImportError:
        return None

    return libusb_package.find_library("libusb-1.0")


def get_libusb_backend() -> Any:
    library_path = libusb_library_path()
    if library_path is None:
        return usb.backend.libusb1.get_backend()

    def find_library(candidate: str) -> str | None:
        try:
            import libusb_package
        except ImportError:
            return None

        return libusb_package.find_library(candidate) or library_path

    return usb.backend.libusb1.get_backend(find_library=find_library)


def backend_info() -> dict[str, Any]:
    library_path = libusb_library_path()
    backend = get_libusb_backend()
    return {
        "library_path": library_path,
        "available": backend is not None,
        "backend_type": type(backend).__name__ if backend is not None else None,
    }
