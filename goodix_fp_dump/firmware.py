from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .safety import SafetyPlan


class OTPStatus(StrEnum):
    VALID = "valid"
    EMPTY = "empty"
    SHORT = "short"
    MALFORMED = "malformed"
    TRANSIENT_FAILURE = "transient_transport_failure"
    UNSUPPORTED_FORMAT = "unsupported_format"
    INVALID_STATE = "invalid_device_state"
    INCOMPATIBLE = "incompatible_device"


@dataclass(frozen=True, slots=True)
class OTPReadResult:
    status: OTPStatus
    length: int = 0
    data_hex: str | None = None
    error: str | None = None
    metadata: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.status == OTPStatus.VALID

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "length": self.length,
            "data_hex": self.data_hex,
            "error": self.error,
            "metadata": self.metadata or {},
        }


def classify_otp(data: bytes, min_length: int = 64) -> OTPReadResult:
    if len(data) == 0:
        return OTPReadResult(OTPStatus.EMPTY)
    if len(data) < min_length:
        return OTPReadResult(OTPStatus.SHORT, length=len(data), data_hex=data.hex())
    if all(byte == 0x00 for byte in data):
        return OTPReadResult(
            OTPStatus.MALFORMED,
            length=len(data),
            data_hex=data.hex(),
            error="all-zero OTP payload",
        )
    return OTPReadResult(OTPStatus.VALID, length=len(data), data_hex=data.hex())


def classify_otp_error(error: Exception) -> OTPReadResult:
    text = str(error)
    lowered = text.lower()
    if isinstance(error, TimeoutError) or "timeout" in lowered:
        status = OTPStatus.TRANSIENT_FAILURE
    elif "unsupported" in lowered:
        status = OTPStatus.UNSUPPORTED_FORMAT
    elif "state" in lowered:
        status = OTPStatus.INVALID_STATE
    elif "incompatible" in lowered or "not found" in lowered:
        status = OTPStatus.INCOMPATIBLE
    else:
        status = OTPStatus.TRANSIENT_FAILURE
    return OTPReadResult(status, error=text)


class FirmwareCompatibilityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FirmwareFamily:
    name: str
    products: frozenset[int]
    image_dir: str


FIRMWARE_FAMILIES = {
    "51x0": FirmwareFamily("51x0", frozenset({0x5110}), "51x0"),
    "51x7": FirmwareFamily("51x7", frozenset({0x5117}), "51x7"),
    "52xd": FirmwareFamily("52xd", frozenset({0x521D}), "52xd"),
    "53xd": FirmwareFamily("53xd", frozenset({0x532D, 0x538D}), "53xd"),
    "53x5": FirmwareFamily("53x5", frozenset({0x5335, 0x5385, 0x5395, 0x5740}), "53x5"),
    "5503": FirmwareFamily("5503", frozenset({0x5503}), "5503"),
    "55x4": FirmwareFamily("55x4", frozenset({0x55A4, 0x55B4}), "55x4"),
}


def family_for_product(product: int) -> FirmwareFamily:
    for family in FIRMWARE_FAMILIES.values():
        if product in family.products:
            return family
    raise FirmwareCompatibilityError(f"unknown firmware family for {product:04x}")


def validate_product_family(product: int, family_name: str) -> FirmwareFamily:
    family = FIRMWARE_FAMILIES.get(family_name)
    if family is None:
        raise FirmwareCompatibilityError(f"unknown firmware family {family_name}")
    if product not in family.products:
        raise FirmwareCompatibilityError(
            f"product {product:04x} is not compatible with {family_name}"
        )
    return family


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file_:
        for chunk in iter(lambda: file_.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_flash_plan(
    *,
    product: int,
    firmware_family: str,
    target: str,
    stock_dump_sha256: str,
    confirmation: str,
    psk_evidence: bool,
    operations: tuple[str, ...] = ("flash_firmware",),
) -> dict[str, Any]:
    family = validate_product_family(product, firmware_family)
    safety = SafetyPlan(
        target=target,
        allow_write=True,
        confirmation=confirmation,
        stock_dump_sha256=stock_dump_sha256,
        firmware_family=family.name,
        psk_evidence=psk_evidence,
        operations=operations,
    )
    safety.validate()
    return {
        "product": f"{product:04x}",
        "firmware_family": family.name,
        "image_dir": family.image_dir,
        "operations": list(operations),
        "stock_dump_sha256": stock_dump_sha256,
    }
