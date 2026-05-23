from __future__ import annotations

from dataclasses import dataclass, field


DESTRUCTIVE_OPERATIONS = frozenset(
    {
        "erase_firmware",
        "write_firmware",
        "update_firmware",
        "flash_firmware",
        "write_psk",
        "reset_persistent",
    }
)


class DestructiveOperationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SafetyPlan:
    target: str
    allow_write: bool = False
    confirmation: str | None = None
    stock_dump_sha256: str | None = None
    firmware_family: str | None = None
    psk_evidence: bool = False
    operations: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        destructive = sorted(set(self.operations) & DESTRUCTIVE_OPERATIONS)
        if not destructive:
            return
        if not self.allow_write:
            raise DestructiveOperationError(
                f"destructive operations require allow_write: {destructive}"
            )
        if self.confirmation != self.target:
            raise DestructiveOperationError(
                f"confirmation must exactly match target {self.target}"
            )
        if not self.stock_dump_sha256:
            raise DestructiveOperationError("verified stock dump hash is required")
        if not self.firmware_family:
            raise DestructiveOperationError("firmware family is required")
        if not self.psk_evidence:
            raise DestructiveOperationError("PSK/PMK evidence capture is required")


def assert_read_only(operation: str) -> None:
    if operation in DESTRUCTIVE_OPERATIONS:
        raise DestructiveOperationError(f"{operation} is destructive")
