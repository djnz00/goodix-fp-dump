from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


def utc_stamp(now: datetime | None = None) -> str:
    now_ = now or datetime.now(UTC)
    return now_.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def product_tag(vendor: int, product: int) -> str:
    return f"{vendor:04x}-{product:04x}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_:
        for chunk in iter(lambda: file_.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class ArchiveRun:
    path: Path

    @classmethod
    def create(
        cls,
        root: Path | str,
        vendor: int,
        product: int,
        now: datetime | None = None,
    ) -> "ArchiveRun":
        root_ = Path(root)
        run = root_ / f"{utc_stamp(now)}-{product_tag(vendor, product)}"
        for directory in (
            run / "original",
            run / "captures" / "usbmon",
            run / "captures" / "tls",
            run / "captures" / "logs",
            run / "derived",
            run / "analysis" / "binwalk",
            run / "analysis" / "ghidra",
            run / "analysis" / "notes",
            run / "restore",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return cls(run)

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.json"

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        manifest_ = {
            "schema": "goodix-fp-dump-archive-v1",
            **manifest,
        }
        self.path.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            "w",
            dir=self.path,
            delete=False,
            encoding="utf-8",
        ) as file_:
            json.dump(manifest_, file_, indent=2, sort_keys=True)
            file_.write("\n")
            tmp = Path(file_.name)
        os.replace(tmp, self.manifest_path)

    def artifact_record(self, path: Path | str) -> dict[str, Any]:
        path_ = Path(path)
        stat = path_.stat()
        return {
            "path": path_.relative_to(self.path).as_posix(),
            "sha256": sha256_file(path_),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }
