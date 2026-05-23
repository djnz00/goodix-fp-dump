from __future__ import annotations

from datetime import UTC, datetime
import json

import pytest

from goodix_fp_dump.archive import ArchiveRun

pytestmark = pytest.mark.unit


def test_archive_run_creates_expected_layout(tmp_path) -> None:
    archive = ArchiveRun.create(
        tmp_path,
        0x27C6,
        0x521D,
        now=datetime(2026, 5, 23, 12, 0, tzinfo=UTC),
    )

    assert archive.path.name == "20260523T120000Z-27c6-521d"
    assert (archive.path / "original").is_dir()
    assert (archive.path / "captures" / "usbmon").is_dir()
    assert (archive.path / "analysis" / "notes").is_dir()
    assert (archive.path / "restore").is_dir()


def test_write_manifest_is_json_with_schema(tmp_path) -> None:
    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)

    archive.write_manifest({"operation": "preflight"})

    assert json.loads(archive.manifest_path.read_text()) == {
        "operation": "preflight",
        "schema": "goodix-fp-dump-archive-v1",
    }


def test_artifact_record_hashes_file(tmp_path) -> None:
    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    artifact = archive.path / "original" / "blob.bin"
    artifact.write_bytes(b"abc")

    assert archive.artifact_record(artifact) == {
        "path": "original/blob.bin",
        "sha256": ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "size": 3,
        "mtime_ns": artifact.stat().st_mtime_ns,
    }
