from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ndr.runtime import model_dirs_from_root, prepare_live_run


def test_prepare_live_run_accepts_empty_window(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text("", encoding="utf-8")
    out = tmp_path / "runs"
    start = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    end = datetime(2026, 11, 20, 10, 10, tzinfo=UTC)

    run_dir = prepare_live_run([raw], out, start, end)

    assert run_dir == out / f"live-{int(start.timestamp())}"
    assert (run_dir / "run.json").is_file()
    assert (run_dir / "dns.jsonl").is_file()
    assert (run_dir / "smb_mapping.jsonl").is_file()
    assert (run_dir / "smb_mapping.jsonl").read_text(encoding="utf-8") == ""


def test_prepare_live_run_rejects_unaligned_window(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text("", encoding="utf-8")
    start = datetime(2026, 11, 20, 10, 1, tzinfo=UTC)
    end = datetime(2026, 11, 20, 10, 11, tzinfo=UTC)
    with pytest.raises(ValueError, match="aligned"):
        prepare_live_run([raw], tmp_path / "runs", start, end)


def test_model_root_requires_all_detectors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        model_dirs_from_root(tmp_path)
