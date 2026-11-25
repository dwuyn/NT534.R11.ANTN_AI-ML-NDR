from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import GroundTruthRun
from ndr.lab import prepare_lab_runs


def _run(
    run_id: str,
    start: float,
    end: float,
    *,
    kind: str = "benign",
    scenario: str = "benign_browsing",
) -> GroundTruthRun:
    return GroundTruthRun(
        run_id=run_id,
        scenario=scenario,
        kind=kind,
        variant="test",
        start_ts=datetime.fromtimestamp(start, tz=timezone.utc),
        end_ts=datetime.fromtimestamp(end, tz=timezone.utc),
        tool="test",
    )


def _event(timestamp: float, uid: str) -> str:
    return json.dumps({"ts": timestamp, "uid": uid, "id.orig_h": "10.0.0.1"})


def _read_lines(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_prepare_splits_deduplicates_and_writes_run_manifest(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text(
        "\n".join([_event(10, "C10"), _event(20, "C20"), _event(30, "C30")])
        + "\n",
        encoding="utf-8",
    )
    with gzip.open(raw / "conn.log.gz", "wt", encoding="utf-8") as handle:
        handle.write(_event(20, "C20") + "\n")
    (raw / "dns.log").write_text(_event(15, "D15") + "\n", encoding="utf-8")
    (raw / "ssh.log").write_text(_event(25, "S25") + "\n", encoding="utf-8")

    runs = [_run("a", 10, 20), _run("b", 20, 31)]
    out = tmp_path / "runs"
    paths = prepare_lab_runs([raw], runs, out)

    assert [path.name for path in paths] == ["a", "b"]
    assert [event["ts"] for event in _read_lines(out / "a" / "conn.jsonl")] == [10]
    assert [event["ts"] for event in _read_lines(out / "b" / "conn.jsonl")] == [
        20,
        30,
    ]
    assert [event["ts"] for event in _read_lines(out / "a" / "dns.jsonl")] == [15]
    assert [event["ts"] for event in _read_lines(out / "b" / "ssh.jsonl")] == [25]
    assert _read_lines(out / "a" / "ftp.jsonl") == []

    for run in runs:
        run_dir = out / run.run_id
        for log_type in (
            "conn",
            "dns",
            "ssh",
            "ftp",
            "http",
            "files",
            "ssl",
            "intel",
            "smb_mapping",
            "smb_files",
            "dce_rpc",
        ):
            assert (run_dir / f"{log_type}.jsonl").is_file()
        assert GroundTruthRun.model_validate_json(
            (run_dir / "run.json").read_text(encoding="utf-8")
        ) == run


def test_prepare_rejects_missing_raw_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="raw log directory not found"):
        prepare_lab_runs(
            [tmp_path / "missing"], [_run("a", 10, 20)], tmp_path / "runs"
        )


def test_prepare_rejects_no_supported_logs(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "weird.log").write_text(_event(10, "W10") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no supported Zeek log files"):
        prepare_lab_runs([raw], [_run("a", 10, 20)], tmp_path / "runs")


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ('{"uid": "C1"}\n', "missing or invalid ts"),
        ('{"ts": "bad", "uid": "C1"}\n', "missing or invalid ts"),
        ("{\n", "invalid JSON"),
        ("[]\n", "expected a JSON object"),
    ],
)
def test_prepare_rejects_invalid_raw_event(
    tmp_path: Path, line: str, message: str
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text(line, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        prepare_lab_runs([raw], [_run("a", 10, 20)], tmp_path / "runs")


def test_prepare_rejects_run_without_events_and_rolls_back(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text(_event(1, "C1") + "\n", encoding="utf-8")
    out = tmp_path / "runs"

    with pytest.raises(ValueError, match="no supported events"):
        prepare_lab_runs([raw], [_run("a", 10, 20)], out)

    assert not out.exists()


def test_prepare_rejects_non_empty_output(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "conn.log").write_text(_event(10, "C10") + "\n", encoding="utf-8")
    out = tmp_path / "runs"
    out.mkdir()
    (out / "stale").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="output directory must be empty"):
        prepare_lab_runs([raw], [_run("a", 10, 20)], out)
