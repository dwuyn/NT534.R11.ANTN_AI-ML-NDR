from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.lab import load_lab_manifest


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _item(
    run_id: str,
    scenario: str,
    *,
    kind: str = "attack",
    start: float = 10.0,
    end: float = 20.0,
    expected: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "scenario": scenario,
        "kind": kind,
        "variant": "lab",
        "start_ts": _utc(start),
        "end_ts": _utc(end),
        "attacker_ip": "192.168.217.132",
        "victim_ip": "192.168.217.129",
        "tool": "test",
        "mitre_tactic": ["TA0007"],
        "mitre_technique": ["T1046"],
        "expected_detection": expected if expected is not None else ["D2"],
        "notes": "",
    }


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_valid_manifest_sorted(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "manifest.json",
        [
            _item("scan-late", "port_scan", start=30.0, end=40.0),
            _item(
                "benign-early",
                "benign_browsing",
                kind="benign",
                start=1.0,
                end=2.0,
                expected=[],
            ),
            _item("brute", "brute_force", expected=["D3"]),
            _item("beacon", "c2_beaconing", expected=["D5"]),
            _item("dns", "dns_tunneling", expected=["D7"]),
        ],
    )

    runs = load_lab_manifest(path)

    assert [run.run_id for run in runs] == [
        "benign-early",
        "beacon",
        "brute",
        "dns",
        "scan-late",
    ]
    assert runs[0].kind == "benign"
    assert runs[2].expected_detection == ["D3"]


@pytest.mark.parametrize(
    ("item", "message"),
    [
        (_item("dup", "port_scan"), "duplicate run_id"),
        (
            _item("../unsafe", "port_scan"),
            "invalid run_id",
        ),
        (
            _item("bad-window", "port_scan", start=20.0, end=20.0),
            "start_ts must be before end_ts",
        ),
        (
            _item("malware", "malware_download", expected=["D1"]),
            "unsupported lab attack scenario",
        ),
        (
            _item("lateral", "lateral_movement", expected=["D1"]),
            "unsupported lab attack scenario",
        ),
        (
            _item("d4", "port_scan", expected=["D4"]),
            "unsupported detector",
        ),
    ],
)
def test_manifest_validation_errors(
    tmp_path: Path, item: dict, message: str
) -> None:
    data = [item]
    if message == "duplicate run_id":
        data.append(item)
    path = _write(tmp_path / "manifest.json", data)

    with pytest.raises(ValueError, match=message):
        load_lab_manifest(path)


def test_manifest_invalid_json_and_missing(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_lab_manifest(invalid)

    with pytest.raises(FileNotFoundError):
        load_lab_manifest(tmp_path / "missing.json")
