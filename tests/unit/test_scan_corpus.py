from __future__ import annotations

import math
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.scan import generate_scan_corpus
from ndr.zeek import iter_conn_jsonl


def _conn_bytes(root: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("conn.jsonl"))
    }


def test_scan_corpus_is_deterministic(tmp_path: Path) -> None:
    first = generate_scan_corpus(tmp_path / "a", seed=7)
    second = generate_scan_corpus(tmp_path / "b", seed=7)
    assert len(first) == len(second) == 12
    assert _conn_bytes(tmp_path / "a") == _conn_bytes(tmp_path / "b")


def test_scan_corpus_ground_truth(tmp_path: Path) -> None:
    generate_scan_corpus(tmp_path / "runs", seed=7)
    runs = [
        GroundTruthRun.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted((tmp_path / "runs").glob("*/run.json"))
    ]
    assert len(runs) == 12
    attacks = [run for run in runs if run.kind == "attack"]
    benign = [run for run in runs if run.kind == "benign"]
    assert len(attacks) == 6
    assert len(benign) == 6
    for run in attacks:
        assert run.attacker_ip == "192.168.217.132"
        assert run.expected_detection == ["D2"]
        assert run.mitre_tactic == ["TA0007"]
        assert run.mitre_technique == ["T1046"]
        assert run.tool == "synthetic_scan"
        assert run.victim_ip == "192.168.217.129"
    for run in benign:
        assert run.attacker_ip is None
        assert run.expected_detection == []


def test_scan_attack_runs_have_labelable_windows(tmp_path: Path) -> None:
    generate_scan_corpus(tmp_path / "runs", seed=7)
    for run_path in sorted((tmp_path / "runs").glob("*/run.json")):
        run = GroundTruthRun.model_validate_json(
            run_path.read_text(encoding="utf-8")
        )
        if run.kind != "attack":
            continue
        records = list(iter_conn_jsonl(run_path.parent / "conn.jsonl"))
        assert records
        assert {record.orig_h for record in records} == {run.attacker_ip}
        windows: dict[float, int] = {}
        for record in records:
            start = math.floor(record.ts / 300) * 300
            windows[start] = windows.get(start, 0) + 1
        assert max(windows.values()) >= 10
