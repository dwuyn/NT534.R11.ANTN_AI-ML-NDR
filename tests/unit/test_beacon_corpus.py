from __future__ import annotations

from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.beacon import generate_beacon_corpus


def _conn_bytes(root: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("conn.jsonl"))
    }


def test_beacon_corpus_is_deterministic(tmp_path: Path) -> None:
    first = generate_beacon_corpus(tmp_path / "a", seed=7)
    second = generate_beacon_corpus(tmp_path / "b", seed=7)
    assert len(first) == len(second) == 12
    assert _conn_bytes(tmp_path / "a") == _conn_bytes(tmp_path / "b")


def test_beacon_corpus_ground_truth(tmp_path: Path) -> None:
    generate_beacon_corpus(tmp_path / "runs", seed=7)
    runs = [
        GroundTruthRun.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted((tmp_path / "runs").glob("*/run.json"))
    ]
    assert len(runs) == 12
    for run in runs:
        if run.kind == "attack":
            assert run.attacker_ip == "192.168.217.132"
            assert run.expected_detection == ["D5"]
        else:
            assert run.attacker_ip is None
            assert run.expected_detection == []
