from __future__ import annotations

from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.generate import generate


def _conn_bytes(root: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("conn.jsonl"))
    }


def test_generator_is_deterministic(tmp_path: Path) -> None:
    first = generate(
        tmp_path / "a", seed=7, benign_runs=2, attack_runs=2, benign_minutes=10
    )
    second = generate(
        tmp_path / "b", seed=7, benign_runs=2, attack_runs=2, benign_minutes=10
    )
    assert len(first) == len(second) == 4
    assert _conn_bytes(tmp_path / "a") == _conn_bytes(tmp_path / "b")


def test_ground_truth_fields(tmp_path: Path) -> None:
    generate(
        tmp_path / "runs", seed=7, benign_runs=2, attack_runs=2, benign_minutes=10
    )
    runs = [
        GroundTruthRun.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted((tmp_path / "runs").glob("*/run.json"))
    ]
    assert len(runs) == 4
    for run in runs:
        if run.kind == "attack":
            assert run.attacker_ip == "192.168.217.132"
            assert run.expected_detection == ["D1"]
        else:
            assert run.attacker_ip is None
