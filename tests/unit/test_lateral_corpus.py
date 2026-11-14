from __future__ import annotations

from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.lateral import generate_lateral_corpus

LOG_NAMES = ("conn.jsonl", "smb_mapping.jsonl", "smb_files.jsonl", "dce_rpc.jsonl")


def _runs(root: Path) -> list[tuple[Path, GroundTruthRun]]:
    runs: list[tuple[Path, GroundTruthRun]] = []
    for path in sorted(root.glob("*/run.json")):
        runs.append(
            (
                path.parent,
                GroundTruthRun.model_validate_json(
                    path.read_text(encoding="utf-8")
                ),
            )
        )
    return runs


def test_lateral_corpus_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_lateral_corpus(first, seed=7)
    generate_lateral_corpus(second, seed=7)

    first_runs = _runs(first)
    second_runs = _runs(second)
    assert len(first_runs) == len(second_runs) == 12
    for run_dir, run in first_runs:
        counterpart = second / run_dir.name
        assert run.run_id == run_dir.name
        for name in (*LOG_NAMES, "run.json"):
            assert (run_dir / name).read_bytes() == (
                counterpart / name
            ).read_bytes()


def test_lateral_corpus_labels(tmp_path: Path) -> None:
    generate_lateral_corpus(tmp_path, seed=7)
    runs = _runs(tmp_path)
    assert len(runs) == 12

    attacks = [run for _, run in runs if run.kind == "attack"]
    benign = [run for _, run in runs if run.kind == "benign"]
    assert len(attacks) == 6
    assert len(benign) == 6

    for run_dir, run in runs:
        for name in LOG_NAMES:
            assert (run_dir / name).is_file()

    for run in attacks:
        assert run.attacker_ip == "192.168.217.132"
        assert run.expected_detection == ["D6"]
        assert run.tool == "synthetic_lateral"
        assert run.mitre_tactic == ["TA0008", "TA0002"]
        assert run.mitre_technique == ["T1021.002", "T1569.002"]

    for run in benign:
        assert run.attacker_ip is None
        assert run.expected_detection == []
