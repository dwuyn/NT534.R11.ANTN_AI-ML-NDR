from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.brute import generate_brute_corpus


def _runs(root: Path) -> list[tuple[Path, GroundTruthRun]]:
    found: list[tuple[Path, GroundTruthRun]] = []
    for path in sorted(root.glob("*/run.json")):
        found.append(
            (
                path.parent,
                GroundTruthRun.model_validate_json(
                    path.read_text(encoding="utf-8")
                ),
            )
        )
    return found


def test_brute_corpus_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_brute_corpus(first, seed=7)
    generate_brute_corpus(second, seed=7)

    for run_dir, run in _runs(first):
        counterpart = second / run_dir.name
        for filename in ("conn.jsonl", "ssh.jsonl", "ftp.jsonl", "run.json"):
            assert (run_dir / filename).read_bytes() == (
                counterpart / filename
            ).read_bytes()
        assert run.run_id == run_dir.name


def test_brute_corpus_labels(tmp_path: Path) -> None:
    generate_brute_corpus(tmp_path, seed=7)
    runs = _runs(tmp_path)
    assert len(runs) == 12

    attacks = [run for _, run in runs if run.kind == "attack"]
    benign = [run for _, run in runs if run.kind == "benign"]
    assert len(attacks) == 6
    assert len(benign) == 6

    for run_dir, _ in runs:
        for filename in ("conn.jsonl", "ssh.jsonl", "ftp.jsonl"):
            assert (run_dir / filename).is_file()

    for run in attacks:
        assert run.attacker_ip == "192.168.217.132"
        assert run.expected_detection == ["D3"]
        assert run.tool == "synthetic_brute"
        assert run.mitre_tactic == ["TA0006"]
        assert run.mitre_technique == ["T1110"]
    for run in benign:
        assert run.attacker_ip is None
        assert run.expected_detection == []
