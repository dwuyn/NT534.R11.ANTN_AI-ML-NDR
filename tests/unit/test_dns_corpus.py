from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.dns import generate_dns_corpus


def _runs(root: Path) -> list[tuple[Path, GroundTruthRun]]:
    returns: list[tuple[Path, GroundTruthRun]] = []
    for path in sorted(root.glob("*/run.json")):
        returns.append(
            (
                path.parent,
                GroundTruthRun.model_validate_json(
                    path.read_text(encoding="utf-8")
                ),
            )
        )
    return returns


def test_dns_corpus_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_dns_corpus(first, seed=7)
    generate_dns_corpus(second, seed=7)

    for run_dir, run in _runs(first):
        counterpart = second / run_dir.name
        assert (run_dir / "dns.jsonl").read_bytes() == (
            counterpart / "dns.jsonl"
        ).read_bytes()
        assert (run_dir / "run.json").read_bytes() == (
            counterpart / "run.json"
        ).read_bytes()
        assert run.run_id == run_dir.name


def test_dns_corpus_labels(tmp_path: Path) -> None:
    generate_dns_corpus(tmp_path, seed=7)
    runs = _runs(tmp_path)
    assert len(runs) == 12

    attacks = [run for _, run in runs if run.kind == "attack"]
    benign = [run for _, run in runs if run.kind == "benign"]
    assert len(attacks) == 6
    assert len(benign) == 6
    for run in attacks:
        assert run.attacker_ip == "192.168.217.132"
        assert run.expected_detection == ["D7"]
        assert run.tool == "synthetic_dns_tunnel"
    for run in benign:
        assert run.attacker_ip is None
        assert run.expected_detection == []
