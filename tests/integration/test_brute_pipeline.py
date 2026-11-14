from pathlib import Path

import pytest

from ndr.anomaly.report import build_report
from ndr.brute.score import score_brute
from ndr.brute.train import train_brute
from ndr.contracts import DetectionEvent
from ndr.features.brute import BRUTE_FEATURE_NAMES
from ndr.synth.brute import generate_brute_corpus


def test_brute_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"
    report_path = tmp_path / "report.md"

    generate_brute_corpus(synthetic, seed=7)
    metadata = train_brute(synthetic, model, seed=7)

    assert metadata.features == list(BRUTE_FEATURE_NAMES)
    assert len(metadata.training["train_runs"]) == 6
    assert len(metadata.training["val_runs"]) == 3
    assert len(metadata.training["test_runs"]) == 3
    assert metadata.metrics["test_recall"] >= 0.85
    assert metadata.metrics["test_fp_per_day"] <= 10.0
    assert metadata.model_name == "bruteforce_lgbm"

    events = score_brute(synthetic, model, detections_path)
    assert events
    for line in detections_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            DetectionEvent.model_validate_json(line)

    assert all(event.rule.id == "NDR-ML-BRUTE-001" for event in events)
    assert any(
        feature.shap is not None
        for event in events
        for feature in event.top_features
    )

    summary = build_report(
        detections_path,
        synthetic,
        report_path,
        title="D3 brute-force report (synthetic)",
        target_fp_per_day=10.0,
        run_filename="ssh.jsonl",
    )
    assert summary["runs"]["brute-11-attack_mixed_ssh_ftp-mixed"]["detected"]
    assert summary["attack_recall"] == pytest.approx(1.0)

    report_text = report_path.read_text(encoding="utf-8")
    assert "D3 brute-force report" in report_text
    assert "attack_ssh_hydra" in report_text
    assert "FP/day" in report_text
