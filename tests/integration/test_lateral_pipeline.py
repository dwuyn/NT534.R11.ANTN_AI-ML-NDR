from pathlib import Path

import pytest

from ndr.anomaly.report import build_report
from ndr.contracts import DetectionEvent
from ndr.features.lateral import LATERAL_FEATURE_NAMES
from ndr.lateral.score import score_lateral
from ndr.lateral.train import train_lateral
from ndr.synth.lateral import generate_lateral_corpus


def test_lateral_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"
    report_path = tmp_path / "report.md"

    generate_lateral_corpus(synthetic, seed=7)
    metadata = train_lateral(synthetic, model, seed=7)

    assert metadata.features == list(LATERAL_FEATURE_NAMES)
    assert len(metadata.training["train_runs"]) == 6
    assert len(metadata.training["val_runs"]) == 3
    assert len(metadata.training["test_runs"]) == 3
    assert metadata.metrics["test_recall"] >= 0.85
    assert metadata.metrics["test_fp_per_day"] <= 10.0

    events = score_lateral(synthetic, model, detections_path)
    assert events
    for line in detections_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            DetectionEvent.model_validate_json(line)

    assert any(
        feature.shap is not None
        for event in events
        for feature in event.top_features
    )

    summary = build_report(
        detections_path,
        synthetic,
        report_path,
        title="D6 lateral movement report (synthetic)",
        target_fp_per_day=10.0,
        run_filename="smb_mapping.jsonl",
    )
    assert summary["attack_recall"] == pytest.approx(1.0)
    report_text = report_path.read_text(encoding="utf-8")
    assert "D6 lateral movement report" in report_text
    assert "FP/day" in report_text
