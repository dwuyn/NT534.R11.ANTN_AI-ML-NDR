from __future__ import annotations

from pathlib import Path

import pytest

from ndr.anomaly.report import build_report
from ndr.beacon.score import score_beacon
from ndr.beacon.train import train_beacon
from ndr.contracts import DetectionEvent
from ndr.features.beacon import BEACON_FEATURE_NAMES
from ndr.synth.beacon import generate_beacon_corpus


def test_beacon_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"
    report_path = tmp_path / "report.md"

    generate_beacon_corpus(synthetic, seed=7)
    metadata = train_beacon(synthetic, model, seed=7)

    assert metadata.features == list(BEACON_FEATURE_NAMES)
    assert len(metadata.training["train_runs"]) == 7
    assert len(metadata.training["val_runs"]) == 2
    assert len(metadata.training["test_runs"]) == 3
    assert metadata.metrics["test_recall"] >= 0.85
    assert metadata.metrics["test_fp_per_day"] <= 10.0

    events = score_beacon(synthetic, model, detections_path)
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
        title="D5 beaconing report (synthetic)",
        target_fp_per_day=10.0,
    )
    assert summary["runs"]["beacon-10-attack_beacon_60s_jitter35-jitter35"]["detected"]
    assert summary["attack_recall"] == pytest.approx(1.0)

    report_text = report_path.read_text(encoding="utf-8")
    assert "D5 beaconing report" in report_text
    assert "attack_beacon_60s_jitter35" in report_text
    assert "FP/day" in report_text
