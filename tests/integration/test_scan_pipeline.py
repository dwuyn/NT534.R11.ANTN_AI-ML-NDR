from __future__ import annotations

from pathlib import Path

from ndr.contracts import DetectionEvent
from ndr.features.scan import SCAN_FEATURE_NAMES
from ndr.scan.score import score_scan
from ndr.scan.train import train_scan
from ndr.synth.scan import generate_scan_corpus


def test_scan_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"

    generate_scan_corpus(synthetic, seed=7)
    metadata = train_scan(synthetic, model, seed=7)

    assert metadata.model_name == "scan_lgbm"
    assert metadata.features == list(SCAN_FEATURE_NAMES)
    assert len(metadata.training["train_runs"]) == 6
    assert len(metadata.training["val_runs"]) == 3
    assert len(metadata.training["test_runs"]) == 3
    assert metadata.metrics["test_recall"] >= 0.85
    assert metadata.metrics["test_fp_per_day"] <= 10.0
    for artifact in ("lgbm.joblib", "calibrator.joblib", "baseline.json", "metadata.json"):
        assert (model / artifact).is_file()

    events = score_scan(synthetic, model, detections_path)
    assert events
    for line in detections_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            DetectionEvent.model_validate_json(line)

    assert any(
        feature.shap is not None
        for event in events
        for feature in event.top_features
    )
    assert any(event.is_alert for event in events)
