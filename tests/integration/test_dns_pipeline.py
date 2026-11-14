from pathlib import Path

import pytest

from ndr.anomaly.report import build_report
from ndr.contracts import DetectionEvent
from ndr.dns.score import score_dns
from ndr.dns.train import train_dns
from ndr.features.dns import DNS_FEATURE_NAMES
from ndr.synth.dns import generate_dns_corpus


def test_dns_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"
    report_path = tmp_path / "report.md"

    generate_dns_corpus(synthetic, seed=7)
    metadata = train_dns(synthetic, model, seed=7)

    assert metadata.features == list(DNS_FEATURE_NAMES)
    assert len(metadata.training["train_runs"]) == 6
    assert len(metadata.training["val_runs"]) == 3
    assert len(metadata.training["test_runs"]) == 3
    assert metadata.metrics["test_recall"] >= 0.85
    assert metadata.metrics["test_fp_per_day"] <= 10.0

    events = score_dns(synthetic, model, detections_path)
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
        title="D7 DNS tunneling report (synthetic)",
        target_fp_per_day=10.0,
        run_filename="dns.jsonl",
    )
    assert summary["runs"]["dns-11-attack_dns_mixed-1qps"]["detected"]
    assert summary["attack_recall"] == pytest.approx(1.0)

    report_text = report_path.read_text(encoding="utf-8")
    assert "D7 DNS tunneling report" in report_text
    assert "attack_dns_slow" in report_text
    assert "FP/day" in report_text
