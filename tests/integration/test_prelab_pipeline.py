from __future__ import annotations

from pathlib import Path

from ndr.prelab import run_prelab
from ndr.risk.engine import load_alerts


def test_prelab_pipeline_end_to_end(tmp_path: Path) -> None:
    summary = run_prelab(tmp_path, seed=42)

    detectors = summary["detectors"]
    for name in ("D2", "D3", "D4", "D6", "D5", "D7"):
        assert name in detectors
        assert detectors[name]["attack_recall"] >= 0.85
        assert detectors[name]["test_fp_per_day"] <= 10.0
        assert detectors[name]["detections"] > 0

    risk = summary["risk"]
    assert risk["fused_alerts"] > 0
    assert risk["reduction"] >= 0.5
    assert risk["mitre_coverage"] == 1.0

    triage = summary["triage"]
    high_critical = [
        alert
        for alert in load_alerts(tmp_path / "alerts.jsonl")
        if alert.level in {"high", "critical"}
    ]
    assert triage["count"] == len(high_critical)
    assert triage["count"] > 0
    assert triage["schema_valid_rate"] == 1.0
    assert triage["mitre_accuracy"] == 1.0
    assert triage["hallucination_rate"] == 0.0

    response = summary["response"]
    assert response["allowed"] >= 1
    assert response["denied"] >= 1

    report = (tmp_path / "prelab.md").read_text(encoding="utf-8")
    for token in ("D2", "D3", "D4", "D6", "Reduction", "Triage", "Response"):
        assert token in report
