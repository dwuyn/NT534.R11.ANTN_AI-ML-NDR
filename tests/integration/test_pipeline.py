from __future__ import annotations

from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.anomaly.train import discover_runs, train
from ndr.contracts import DetectionEvent
from ndr.features.baseline import load_profile
from ndr.features.conn import FEATURE_NAMES, build_snapshots
from ndr.synth.generate import generate
from ndr.zeek import iter_conn_jsonl


def test_synthetic_pipeline_end_to_end(tmp_path: Path) -> None:
    synthetic = tmp_path / "synth"
    model = tmp_path / "model"
    detections_path = tmp_path / "detections.jsonl"
    report_path = tmp_path / "report.md"

    generate(
        synthetic,
        seed=7,
        benign_runs=4,
        attack_runs=4,
        benign_minutes=30,
    )
    metadata = train(synthetic, model, seed=7)
    assert metadata.features == list(FEATURE_NAMES)
    assert metadata.training["windows"] >= 100

    events = score(synthetic, model, detections_path)
    assert len(events) >= 100

    lines = [
        line
        for line in detections_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == len(events)
    for line in lines:
        DetectionEvent.model_validate_json(line)

    baseline = load_profile(model / "baseline.json")
    expected_snapshots = 0
    for _, conn_path in discover_runs(synthetic):
        expected_snapshots += len(
            build_snapshots(list(iter_conn_jsonl(conn_path)), baseline)
        )
    assert len(events) == expected_snapshots

    summary = build_report(detections_path, synthetic, report_path)
    assert summary["runs"]["lab-04-attack_fast_scan-vertical_200_ports"]["detected"]
    assert summary["runs"]["lab-07-attack_exfil-burst_20_conns"]["detected"]

    benign_windows = 0
    benign_alerts = 0
    for run, _ in discover_runs(synthetic):
        if run.kind != "benign":
            continue
        overlaps = [
            event
            for event in events
            if event.window.start < run.end_ts and event.window.end > run.start_ts
        ]
        benign_windows += len(overlaps)
        benign_alerts += sum(1 for event in overlaps if event.is_alert)
    assert benign_windows > 0
    assert benign_alerts / benign_windows < 0.10

    report_text = report_path.read_text(encoding="utf-8")
    assert "attack_fast_scan" in report_text
    assert "attack_exfil" in report_text
    assert "FP/day" in report_text
