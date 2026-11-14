from pathlib import Path

from ndr.anomaly.score import score
from ndr.anomaly.train import train
from ndr.beacon.score import score_beacon
from ndr.beacon.train import train_beacon
from ndr.contracts import AlertEvent
from ndr.dns.score import score_dns
from ndr.dns.train import train_dns
from ndr.risk.engine import (
    build_alerts,
    demo_enrichment,
    load_detections,
    risk_level,
    write_alerts,
)
from ndr.risk.report import build_risk_report
from ndr.synth.beacon import generate_beacon_corpus
from ndr.synth.dns import generate_dns_corpus
from ndr.synth.generate import generate


def test_risk_pipeline_end_to_end(tmp_path: Path) -> None:
    detections_dir = tmp_path / "detections"

    generate(
        out_dir=tmp_path / "d1" / "synthetic",
        seed=42,
        benign_runs=4,
        attack_runs=4,
        benign_minutes=60,
    )
    train(
        input_dir=tmp_path / "d1" / "synthetic",
        out_dir=tmp_path / "d1" / "model",
        seed=42,
    )
    score(
        input_dir=tmp_path / "d1" / "synthetic",
        model_dir=tmp_path / "d1" / "model",
        out_path=detections_dir / "anomaly.jsonl",
    )

    generate_beacon_corpus(out_dir=tmp_path / "d5" / "synthetic", seed=42)
    train_beacon(
        input_dir=tmp_path / "d5" / "synthetic",
        out_dir=tmp_path / "d5" / "model",
        seed=42,
    )
    score_beacon(
        input_dir=tmp_path / "d5" / "synthetic",
        model_dir=tmp_path / "d5" / "model",
        out_path=detections_dir / "beacon.jsonl",
    )

    generate_dns_corpus(out_dir=tmp_path / "d7" / "synthetic", seed=42)
    train_dns(
        input_dir=tmp_path / "d7" / "synthetic",
        out_dir=tmp_path / "d7" / "model",
        seed=42,
    )
    score_dns(
        input_dir=tmp_path / "d7" / "synthetic",
        model_dir=tmp_path / "d7" / "model",
        out_path=detections_dir / "dns.jsonl",
    )

    alerts = build_alerts(load_detections(detections_dir), demo_enrichment())
    alerts_path = tmp_path / "alerts.jsonl"
    write_alerts(alerts, alerts_path)

    assert alerts
    for line in alerts_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            AlertEvent.model_validate_json(line)
    for alert in alerts:
        assert alert.mitre.tactic
        assert alert.mitre.technique
        assert alert.reasons
        assert alert.count >= 1
        assert alert.first_seen <= alert.last_seen
        assert risk_level(alert.risk) == alert.level

    report_path = tmp_path / "report.md"
    summary = build_risk_report(alerts_path, detections_dir, report_path)
    assert summary["reduction"] >= 0.5
    assert summary["mitre_coverage"] == 1.0
    assert sum(summary["levels"].values()) == summary["fused_alerts"]
    assert summary["anomaly_detections"] >= 1

    report_text = report_path.read_text(encoding="utf-8")
    for needle in (
        "D8 risk fusion report",
        "c2_beaconing",
        "dns_tunneling",
        "Reduction",
        "MITRE coverage",
    ):
        assert needle in report_text
