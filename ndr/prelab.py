"""Run the full synthetic pre-lab NDR pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.anomaly.train import train
from ndr.beacon.score import score_beacon
from ndr.beacon.train import train_beacon
from ndr.brute.score import score_brute
from ndr.brute.train import train_brute
from ndr.contracts import ModelMetadata
from ndr.dns.score import score_dns
from ndr.dns.train import train_dns
from ndr.llm.eval import summarize_triage
from ndr.llm.provider import MockProvider
from ndr.llm.triage import triage_alerts
from ndr.lateral.score import score_lateral
from ndr.lateral.train import train_lateral
from ndr.malware.score import score_malware
from ndr.malware.train import train_malware
from ndr.response.engine import ResponseSimulator, decide_response
from ndr.response.policy import ResponsePolicy
from ndr.risk.engine import (
    build_alerts,
    demo_enrichment,
    load_detections,
    write_alerts,
)
from ndr.risk.report import build_risk_report
from ndr.scan.score import score_scan
from ndr.scan.train import train_scan
from ndr.synth.beacon import generate_beacon_corpus
from ndr.synth.brute import generate_brute_corpus
from ndr.synth.dns import generate_dns_corpus
from ndr.synth.generate import generate
from ndr.synth.lateral import generate_lateral_corpus
from ndr.synth.malware import generate_malware_corpus
from ndr.synth.scan import generate_scan_corpus

TARGET_FP_PER_DAY = 10.0


def _metadata(out_dir: Path) -> ModelMetadata:
    return ModelMetadata.model_validate_json(
        (out_dir / "metadata.json").read_text(encoding="utf-8")
    )


def _detector_entry(
    detections: list,
    report: dict,
    model_dir: Path,
) -> dict[str, float | int]:
    metrics = _metadata(model_dir).metrics
    fp_per_day = metrics.get("test_fp_per_day", report["benign_fp_per_day"])
    return {
        "attack_recall": float(report["attack_recall"]),
        "test_fp_per_day": float(fp_per_day),
        "detections": len(detections),
    }


def run_prelab(workdir: Path, seed: int = 42) -> dict:
    workdir = Path(workdir)
    detection_dir = workdir / "detections"
    detection_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = workdir / "reports"
    audit_dir = workdir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    detectors: dict[str, dict] = {}

    d1_synth = workdir / "d1" / "synthetic"
    d1_model = workdir / "d1" / "model"
    d1_det = detection_dir / "anomaly.jsonl"
    generate(out_dir=d1_synth, seed=seed, benign_runs=4, attack_runs=4)
    train(input_dir=d1_synth, out_dir=d1_model, seed=seed)
    d1_events = score(input_dir=d1_synth, model_dir=d1_model, out_path=d1_det)
    d1_report = build_report(
        detections_path=d1_det,
        input_dir=d1_synth,
        out_path=reports_dir / "d1.md",
        title="D1 anomaly report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
    )
    detectors["D1"] = _detector_entry(d1_events, d1_report, d1_model)

    d2_synth = workdir / "d2" / "synthetic"
    d2_model = workdir / "d2" / "model"
    d2_det = detection_dir / "scan.jsonl"
    generate_scan_corpus(out_dir=d2_synth, seed=seed)
    train_scan(input_dir=d2_synth, out_dir=d2_model, seed=seed)
    d2_events = score_scan(input_dir=d2_synth, model_dir=d2_model, out_path=d2_det)
    d2_report = build_report(
        detections_path=d2_det,
        input_dir=d2_synth,
        out_path=reports_dir / "d2.md",
        title="D2 scan report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
    )
    detectors["D2"] = _detector_entry(d2_events, d2_report, d2_model)

    d3_synth = workdir / "d3" / "synthetic"
    d3_model = workdir / "d3" / "model"
    d3_det = detection_dir / "brute.jsonl"
    generate_brute_corpus(out_dir=d3_synth, seed=seed)
    train_brute(input_dir=d3_synth, out_dir=d3_model, seed=seed)
    d3_events = score_brute(input_dir=d3_synth, model_dir=d3_model, out_path=d3_det)
    d3_report = build_report(
        detections_path=d3_det,
        input_dir=d3_synth,
        out_path=reports_dir / "d3.md",
        title="D3 brute force report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
        run_filename="ssh.jsonl",
    )
    detectors["D3"] = _detector_entry(d3_events, d3_report, d3_model)

    d4_synth = workdir / "d4" / "synthetic"
    d4_model = workdir / "d4" / "model"
    d4_det = detection_dir / "malware.jsonl"
    generate_malware_corpus(out_dir=d4_synth, seed=seed)
    train_malware(input_dir=d4_synth, out_dir=d4_model, seed=seed)
    d4_events = score_malware(
        input_dir=d4_synth, model_dir=d4_model, out_path=d4_det
    )
    d4_report = build_report(
        detections_path=d4_det,
        input_dir=d4_synth,
        out_path=reports_dir / "d4.md",
        title="D4 malware download report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
        run_filename="http.jsonl",
    )
    detectors["D4"] = _detector_entry(d4_events, d4_report, d4_model)

    d5_synth = workdir / "d5" / "synthetic"
    d5_model = workdir / "d5" / "model"
    d5_det = detection_dir / "beacon.jsonl"
    generate_beacon_corpus(out_dir=d5_synth, seed=seed)
    train_beacon(input_dir=d5_synth, out_dir=d5_model, seed=seed)
    d5_events = score_beacon(
        input_dir=d5_synth, model_dir=d5_model, out_path=d5_det
    )
    d5_report = build_report(
        detections_path=d5_det,
        input_dir=d5_synth,
        out_path=reports_dir / "d5.md",
        title="D5 beaconing report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
    )
    detectors["D5"] = _detector_entry(d5_events, d5_report, d5_model)

    d6_synth = workdir / "d6" / "synthetic"
    d6_model = workdir / "d6" / "model"
    d6_det = detection_dir / "lateral.jsonl"
    generate_lateral_corpus(out_dir=d6_synth, seed=seed)
    train_lateral(input_dir=d6_synth, out_dir=d6_model, seed=seed)
    d6_events = score_lateral(
        input_dir=d6_synth, model_dir=d6_model, out_path=d6_det
    )
    d6_report = build_report(
        detections_path=d6_det,
        input_dir=d6_synth,
        out_path=reports_dir / "d6.md",
        title="D6 lateral movement report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
        run_filename="smb_mapping.jsonl",
    )
    detectors["D6"] = _detector_entry(d6_events, d6_report, d6_model)

    d7_synth = workdir / "d7" / "synthetic"
    d7_model = workdir / "d7" / "model"
    d7_det = detection_dir / "dns.jsonl"
    generate_dns_corpus(out_dir=d7_synth, seed=seed)
    train_dns(input_dir=d7_synth, out_dir=d7_model, seed=seed)
    d7_events = score_dns(input_dir=d7_synth, model_dir=d7_model, out_path=d7_det)
    d7_report = build_report(
        detections_path=d7_det,
        input_dir=d7_synth,
        out_path=reports_dir / "d7.md",
        title="D7 DNS tunneling report (synthetic)",
        target_fp_per_day=TARGET_FP_PER_DAY,
        run_filename="dns.jsonl",
    )
    detectors["D7"] = _detector_entry(d7_events, d7_report, d7_model)

    alerts_path = workdir / "alerts.jsonl"
    alerts = build_alerts(load_detections(detection_dir), demo_enrichment())
    write_alerts(alerts, alerts_path)
    risk = build_risk_report(
        alerts_path=alerts_path,
        input_dir=detection_dir,
        out_path=workdir / "risk.md",
    )

    high_critical = [alert for alert in alerts if alert.level in {"high", "critical"}]
    triage_results = triage_alerts(
        high_critical,
        MockProvider(),
        audit_path=audit_dir / "llm.jsonl",
    )
    with (workdir / "triage.jsonl").open("w", encoding="utf-8") as handle:
        for result in triage_results:
            handle.write(result.model_dump_json() + "\n")
    triage = summarize_triage(high_critical, triage_results)

    allowlist_path = workdir / "allowlist.json"
    allowlist_path.write_text(
        json.dumps(["192.168.217.129"]), encoding="utf-8"
    )
    policy = ResponsePolicy(allowlist=frozenset({"192.168.217.129"}))
    simulator = ResponseSimulator()
    decisions = []
    recent: list[datetime] = []
    for alert in sorted(alerts, key=lambda item: (item.first_seen or item.timestamp, item.alert_id)):
        timestamp = alert.first_seen or alert.timestamp
        recent = [
            moment
            for moment in recent
            if 0.0 <= (timestamp - moment).total_seconds() < 60.0
        ]
        decision = decide_response(alert, policy, len(recent))
        if decision.allowed:
            recent.append(timestamp)
            simulator.apply(decision, timestamp)
        decisions.append(decision)
    with (workdir / "response.jsonl").open("w", encoding="utf-8") as handle:
        for decision in decisions:
            handle.write(json.dumps(asdict(decision), sort_keys=True) + "\n")
    simulator.write_jsonl(audit_dir / "response.jsonl")
    response = {
        "allowed": sum(1 for decision in decisions if decision.allowed),
        "denied": sum(1 for decision in decisions if not decision.allowed),
        "allowlisted": sum(
            1 for decision in decisions if decision.reason == "allowlisted"
        ),
    }

    lines = [
        "# Pre-lab NDR synthetic demo",
        "",
        "| detector | detections | attack_recall | test_fp_per_day |",
        "|---|---:|---:|---:|",
    ]
    for name, entry in detectors.items():
        lines.append(
            f"| {name} | {entry['detections']} | "
            f"{entry['attack_recall']:.2f} | {entry['test_fp_per_day']:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Risk",
            "",
            f"- Raw alerts: {risk['raw_alerts']}",
            f"- Fused alerts: {risk['fused_alerts']}",
            f"- Reduction: {risk['reduction'] * 100:.2f}%",
            f"- MITRE coverage: {risk['mitre_coverage'] * 100:.2f}%",
            "",
            "## Triage",
            "",
            f"- Triage count: {triage['triage_count']}",
            f"- Schema valid rate: {triage['schema_valid_rate']:.2f}",
            f"- MITRE accuracy: {triage['mitre_accuracy']:.2f}",
            f"- Hallucination rate: {triage['hallucination_rate']:.2f}",
            "",
            "## Response",
            "",
            f"- Allowed: {response['allowed']}",
            f"- Denied: {response['denied']}",
            f"- Allowlisted: {response['allowlisted']}",
        ]
    )
    (workdir / "prelab.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "detectors": detectors,
        "risk": {
            "raw_alerts": risk["raw_alerts"],
            "fused_alerts": risk["fused_alerts"],
            "reduction": risk["reduction"],
            "mitre_coverage": risk["mitre_coverage"],
        },
        "triage": {
            "count": triage["triage_count"],
            "schema_valid_rate": triage["schema_valid_rate"],
            "mitre_accuracy": triage["mitre_accuracy"],
            "hallucination_rate": triage["hallucination_rate"],
        },
        "response": response,
    }
    (workdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary
