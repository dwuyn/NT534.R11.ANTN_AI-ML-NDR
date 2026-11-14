"""Build the D8 risk fusion report."""

from __future__ import annotations

from pathlib import Path

from ndr.risk.engine import (
    ALERT_RULES,
    ANOMALY_RULE_ID,
    load_alerts,
    load_detections,
)


def build_risk_report(
    alerts_path: Path, input_dir: Path, out_path: Path
) -> dict:
    alerts = load_alerts(alerts_path)
    detections = load_detections(input_dir)

    raw = [
        detection
        for detection in detections
        if detection.is_alert and detection.rule.id in ALERT_RULES
    ]
    anomaly = [
        detection
        for detection in detections
        if detection.is_alert and detection.rule.id == ANOMALY_RULE_ID
    ]

    reduction = 1.0 - len(alerts) / len(raw) if raw else 0.0
    mitre_coverage = (
        sum(
            1
            for alert in alerts
            if alert.mitre.tactic and alert.mitre.technique
        )
        / len(alerts)
        if alerts
        else 0.0
    )
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        levels[alert.level] += 1
    agreement_alerts = sum(
        1 for alert in alerts if "detectors_agree" in alert.reasons
    )

    scenarios = sorted({meta.scenario for meta in ALERT_RULES.values()})
    rows = {
        scenario: {
            "alerts": 0,
            "raw": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for scenario in scenarios
    }
    for detection in raw:
        scenario = ALERT_RULES[detection.rule.id].scenario
        rows[scenario]["raw"] += 1
    for alert in alerts:
        if alert.scenario not in rows:
            continue
        row = rows[alert.scenario]
        row["alerts"] += 1
        row[alert.level] += 1

    lines = [
        "# D8 risk fusion report (synthetic)",
        "",
        "| scenario | alerts | raw_alerts | critical | high | medium | low |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for scenario in scenarios:
        row = rows[scenario]
        lines.append(
            f"| {scenario} | {row['alerts']} | {row['raw']} | "
            f"{row['critical']} | {row['high']} | {row['medium']} | "
            f"{row['low']} |"
        )

    lines.extend(
        [
            "",
            f"- Raw D5/D7 alerts: {len(raw)}",
            f"- Fused alerts: {len(alerts)}",
            f"- Reduction: {reduction * 100:.2f}%",
            f"- MITRE coverage: {mitre_coverage * 100:.2f}%",
            f"- Detector-agreement alerts: {agreement_alerts}",
            f"- D1 corroboration detections: {len(anomaly)} "
            "(not alert sources)",
            "- Synthetic data only: numbers validate wiring, not real-world "
            "risk calibration.",
        ]
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "raw_alerts": len(raw),
        "fused_alerts": len(alerts),
        "reduction": reduction,
        "mitre_coverage": mitre_coverage,
        "levels": levels,
        "agreement_alerts": agreement_alerts,
        "anomaly_detections": len(anomaly),
    }
