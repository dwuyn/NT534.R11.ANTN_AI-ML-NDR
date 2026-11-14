"""Deterministic evaluation harness for the mock LLM triage path."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from ndr.contracts import AlertEvent, Mitre, ResponseRecommendation
from ndr.llm.contracts import TriageResult
from ndr.llm.guardrail import ipv4_addresses
from ndr.llm.provider import TriageProvider
from ndr.llm.triage import triage_alerts
from ndr.risk.engine import ALERT_RULES, risk_level

_EVAL_BASE = datetime(2026, 2, 1, tzinfo=timezone.utc)

_EVAL_SPECS: tuple[tuple[str, str, str, str, int], ...] = (
    ("port_scan", "NDR-ML-SCAN-001", "192.168.217.132", "192.168.217.10", 90),
    ("brute_force", "NDR-ML-BRUTE-001", "192.168.217.132", "192.168.217.20", 78),
    ("malware_download", "NDR-ML-MALWARE-001", "192.168.217.50", "203.0.113.44", 82),
    ("c2_beaconing", "NDR-ML-BEACON-001", "192.168.217.60", "198.51.100.7", 93),
    ("lateral_movement", "NDR-ML-LATERAL-001", "192.168.217.132", "192.168.217.129", 91),
    ("dns_tunneling", "NDR-ML-DNS-001", "192.168.217.70", "192.168.217.2", 80),
)


def build_eval_alerts() -> list[AlertEvent]:
    alerts: list[AlertEvent] = []
    for index, (scenario, rule_id, src_ip, dst_ip, risk) in enumerate(_EVAL_SPECS):
        meta = ALERT_RULES[rule_id]
        timestamp = _EVAL_BASE + timedelta(minutes=index)
        slug = scenario.replace("_", "-")
        alerts.append(
            AlertEvent(
                timestamp=timestamp,
                first_seen=timestamp,
                last_seen=timestamp,
                alert_id=f"eval-{slug}",
                status="open",
                risk=risk,
                level=risk_level(risk),
                count=1,
                confidence=0.95,
                reasons=[meta.reason],
                scenario=scenario,
                entities={"src_ip": src_ip, "dst_ip": dst_ip},
                evidence={
                    "detections": [
                        f"fs-{slug}-001",
                        f"fs-{slug}-002",
                        f"fs-{slug}-003",
                    ],
                    "uids": [f"C-{index:02d}0001", f"C-{index:02d}0002"],
                    "models": [f"{scenario}_lgbm"],
                    "rules": [rule_id],
                    "anomaly_detections": [],
                },
                mitre=Mitre(
                    tactic=list(meta.tactic),
                    technique=list(meta.technique),
                ),
                response=ResponseRecommendation(
                    recommended="notify_and_request_approval",
                    auto_action=None,
                    approval_required=True,
                ),
            )
        )
    return alerts


def _result_text(ai) -> str:
    return "\n".join(
        [
            ai.summary,
            *ai.evidence,
            *ai.hypotheses,
            *ai.actions,
            *ai.caveats,
        ]
    )


def summarize_triage(
    alerts: Sequence[AlertEvent],
    results: Sequence[TriageResult],
) -> dict:
    by_id = {alert.alert_id: alert for alert in alerts}
    pairs = [
        (by_id[result.alert_id], result)
        for result in results
        if result.alert_id in by_id
    ]
    total = len(results)
    if total == 0:
        return {
            "schema_valid_rate": 0.0,
            "mitre_accuracy": 0.0,
            "evidence_coverage": 0.0,
            "hallucination_rate": 0.0,
            "actionability_rate": 0.0,
            "triage_count": 0,
        }

    schema_valid = 0
    mitre_match = 0
    evidence_match = 0
    actionability = 0
    hallucinated = 0
    for alert, result in pairs:
        ai = result.ai
        schema_valid += 1
        if ai.mitre == alert.mitre:
            mitre_match += 1
        detections = set(alert.evidence.get("detections", []))
        if detections and detections & set(ai.evidence):
            evidence_match += 1
        if ai.actions:
            actionability += 1
        allowed = set(alert.entities.values())
        if ipv4_addresses(_result_text(ai)) - allowed:
            hallucinated += 1

    denominator = len(pairs) if pairs else 1
    return {
        "schema_valid_rate": schema_valid / denominator,
        "mitre_accuracy": mitre_match / denominator,
        "evidence_coverage": evidence_match / denominator,
        "hallucination_rate": hallucinated / denominator,
        "actionability_rate": actionability / denominator,
        "triage_count": total,
    }


def evaluate_triage(
    alerts: Sequence[AlertEvent],
    provider: TriageProvider,
) -> dict:
    results = triage_alerts(alerts, provider)
    return summarize_triage(alerts, results)
