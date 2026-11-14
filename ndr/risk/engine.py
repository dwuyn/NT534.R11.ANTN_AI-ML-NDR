"""Deduplicate detections and fuse them into risk-scored alerts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ndr.contracts import (
    AlertEvent,
    DetectionEvent,
    Entity,
    Mitre,
    ResponseRecommendation,
)

RISK_WINDOW_SECONDS = 1800
INTEL_BONUS = 10
ASSET_BONUS = 10
AGREEMENT_BONUS = 10
KILL_CHAIN_BONUS = 5
ALLOWLIST_PENALTY = 10
FP_PENALTY = 10
FP_RATE_THRESHOLD = 0.5

ANOMALY_RULE_ID = "NDR-ML-ANOM-001"


@dataclass(frozen=True)
class DetectorMeta:
    scenario: str
    tactic: tuple[str, ...]
    technique: tuple[str, ...]
    stage: int
    reason: str


ALERT_RULES: dict[str, DetectorMeta] = {
    "NDR-ML-SCAN-001": DetectorMeta(
        scenario="port_scan",
        tactic=("TA0007",),
        technique=("T1046",),
        stage=1,
        reason="ml_port_scan",
    ),
    "NDR-ML-BRUTE-001": DetectorMeta(
        scenario="brute_force",
        tactic=("TA0006",),
        technique=("T1110",),
        stage=2,
        reason="ml_brute_force",
    ),
    "NDR-ML-MALWARE-001": DetectorMeta(
        scenario="malware_download",
        tactic=("TA0011",),
        technique=("T1105",),
        stage=3,
        reason="ml_malware_download",
    ),
    "NDR-ML-BEACON-001": DetectorMeta(
        scenario="c2_beaconing",
        tactic=("TA0011",),
        technique=("T1071.001", "T1573"),
        stage=4,
        reason="ml_c2_beaconing",
    ),
    "NDR-ML-LATERAL-001": DetectorMeta(
        scenario="lateral_movement",
        tactic=("TA0008", "TA0002"),
        technique=("T1021.002", "T1569.002"),
        stage=5,
        reason="ml_lateral_movement",
    ),
    "NDR-ML-DNS-001": DetectorMeta(
        scenario="dns_tunneling",
        tactic=("TA0010", "TA0011"),
        technique=("T1048", "T1071.004"),
        stage=6,
        reason="ml_dns_tunneling",
    ),
}


class EntityEnrichment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_critical: bool = False
    intel_match: bool = False
    allowlisted: bool = False
    historical_fp_rate: float = Field(default=0.0, ge=0.0, le=1.0)


def load_enrichment(path: Path | None) -> dict[str, EntityEnrichment]:
    if path is None:
        return {}
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")

    enrichment: dict[str, EntityEnrichment] = {}
    for address, raw in data.items():
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected an object for {address}")
        try:
            enrichment[str(address)] = EntityEnrichment.model_validate(raw)
        except Exception as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return enrichment


def demo_enrichment() -> dict[str, EntityEnrichment]:
    return {
        "192.168.217.132": EntityEnrichment(
            intel_match=True, asset_critical=True
        ),
        "192.168.217.129": EntityEnrichment(asset_critical=True),
        "192.168.217.101": EntityEnrichment(allowlisted=True),
        "192.168.217.102": EntityEnrichment(historical_fp_rate=0.8),
    }


def load_detections(input_dir: Path) -> list[DetectionEvent]:
    paths = sorted(input_dir.glob("*.jsonl"))
    if not paths:
        raise ValueError(f"no detection jsonl under {input_dir}")

    detections: list[DetectionEvent] = []
    for path in paths:
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                detections.append(DetectionEvent.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return sorted(
        detections,
        key=lambda event: (event.timestamp, event.rule.id, event.snapshot_id),
    )


def load_alerts(path: Path) -> list[AlertEvent]:
    if not path.is_file():
        raise FileNotFoundError(path)

    alerts: list[AlertEvent] = []
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            alerts.append(AlertEvent.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return sorted(
        alerts, key=lambda alert: (alert.first_seen or alert.timestamp, alert.alert_id)
    )


def write_alerts(alerts: Sequence[AlertEvent], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(alert.model_dump_json() + "\n")


def _entity_key(entity: Entity) -> tuple[str, str, str, str, str, str]:
    return (
        entity.type,
        entity.src_ip,
        entity.dst_ip or "",
        str(entity.dst_port or 0),
        entity.proto or "",
        entity.domain or "",
    )


@dataclass
class _Group:
    rule_id: str
    meta: DetectorMeta
    entity_key: tuple[str, str, str, str, str, str]
    seed_events: list[DetectionEvent]
    first_seen: datetime
    last_seen: datetime


def _interval_overlaps(
    first_start: datetime,
    first_end: datetime,
    second_start: datetime,
    second_end: datetime,
) -> bool:
    slack = timedelta(seconds=RISK_WINDOW_SECONDS)
    return first_start <= second_end + slack and second_start <= first_end + slack


def risk_level(risk: int) -> str:
    if risk >= 85:
        return "critical"
    if risk >= 70:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def response_for(risk: int) -> ResponseRecommendation:
    level = risk_level(risk)
    if level == "critical":
        return ResponseRecommendation(
            recommended="block_source_and_notify",
            auto_action=None,
            approval_required=True,
        )
    if level == "high":
        return ResponseRecommendation(
            recommended="notify_and_request_approval",
            auto_action=None,
            approval_required=True,
        )
    if level == "medium":
        return ResponseRecommendation(
            recommended="queue_for_investigation",
            auto_action=None,
            approval_required=False,
        )
    return ResponseRecommendation(
        recommended="log_and_hunt",
        auto_action=None,
        approval_required=False,
    )


def _build_groups(seeds: Sequence[DetectionEvent]) -> list[_Group]:
    groups: list[_Group] = []
    for event in seeds:
        meta = ALERT_RULES[event.rule.id]
        entity_key = _entity_key(event.entity)
        if groups:
            last = groups[-1]
            within_window = (
                event.timestamp - last.last_seen
            ).total_seconds() <= RISK_WINDOW_SECONDS
            if (
                last.rule_id == event.rule.id
                and last.entity_key == entity_key
                and within_window
            ):
                last.seed_events.append(event)
                last.first_seen = min(last.first_seen, event.timestamp)
                last.last_seen = max(last.last_seen, event.timestamp)
                continue
        groups.append(
            _Group(
                rule_id=event.rule.id,
                meta=meta,
                entity_key=entity_key,
                seed_events=[event],
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        )
    return groups


def _matching_anomalies(
    group: _Group, valid: Sequence[DetectionEvent]
) -> list[DetectionEvent]:
    slack = timedelta(seconds=RISK_WINDOW_SECONDS)
    anomalies: list[DetectionEvent] = []
    seen: set[str] = set()
    for event in valid:
        if event.rule.id != ANOMALY_RULE_ID:
            continue
        if event.entity.src_ip != group.seed_events[0].entity.src_ip:
            continue
        if not (
            event.window.start <= group.last_seen + slack
            and event.window.end >= group.first_seen - slack
        ):
            continue
        if event.snapshot_id in seen:
            continue
        seen.add(event.snapshot_id)
        anomalies.append(event)
    return anomalies


def _agreement_models(
    group: _Group, valid: Sequence[DetectionEvent]
) -> set[str]:
    slack = timedelta(seconds=RISK_WINDOW_SECONDS)
    start = group.first_seen - slack
    end = group.last_seen + slack
    source_ip = group.seed_events[0].entity.src_ip
    return {
        event.model.name
        for event in valid
        if event.entity.src_ip == source_ip and start <= event.timestamp <= end
    }


def _kill_chain_advances(group: _Group, groups: Sequence[_Group]) -> bool:
    source_ip = group.seed_events[0].entity.src_ip
    for other in groups:
        if other is group:
            continue
        if other.seed_events[0].entity.src_ip != source_ip:
            continue
        if other.meta.scenario == group.meta.scenario:
            continue
        if other.meta.stage >= group.meta.stage:
            continue
        if _interval_overlaps(
            group.first_seen,
            group.last_seen,
            other.first_seen,
            other.last_seen,
        ):
            return True
    return False


def _risk_for_group(
    group: _Group,
    anomalies: Sequence[DetectionEvent],
    enrich: EntityEnrichment,
    detectors_agree: bool,
    kill_chain_advance: bool,
) -> int:
    base = max(
        [100.0 * event.score for event in group.seed_events]
        + [100.0 * event.score for event in anomalies]
    )
    risk = base
    if enrich.intel_match:
        risk += INTEL_BONUS
    if enrich.asset_critical:
        risk += ASSET_BONUS
    if detectors_agree:
        risk += AGREEMENT_BONUS
    if kill_chain_advance:
        risk += KILL_CHAIN_BONUS
    if enrich.allowlisted:
        risk -= ALLOWLIST_PENALTY
    if enrich.historical_fp_rate > FP_RATE_THRESHOLD:
        risk -= FP_PENALTY
    return int(round(max(0.0, min(100.0, risk))))


def _reasons_for(
    group: _Group,
    anomalies: Sequence[DetectionEvent],
    detectors_agree: bool,
    kill_chain_advance: bool,
    enrich: EntityEnrichment,
) -> list[str]:
    reasons = [group.meta.reason]
    if anomalies:
        reasons.append("anomaly_corroboration")
    if detectors_agree:
        reasons.append("detectors_agree")
    if enrich.intel_match:
        reasons.append("intel_match")
    if enrich.asset_critical:
        reasons.append("asset_critical")
    if kill_chain_advance:
        reasons.append("kill_chain_advance")
    if enrich.allowlisted:
        reasons.append("allowlisted")
    if enrich.historical_fp_rate > FP_RATE_THRESHOLD:
        reasons.append("historical_fp")
    return reasons


def _alert_entities(entity: Entity) -> dict[str, str]:
    entities = {"src_ip": entity.src_ip}
    if entity.dst_ip:
        entities["dst_ip"] = entity.dst_ip
    if entity.dst_port is not None:
        entities["dst_port"] = str(entity.dst_port)
    if entity.proto:
        entities["proto"] = entity.proto
    if entity.domain:
        entities["domain"] = entity.domain
    return entities


def _alert_id(group: _Group, rule_id: str, first_seen: datetime) -> str:
    entity_key = group.entity_key
    digest = hashlib.sha1(
        f"{rule_id}|{entity_key}|{int(first_seen.timestamp())}".encode("utf-8")
    ).hexdigest()
    return f"alrt-{digest[:12]}"


def build_alerts(
    detections: Sequence[DetectionEvent],
    enrichment: Mapping[str, EntityEnrichment] | None = None,
) -> list[AlertEvent]:
    enrichment = enrichment or {}
    valid = [event for event in detections if event.is_alert]

    seeds: list[DetectionEvent] = []
    seen: set[tuple[str, str]] = set()
    for event in valid:
        if event.rule.id not in ALERT_RULES:
            continue
        key = (event.rule.id, event.snapshot_id)
        if key in seen:
            continue
        seen.add(key)
        seeds.append(event)
    seeds.sort(
        key=lambda event: (
            event.rule.id,
            _entity_key(event.entity),
            event.timestamp,
            event.snapshot_id,
        )
    )

    groups = _build_groups(seeds)
    alerts: list[AlertEvent] = []
    for group in groups:
        source_ip = group.seed_events[0].entity.src_ip
        anomalies = _matching_anomalies(group, valid)
        agree_models = _agreement_models(group, valid)
        detectors_agree = len(agree_models) >= 2
        kill_chain_advance = _kill_chain_advances(group, groups)
        enrich = enrichment.get(source_ip, EntityEnrichment())
        risk = _risk_for_group(
            group,
            anomalies,
            enrich,
            detectors_agree,
            kill_chain_advance,
        )
        confidence = max(
            event.score for event in [*group.seed_events, *anomalies]
        )
        reasons = _reasons_for(
            group,
            anomalies,
            detectors_agree,
            kill_chain_advance,
            enrich,
        )
        entity = group.seed_events[0].entity
        evidence = {
            "detections": sorted(
                {event.snapshot_id for event in group.seed_events}
            ),
            "uids": sorted(
                {uid for event in group.seed_events for uid in event.uids}
            ),
            "models": sorted(agree_models),
            "rules": sorted({event.rule.id for event in group.seed_events}),
            "anomaly_detections": sorted(
                {event.snapshot_id for event in anomalies}
            ),
        }
        alerts.append(
            AlertEvent(
                timestamp=group.last_seen,
                first_seen=group.first_seen,
                last_seen=group.last_seen,
                alert_id=_alert_id(group, group.rule_id, group.first_seen),
                status="open",
                risk=risk,
                level=risk_level(risk),
                count=len(group.seed_events),
                confidence=confidence,
                reasons=reasons,
                scenario=group.meta.scenario,
                entities=_alert_entities(entity),
                evidence=evidence,
                mitre=Mitre(
                    tactic=list(group.meta.tactic),
                    technique=list(group.meta.technique),
                ),
                response=response_for(risk),
                ai=None,
            )
        )

    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.alert_id))
