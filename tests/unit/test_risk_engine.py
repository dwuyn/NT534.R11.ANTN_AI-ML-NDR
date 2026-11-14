from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import (
    DetectionEvent,
    Entity,
    ModelInfo,
    RuleInfo,
    Window,
)
from ndr.risk.engine import (
    ALERT_RULES,
    ANOMALY_RULE_ID,
    EntityEnrichment,
    build_alerts,
    load_detections,
    load_enrichment,
    response_for,
    risk_level,
)

BEACON_RULE = "NDR-ML-BEACON-001"
DNS_RULE = "NDR-ML-DNS-001"
SRC = "10.0.0.5"


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _detection(
    rule_id: str,
    timestamp: float,
    score: float,
    *,
    dst: str | None = "203.0.113.10",
    dst_port: int | None = 443,
    domain: str | None = "tunnel.test",
    uid: str | None = None,
    snapshot_id: str | None = None,
) -> DetectionEvent:
    if rule_id == ANOMALY_RULE_ID:
        entity = Entity(type="host", src_ip=SRC)
        window = Window(
            start=_utc(timestamp - 300), end=_utc(timestamp), size_sec=300
        )
        model = ModelInfo(
            name="anomaly_iforest", version="0.1.0", type="anomaly"
        )
        rule = RuleInfo(
            id=rule_id, name="ML Anomaly (conn)", version="0.1.0"
        )
    elif rule_id == BEACON_RULE:
        entity = Entity(
            type="host_pair",
            src_ip=SRC,
            dst_ip=dst,
            dst_port=dst_port,
            proto="tcp",
        )
        window = Window(
            start=_utc(timestamp - 600), end=_utc(timestamp), size_sec=600
        )
        model = ModelInfo(
            name="beaconing_lgbm_iforest", version="0.1.0", type="classification"
        )
        rule = RuleInfo(id=rule_id, name="ML C2 Beaconing", version="0.1.0")
    else:
        entity = Entity(type="host_domain", src_ip=SRC, domain=domain)
        window = Window(
            start=_utc(timestamp - 300), end=_utc(timestamp), size_sec=300
        )
        model = ModelInfo(
            name="dns_tunnel_lgbm", version="0.1.0", type="classification"
        )
        rule = RuleInfo(id=rule_id, name="ML DNS Tunneling", version="0.1.0")

    return DetectionEvent(
        timestamp=_utc(timestamp),
        rule=rule,
        model=model,
        score=score,
        threshold=0.5,
        is_alert=True,
        top_features=[],
        entity=entity,
        window=window,
        uids=[uid or f"C{timestamp}"],
        snapshot_id=snapshot_id
        or f"fs-{rule_id}-{timestamp}-{dst or domain or ''}",
    )


def _dns(timestamp: float, score: float, **kwargs) -> DetectionEvent:
    return _detection(DNS_RULE, timestamp, score, **kwargs)


def _beacon(timestamp: float, score: float, **kwargs) -> DetectionEvent:
    return _detection(BEACON_RULE, timestamp, score, **kwargs)


def _anomaly(timestamp: float, score: float, **kwargs) -> DetectionEvent:
    return _detection(ANOMALY_RULE_ID, timestamp, score, **kwargs)


def test_new_detector_metadata_and_stage_order() -> None:
    expected = {
        "NDR-ML-SCAN-001": ("port_scan", 1, ["TA0007"], ["T1046"]),
        "NDR-ML-BRUTE-001": ("brute_force", 2, ["TA0006"], ["T1110"]),
        "NDR-ML-MALWARE-001": ("malware_download", 3, ["TA0011"], ["T1105"]),
        "NDR-ML-BEACON-001": ("c2_beaconing", 4, ["TA0011"], ["T1071.001", "T1573"]),
        "NDR-ML-LATERAL-001": (
            "lateral_movement",
            5,
            ["TA0008", "TA0002"],
            ["T1021.002", "T1569.002"],
        ),
        "NDR-ML-DNS-001": ("dns_tunneling", 6, ["TA0010", "TA0011"], ["T1048", "T1071.004"]),
    }
    for rule_id, (scenario, stage, tactic, technique) in expected.items():
        meta = ALERT_RULES[rule_id]
        assert meta.scenario == scenario
        assert meta.stage == stage
        assert list(meta.tactic) == tactic
        assert list(meta.technique) == technique


def test_alert_confidence_is_max_seed_or_anomaly_score() -> None:
    alert = build_alerts(
        [_beacon(0, 0.5), _anomaly(0, 0.9, snapshot_id="fs-anom")]
    )[0]
    assert alert.confidence == 0.9

    single = build_alerts([_beacon(0, 0.8)])[0]
    assert single.confidence == 0.8


def test_group_merges_chain_and_keeps_evidence() -> None:
    alerts = build_alerts(
        [
            _dns(0, 0.7, uid="C1", snapshot_id="fs1"),
            _dns(300, 0.8, uid="C2", snapshot_id="fs2"),
            _dns(600, 0.9, uid="C3", snapshot_id="fs3"),
        ]
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.risk == 90
    assert alert.level == "critical"
    assert alert.count == 3
    assert alert.first_seen == _utc(0)
    assert alert.last_seen == _utc(600)
    assert alert.timestamp == _utc(600)
    assert alert.scenario == "dns_tunneling"
    assert alert.evidence["detections"] == ["fs1", "fs2", "fs3"]
    assert alert.evidence["uids"] == ["C1", "C2", "C3"]
    assert alert.evidence["models"] == ["dns_tunnel_lgbm"]
    assert alert.evidence["rules"] == [DNS_RULE]
    assert alert.evidence["anomaly_detections"] == []
    assert alert.mitre.tactic == ["TA0010", "TA0011"]
    assert alert.mitre.technique == ["T1048", "T1071.004"]
    assert alert.reasons == ["ml_dns_tunneling"]


def test_gap_boundary_splits_groups() -> None:
    assert len(build_alerts([_dns(0, 0.8), _dns(1800, 0.8)])) == 1
    assert len(build_alerts([_dns(0, 0.8), _dns(1801, 0.8)])) == 2


def test_different_entity_not_merged() -> None:
    alerts = build_alerts(
        [
            _beacon(0, 0.8, dst="203.0.113.10"),
            _beacon(0, 0.8, dst="203.0.113.11"),
        ]
    )
    assert len(alerts) == 2


def test_detector_agreement_and_kill_chain() -> None:
    alerts = build_alerts([_beacon(0, 0.8), _dns(0, 0.9)])
    assert len(alerts) == 2
    by_scenario = {alert.scenario: alert for alert in alerts}

    beacon = by_scenario["c2_beaconing"]
    assert beacon.risk == 90
    assert beacon.level == "critical"
    assert "detectors_agree" in beacon.reasons
    assert "kill_chain_advance" not in beacon.reasons

    dns = by_scenario["dns_tunneling"]
    assert dns.risk == 100
    assert dns.level == "critical"
    assert "detectors_agree" in dns.reasons
    assert "kill_chain_advance" in dns.reasons
    assert dns.evidence["models"] == [
        "beaconing_lgbm_iforest",
        "dns_tunnel_lgbm",
    ]


def test_anomaly_corroboration_does_not_seed_alert() -> None:
    assert build_alerts([_anomaly(0, 0.9)]) == []

    alert = build_alerts(
        [_beacon(0, 0.5), _anomaly(0, 0.9, snapshot_id="fs-anom")]
    )[0]
    assert alert.risk == 100
    assert "anomaly_corroboration" in alert.reasons
    assert alert.evidence["anomaly_detections"] == ["fs-anom"]


def test_enrichment_bonus_and_penalty() -> None:
    def score(enrichment: EntityEnrichment) -> tuple[int, str, list[str]]:
        alert = build_alerts(
            [_beacon(0, 0.5)], {SRC: enrichment}
        )[0]
        return alert.risk, alert.level, alert.reasons

    risk, level, reasons = score(
        EntityEnrichment(intel_match=True, asset_critical=True)
    )
    assert (risk, level) == (70, "high")
    assert "intel_match" in reasons
    assert "asset_critical" in reasons

    risk, level, _ = score(EntityEnrichment(allowlisted=True))
    assert (risk, level) == (40, "medium")

    risk, level, reasons = score(EntityEnrichment(historical_fp_rate=0.8))
    assert (risk, level) == (40, "medium")
    assert "historical_fp" in reasons

    risk, level, reasons = score(
        EntityEnrichment(
            intel_match=True,
            asset_critical=True,
            allowlisted=True,
            historical_fp_rate=0.8,
        )
    )
    assert (risk, level) == (50, "medium")
    assert reasons == [
        "ml_c2_beaconing",
        "intel_match",
        "asset_critical",
        "allowlisted",
        "historical_fp",
    ]


def test_risk_level_boundaries() -> None:
    assert risk_level(85) == "critical"
    assert risk_level(84) == "high"
    assert risk_level(70) == "high"
    assert risk_level(69) == "medium"
    assert risk_level(40) == "medium"
    assert risk_level(39) == "low"


def test_response_mapping() -> None:
    critical = response_for(90)
    assert critical.recommended == "block_source_and_notify"
    assert critical.auto_action is None
    assert critical.approval_required is True

    high = response_for(75)
    assert high.recommended == "notify_and_request_approval"
    assert high.approval_required is True

    medium = response_for(50)
    assert medium.recommended == "queue_for_investigation"
    assert medium.approval_required is False

    low = response_for(10)
    assert low.recommended == "log_and_hunt"
    assert low.approval_required is False


def test_alert_ids_are_deterministic() -> None:
    events = [_beacon(0, 0.8, dst="203.0.113.10"), _dns(0, 0.9)]
    first = build_alerts(events)
    second = build_alerts(events)
    assert [alert.alert_id for alert in first] == [
        alert.alert_id for alert in second
    ]
    assert all(alert.alert_id.startswith("alrt-") for alert in first)


def test_empty_input_returns_empty() -> None:
    assert build_alerts([]) == []


def test_load_enrichment_validation(tmp_path: Path) -> None:
    path = tmp_path / "enrichment.json"
    path.write_text(
        json.dumps(
            {
                SRC: {
                    "intel_match": True,
                    "asset_critical": False,
                    "allowlisted": False,
                    "historical_fp_rate": 0.2,
                }
            }
        ),
        encoding="utf-8",
    )
    loaded = load_enrichment(path)
    assert loaded[SRC].intel_match is True
    assert loaded[SRC].historical_fp_rate == 0.2
    assert load_enrichment(None) == {}

    with pytest.raises(FileNotFoundError):
        load_enrichment(tmp_path / "missing.json")

    path.write_text(json.dumps({SRC: {"unknown": True}}), encoding="utf-8")
    with pytest.raises(ValueError, match="extra_forbidden"):
        load_enrichment(path)

    path.write_text(
        json.dumps({SRC: {"historical_fp_rate": 1.5}}), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        load_enrichment(path)


def test_load_detections_reports_line(tmp_path: Path) -> None:
    path = tmp_path / "detections"
    path.mkdir()
    (path / "bad.jsonl").write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        load_detections(path)
    assert f"{path / 'bad.jsonl'}:1" in str(error.value)
