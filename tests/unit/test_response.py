from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import AlertEvent, ResponseRecommendation
from ndr.response import (
    ResponseDecision,
    ResponsePolicy,
    ResponseSimulator,
    decide_response,
    load_allowlist,
)

SRC = "198.51.100.7"
TS = datetime(2026, 2, 5, 12, 0, 0, tzinfo=timezone.utc)


def _alert(
    *,
    alert_id: str = "alert-1",
    risk: int = 95,
    confidence: float | None = 0.95,
    entities: dict[str, str] | None = None,
) -> AlertEvent:
    if entities is None:
        entities = {"src_ip": SRC}
    level = (
        "critical"
        if risk >= 90
        else "high"
        if risk >= 70
        else "medium"
        if risk >= 40
        else "low"
    )
    return AlertEvent(
        timestamp=TS,
        alert_id=alert_id,
        risk=risk,
        level=level,
        confidence=confidence,
        entities=entities,
        evidence={"detections": ["NDR-ML-SCAN-001"], "uids": ["C1"]},
        response=ResponseRecommendation(
            recommended="block_source_and_notify", approval_required=True
        ),
    )


def _decision(
    *,
    alert_id: str = "alert-1",
    risk: int = 95,
    confidence: float | None = 0.95,
    entities: dict[str, str] | None = None,
    policy: ResponsePolicy | None = None,
    recent_actions: int = 0,
) -> ResponseDecision:
    return decide_response(
        _alert(
            alert_id=alert_id,
            risk=risk,
            confidence=confidence,
            entities=entities,
        ),
        policy or ResponsePolicy(),
        recent_actions=recent_actions,
    )


def test_policy_defaults() -> None:
    policy = ResponsePolicy()
    assert policy.min_risk == 85
    assert policy.min_confidence == 0.9
    assert policy.ttl_seconds == 3600
    assert policy.max_actions_per_minute == 10
    assert policy.allowlist == frozenset()
    assert isinstance(policy.allowlist, frozenset)


def test_load_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps(["192.168.217.129", "10.0.0.1"]))
    assert load_allowlist(path) == frozenset({"192.168.217.129", "10.0.0.1"})


def test_load_allowlist_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_allowlist(tmp_path / "missing.json")


def test_load_allowlist_non_list(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"hosts": ["10.0.0.1"]}))
    with pytest.raises(ValueError):
        load_allowlist(path)


def test_allow_key_alert() -> None:
    decision = _decision()
    assert decision.allowed is True
    assert decision.alert_id == "alert-1"
    assert decision.action == "block_ip"
    assert decision.target == SRC
    assert decision.reason == "policy_allow"
    assert decision.ttl_seconds == 3600
    assert decision.simulated is True


def test_deny_missing_target() -> None:
    decision = _decision(entities={})
    assert decision.allowed is False
    assert decision.reason == "missing_target"
    assert decision.target is None


def test_deny_risk_below_threshold() -> None:
    decision = _decision(risk=84)
    assert decision.allowed is False
    assert decision.reason == "risk_below_threshold"


def test_deny_confidence_below_threshold() -> None:
    decision = _decision(confidence=0.89)
    assert decision.allowed is False
    assert decision.reason == "confidence_below_threshold"


def test_deny_missing_confidence_treated_as_zero() -> None:
    decision = _decision(confidence=None)
    assert decision.allowed is False
    assert decision.reason == "confidence_below_threshold"


def test_deny_allowlisted() -> None:
    policy = ResponsePolicy(allowlist=frozenset({SRC}))
    decision = _decision(policy=policy)
    assert decision.allowed is False
    assert decision.reason == "allowlisted"
    assert decision.target == SRC


def test_deny_rate_limited() -> None:
    decision = _decision(recent_actions=10)
    assert decision.allowed is False
    assert decision.reason == "rate_limited"
    assert _decision(recent_actions=9).allowed is True


def test_policy_order_risk_before_allowlist() -> None:
    policy = ResponsePolicy(allowlist=frozenset({SRC}))
    decision = _decision(risk=50, policy=policy)
    assert decision.reason == "risk_below_threshold"


def test_policy_ttl_is_used() -> None:
    policy = ResponsePolicy(ttl_seconds=120)
    decision = _decision(policy=policy)
    assert decision.allowed is True
    assert decision.ttl_seconds == 120


def test_simulator_ignores_denied_and_records_allowed() -> None:
    simulator = ResponseSimulator()
    denied = _decision(risk=10)
    assert simulator.apply(denied, TS) is None
    assert simulator.records == []

    allowed = _decision()
    simulator.apply(allowed, TS)
    assert simulator.records == [
        {
            "type": "block_ip",
            "alert_id": "alert-1",
            "target": SRC,
            "ttl_seconds": 3600,
            "reason": "policy_allow",
            "timestamp": "2026-02-05T12:00:00+00:00",
            "simulated": True,
        }
    ]


def test_simulator_rollback() -> None:
    simulator = ResponseSimulator()
    simulator.apply(_decision(), TS)
    record = simulator.rollback("alert-1", TS)
    assert record == {
        "type": "rollback",
        "alert_id": "alert-1",
        "target": SRC,
        "timestamp": "2026-02-05T12:00:00+00:00",
        "simulated": True,
    }
    assert simulator.records[-1] == record
    assert len(simulator.records) == 2


def test_simulator_rollback_unknown_alert() -> None:
    simulator = ResponseSimulator()
    record = simulator.rollback("unknown", TS)
    assert record["target"] is None
    assert record["type"] == "rollback"


def test_simulator_write_jsonl(tmp_path: Path) -> None:
    simulator = ResponseSimulator()
    simulator.apply(_decision(), TS)
    simulator.rollback("alert-1", TS)
    out = tmp_path / "nested" / "actions.jsonl"
    simulator.write_jsonl(out)

    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert [line["type"] for line in lines] == ["block_ip", "rollback"]
    assert lines == simulator.records


def test_simulator_is_deterministic() -> None:
    first = ResponseSimulator()
    second = ResponseSimulator()
    for simulator in (first, second):
        simulator.apply(_decision(alert_id="a"), TS)
        simulator.apply(_decision(alert_id="b", risk=20), TS)
        simulator.rollback("a", TS)
    assert first.records == second.records
