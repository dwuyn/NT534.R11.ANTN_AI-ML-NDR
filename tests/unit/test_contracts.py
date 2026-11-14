from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ndr.contracts import (
    AiSummary,
    AlertEvent,
    DetectionEvent,
    Entity,
    FeatureSnapshot,
    FeedbackEvent,
    Mitre,
    ModelInfo,
    ResponseRecommendation,
    RuleInfo,
    TopFeature,
    Window,
)


def _window() -> Window:
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return Window(start=moment, end=moment, size_sec=300)


def test_feature_snapshot_roundtrip() -> None:
    snapshot = FeatureSnapshot(
        snapshot_id="fs-test",
        feature_set_version="v0.1.0",
        window=_window(),
        entity=Entity(src_ip="10.0.0.1"),
        features={"a": 1.0},
        context={"uids": ["C1"]},
    )
    restored = FeatureSnapshot.model_validate_json(snapshot.model_dump_json())
    assert restored == snapshot


def test_detection_event_roundtrip() -> None:
    event = DetectionEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        rule=RuleInfo(id="NDR-ML-ANOM-001", name="ML Anomaly (conn)", version="0.1.0"),
        model=ModelInfo(name="anomaly_iforest", version="0.1.0", type="anomaly"),
        score=0.9,
        threshold=0.8,
        is_alert=True,
        top_features=[TopFeature(name="a", value=1.0, z=2.0)],
        entity=Entity(src_ip="10.0.0.1"),
        window=_window(),
        uids=["C1"],
        snapshot_id="fs-test",
    )
    restored = DetectionEvent.model_validate_json(event.model_dump_json())
    assert restored == event


def test_alert_and_feedback_roundtrip() -> None:
    alert = AlertEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        alert_id="alrt-1",
        risk=90,
        level="critical",
        entities={"src_ip": "10.0.0.1"},
        evidence={"uids": ["C1"]},
        response=ResponseRecommendation(recommended="isolate_host_manual"),
    )
    assert AlertEvent.model_validate_json(alert.model_dump_json()) == alert

    feedback = FeedbackEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        alert_id="alrt-1",
        analyst="analyst1",
        disposition="true_positive",
        reason="confirmed beacon",
    )
    assert FeedbackEvent.model_validate_json(feedback.model_dump_json()) == feedback


def test_alert_event_risk_fields_roundtrip_and_defaults() -> None:
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alert = AlertEvent(
        timestamp=moment,
        first_seen=moment,
        last_seen=moment,
        alert_id="alrt-2",
        risk=90,
        level="critical",
        count=3,
        reasons=["ml_c2_beaconing", "detectors_agree"],
        entities={"src_ip": "10.0.0.1"},
        evidence={"uids": ["C1"]},
        response=ResponseRecommendation(recommended="block_source_and_notify"),
    )
    restored = AlertEvent.model_validate_json(alert.model_dump_json())
    assert restored == alert
    assert restored.count == 3
    assert restored.reasons == ["ml_c2_beaconing", "detectors_agree"]

    defaulted = AlertEvent(
        timestamp=moment,
        alert_id="alrt-3",
        risk=10,
        level="low",
        entities={},
        evidence={},
        response=ResponseRecommendation(recommended="log_and_hunt"),
    )
    assert defaulted.count == 1
    assert defaulted.reasons == []
    assert defaulted.first_seen is None
    assert defaulted.last_seen is None


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Window(
            start=datetime(2026, 1, 1),
            end=datetime(2026, 1, 1, tzinfo=timezone.utc),
            size_sec=300,
        )


def test_ai_summary_extended_fields_roundtrip() -> None:
    summary = AiSummary(
        summary="scan",
        model="mock",
        confidence=0.9,
        evidence=["fs-1"],
        hypotheses=["port scan"],
        actions=["check firewall"],
        mitre=Mitre(tactic=["TA0007"], technique=["T1046"]),
        caveats=["synthetic"],
    )
    assert AiSummary.model_validate_json(summary.model_dump_json()) == summary


def test_invalid_risk_and_level_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AlertEvent(
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            alert_id="alrt-1",
            risk=101,
            level="critical",
            entities={},
            evidence={},
            response=ResponseRecommendation(recommended="none"),
        )
    with pytest.raises(ValidationError):
        AlertEvent(
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            alert_id="alrt-1",
            risk=10,
            level="urgent",
            entities={},
            evidence={},
            response=ResponseRecommendation(recommended="none"),
        )
