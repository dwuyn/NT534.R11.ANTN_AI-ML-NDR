from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import AlertEvent, Mitre, ResponseRecommendation
from ndr.llm.contracts import TriageOutput
from ndr.llm.eval import build_eval_alerts, evaluate_triage, summarize_triage
from ndr.llm.guardrail import redact, validate_provider_output
from ndr.llm.provider import MockProvider, TriageRequest
from ndr.llm.rag import PLAYBOOKS, retrieve_playbook
from ndr.llm.triage import triage_alert, triage_alerts


def _alert(
    *,
    alert_id: str = "alert-1",
    level: str = "high",
    risk: int = 90,
    confidence: float | None = 0.97,
    scenario: str | None = "port_scan",
    detections: tuple[str, ...] = ("fs-1", "fs-2", "fs-3", "fs-4", "fs-5"),
    uids: tuple[str, ...] = ("C-1", "C-2", "C-3", "C-4", "C-5"),
    mitre: Mitre | None = None,
) -> AlertEvent:
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return AlertEvent(
        timestamp=moment,
        first_seen=moment,
        last_seen=moment,
        alert_id=alert_id,
        risk=risk,
        level=level,
        confidence=confidence,
        scenario=scenario,
        entities={"src_ip": "192.168.217.132", "dst_ip": "192.168.217.10"},
        evidence={
            "detections": list(detections),
            "uids": list(uids),
            "models": [],
            "rules": [],
            "anomaly_detections": [],
        },
        mitre=mitre or Mitre(tactic=["TA0007"], technique=["T1046"]),
        response=ResponseRecommendation(recommended="notify_and_request_approval"),
    )


class SecretProvider(MockProvider):
    def complete(self, request: TriageRequest) -> str:
        payload = json.loads(super().complete(request))
        payload["summary"] += " password=hunter2"
        payload["caveats"] = ["token=abc123", "Authorization: Bearer topsecret"]
        return json.dumps(payload)


class MitreMismatchProvider(MockProvider):
    def complete(self, request: TriageRequest) -> str:
        payload = json.loads(super().complete(request))
        payload["mitre"] = {"tactic": ["TA9999"], "technique": ["T9999"]}
        return json.dumps(payload)


class InvalidJsonProvider(MockProvider):
    def complete(self, request: TriageRequest) -> str:
        return "not json"


class BadProvider(MockProvider):
    """Mock provider that hallucinates an address absent from the alert."""

    name = "bad"

    def complete(self, request: TriageRequest) -> str:
        payload = json.loads(super().complete(request))
        payload["summary"] += " Contact 203.0.113.250 for details."
        return json.dumps(payload)


def test_mock_provider_schema_mitre_and_evidence() -> None:
    alert = _alert()
    request = TriageRequest(alert=alert, playbook=retrieve_playbook("port_scan"))
    output = validate_provider_output(MockProvider().complete(request))

    assert isinstance(output, TriageOutput)
    assert output.mitre == alert.mitre
    assert output.evidence == ["fs-1", "fs-2", "fs-3", "C-1", "C-2", "C-3"]
    assert output.confidence == pytest.approx(0.97)
    assert output.actions == list(PLAYBOOKS["port_scan"])
    assert output.caveats == ["Synthetic mock provider; not a real LLM."]


def test_triage_alert_builds_ai_summary() -> None:
    alert = _alert()
    result = triage_alert(alert, MockProvider())

    assert result.alert_id == alert.alert_id
    ai = result.ai
    assert ai.model == "mock"
    assert ai.mitre == alert.mitre
    assert ai.confidence == pytest.approx(0.97)
    assert ai.evidence == ["fs-1", "fs-2", "fs-3", "C-1", "C-2", "C-3"]
    assert "port_scan" in ai.summary
    assert alert.alert_id in ai.summary
    assert "90" in ai.summary
    assert "6 evidence items" in ai.summary
    assert ai.actions == list(PLAYBOOKS["port_scan"])
    assert ai.hypotheses == [
        "Observed telemetry is consistent with port scan activity."
    ]
    assert ai.caveats


def test_mock_confidence_falls_back_to_risk() -> None:
    alert = _alert(confidence=None, risk=90)
    result = triage_alert(alert, MockProvider())
    assert result.ai.confidence == pytest.approx(0.9)


@pytest.mark.parametrize("level", ["low", "medium"])
def test_triage_rejects_non_high_levels(level: str) -> None:
    with pytest.raises(ValueError, match="high/critical"):
        triage_alert(_alert(level=level), MockProvider())


def test_playbook_defaults_for_unknown_scenario() -> None:
    for scenario in (
        "c2_beaconing",
        "dns_tunneling",
        "port_scan",
        "brute_force",
        "malware_download",
        "lateral_movement",
    ):
        assert scenario in PLAYBOOKS
        assert retrieve_playbook(scenario) != ""
    assert retrieve_playbook("other") == retrieve_playbook(None)
    assert retrieve_playbook("other") == retrieve_playbook("")
    assert "Preserve the alert evidence" in retrieve_playbook("other")

    alert = _alert(scenario=None)
    result = triage_alert(alert, MockProvider())
    assert result.ai.actions == list(PLAYBOOKS["default"])
    assert "default" in result.ai.summary


def test_redact_secrets_but_keep_network_identifiers() -> None:
    text = (
        "password=hunter2 token=abc api_key=xyz "
        "Authorization: Bearer s3cr3t ip=192.168.1.5"
    )
    redacted = redact(text)

    for secret in ("hunter2", "abc", "xyz", "s3cr3t"):
        assert secret not in redacted
    assert redacted.count("[REDACTED]") == 4
    assert "192.168.1.5" in redacted


def test_triage_redacts_provider_text() -> None:
    result = triage_alert(_alert(), SecretProvider())
    ai = result.ai

    assert "hunter2" not in ai.summary
    assert "[REDACTED]" in ai.summary
    assert all("abc123" not in caveat for caveat in ai.caveats)
    assert all("topsecret" not in caveat for caveat in ai.caveats)


def test_validate_provider_output_rejects_invalid_json() -> None:
    with pytest.raises(ValueError, match="invalid provider JSON"):
        validate_provider_output("{not json")
    with pytest.raises(ValueError, match="expected an object"):
        validate_provider_output("[]")


def test_validate_provider_output_rejects_extra_keys() -> None:
    alert = _alert()
    payload = json.loads(
        MockProvider().complete(
            TriageRequest(alert=alert, playbook=retrieve_playbook("port_scan"))
        )
    )
    payload["extra"] = "unexpected"
    with pytest.raises(ValueError, match="invalid triage output"):
        validate_provider_output(json.dumps(payload))


def test_validate_provider_output_rejects_bad_confidence() -> None:
    alert = _alert()
    payload = json.loads(
        MockProvider().complete(
            TriageRequest(alert=alert, playbook=retrieve_playbook("port_scan"))
        )
    )
    payload["confidence"] = 1.5
    with pytest.raises(ValueError, match="invalid triage output"):
        validate_provider_output(json.dumps(payload))


def test_triage_rejects_mitre_mismatch() -> None:
    with pytest.raises(ValueError, match="mitre mismatch"):
        triage_alert(_alert(), MitreMismatchProvider())


def test_triage_writes_success_audit(tmp_path: Path) -> None:
    audit = tmp_path / "audit" / "llm.jsonl"
    triage_alert(_alert(), MockProvider(), audit_path=audit)

    lines = audit.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {
        "timestamp",
        "alert_id",
        "provider",
        "ok",
        "error",
        "prompt_sha256",
    }
    assert record["alert_id"] == "alert-1"
    assert record["provider"] == "mock"
    assert record["ok"] is True
    assert record["error"] is None
    assert len(record["prompt_sha256"]) == 64


def test_triage_writes_failure_audit(tmp_path: Path) -> None:
    audit = tmp_path / "audit" / "llm.jsonl"
    with pytest.raises(ValueError, match="invalid provider JSON"):
        triage_alert(_alert(), InvalidJsonProvider(), audit_path=audit)

    record = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert record["ok"] is False
    assert record["error"]
    assert record["provider"] == "mock"
    assert len(record["prompt_sha256"]) == 64


def test_triage_alerts_filters_and_sorts() -> None:
    alerts = [
        _alert(alert_id="alert-c", level="high", risk=70),
        _alert(alert_id="alert-a", level="high", risk=90),
        _alert(alert_id="alert-z", level="critical", risk=95),
        _alert(alert_id="filtered", level="medium", risk=99),
    ]
    results = triage_alerts(alerts, MockProvider())

    assert [result.alert_id for result in results] == [
        "alert-z",
        "alert-a",
        "alert-c",
    ]


def test_mock_provider_is_deterministic() -> None:
    alert = _alert()
    provider = MockProvider()
    request = TriageRequest(alert=alert, playbook=retrieve_playbook("port_scan"))

    assert provider.complete(request) == provider.complete(request)
    assert triage_alert(alert, provider) == triage_alert(alert, provider)


def test_eval_alerts_cover_all_scenarios() -> None:
    alerts = build_eval_alerts()

    assert len(alerts) == 6
    assert {alert.scenario for alert in alerts} == {
        "port_scan",
        "brute_force",
        "malware_download",
        "c2_beaconing",
        "lateral_movement",
        "dns_tunneling",
    }
    assert all(alert.level in {"high", "critical"} for alert in alerts)
    assert len({alert.alert_id for alert in alerts}) == 6


def test_evaluate_triage_all_metrics_pass() -> None:
    metrics = evaluate_triage(build_eval_alerts(), MockProvider())

    assert metrics["triage_count"] == 6
    assert metrics["schema_valid_rate"] == 1.0
    assert metrics["mitre_accuracy"] == 1.0
    assert metrics["evidence_coverage"] == 1.0
    assert metrics["hallucination_rate"] == 0.0
    assert metrics["actionability_rate"] == 1.0


def test_evaluate_triage_detects_hallucination() -> None:
    metrics = evaluate_triage(build_eval_alerts(), BadProvider())

    assert metrics["triage_count"] == 6
    assert metrics["mitre_accuracy"] == 1.0
    assert metrics["hallucination_rate"] == 1.0


def test_summarize_triage_empty_results() -> None:
    metrics = summarize_triage(build_eval_alerts(), [])

    assert metrics["triage_count"] == 0
    assert metrics["schema_valid_rate"] == 0.0
    assert metrics["hallucination_rate"] == 0.0
