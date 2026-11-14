from __future__ import annotations

import json
from pathlib import Path

from ndr.llm.contracts import TriageResult
from ndr.llm.eval import build_eval_alerts, evaluate_triage
from ndr.llm.provider import MockProvider
from ndr.llm.triage import triage_alerts


def test_llm_triage_pipeline_end_to_end(tmp_path: Path) -> None:
    alerts = build_eval_alerts()
    audit = tmp_path / "audit" / "llm.jsonl"

    results = triage_alerts(alerts, MockProvider(), audit_path=audit)

    assert len(results) == len(alerts)
    assert {result.alert_id for result in results} == {
        alert.alert_id for alert in alerts
    }
    for result in results:
        TriageResult.model_validate_json(result.model_dump_json())
        assert result.ai.model == "mock"
        assert result.ai.actions
        assert result.ai.mitre == next(
            alert.mitre for alert in alerts if alert.alert_id == result.alert_id
        )

    records = [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == len(alerts)
    assert all(record["ok"] is True for record in records)
    assert all(record["error"] is None for record in records)
    assert all(record["provider"] == "mock" for record in records)
    assert all(len(record["prompt_sha256"]) == 64 for record in records)

    metrics = evaluate_triage(alerts, MockProvider())
    assert metrics == {
        "schema_valid_rate": 1.0,
        "mitre_accuracy": 1.0,
        "evidence_coverage": 1.0,
        "hallucination_rate": 0.0,
        "actionability_rate": 1.0,
        "triage_count": 6,
    }
