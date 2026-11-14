"""Provider boundary for LLM triage, with a deterministic mock provider."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from ndr.contracts import AlertEvent
from ndr.llm.rag import PLAYBOOKS


@dataclass(frozen=True)
class TriageRequest:
    alert: AlertEvent
    playbook: str


class TriageProvider(Protocol):
    name: str

    def complete(self, request: TriageRequest) -> str: ...


class MockProvider:
    """Deterministic, offline stand-in for a real LLM provider."""

    name = "mock"

    def complete(self, request: TriageRequest) -> str:
        alert = request.alert
        scenario = alert.scenario or "default"
        detections = alert.evidence.get("detections", [])
        uids = alert.evidence.get("uids", [])
        evidence = [*detections[:3], *uids[:3]]
        confidence = alert.confidence or alert.risk / 100
        payload = {
            "summary": (
                f"{scenario} alert {alert.alert_id} scored risk {alert.risk} "
                f"with {len(evidence)} evidence items."
            ),
            "evidence": evidence,
            "hypotheses": [
                "Observed telemetry is consistent with "
                f"{scenario.replace('_', ' ')} activity."
            ],
            "mitre": alert.mitre.model_dump(),
            "actions": list(PLAYBOOKS.get(scenario, PLAYBOOKS["default"])),
            "confidence": confidence,
            "caveats": ["Synthetic mock provider; not a real LLM."],
        }
        return json.dumps(payload)
