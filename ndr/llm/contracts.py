"""Strict contracts for the mock LLM triage boundary."""

from __future__ import annotations

from pydantic import Field

from ndr.contracts import AiSummary, Mitre, StrictModel


class TriageOutput(StrictModel):
    summary: str
    evidence: list[str]
    hypotheses: list[str]
    mitre: Mitre
    actions: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    caveats: list[str]


class TriageResult(StrictModel):
    alert_id: str
    ai: AiSummary
