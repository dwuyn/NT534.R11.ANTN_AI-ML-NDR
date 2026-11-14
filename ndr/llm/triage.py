"""High/critical alert triage through a provider boundary."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from ndr.contracts import AiSummary, AlertEvent
from ndr.llm.audit import write_audit
from ndr.llm.contracts import TriageResult
from ndr.llm.guardrail import redact, validate_provider_output
from ndr.llm.provider import TriageProvider, TriageRequest
from ndr.llm.rag import retrieve_playbook

TRIAGE_LEVELS = frozenset({"high", "critical"})


def _prompt(request: TriageRequest) -> str:
    return f"PLAYBOOK:\n{request.playbook}\nALERT:\n{request.alert.model_dump_json()}"


def _audit_record(
    alert: AlertEvent,
    provider: TriageProvider,
    prompt_sha256: str,
    *,
    ok: bool,
    error: str | None,
) -> dict:
    return {
        "timestamp": alert.timestamp.isoformat(),
        "alert_id": alert.alert_id,
        "provider": provider.name,
        "ok": ok,
        "error": error,
        "prompt_sha256": prompt_sha256,
    }


def triage_alert(
    alert: AlertEvent,
    provider: TriageProvider,
    audit_path: Path | None = None,
) -> TriageResult:
    if alert.level not in TRIAGE_LEVELS:
        raise ValueError("LLM triage only for high/critical")

    playbook = retrieve_playbook(alert.scenario)
    request = TriageRequest(alert=alert, playbook=playbook)
    prompt_sha256 = hashlib.sha256(_prompt(request).encode("utf-8")).hexdigest()

    try:
        raw = provider.complete(request)
        output = validate_provider_output(raw)
        if output.mitre != alert.mitre:
            raise ValueError("mitre mismatch")
        ai = AiSummary(
            summary=redact(output.summary),
            model=provider.name,
            confidence=output.confidence,
            evidence=[redact(item) for item in output.evidence],
            hypotheses=[redact(item) for item in output.hypotheses],
            actions=list(output.actions),
            mitre=output.mitre,
            caveats=[redact(item) for item in output.caveats],
        )
    except Exception as exc:
        if audit_path is not None:
            write_audit(
                audit_path,
                _audit_record(
                    alert,
                    provider,
                    prompt_sha256,
                    ok=False,
                    error=str(exc),
                ),
            )
        raise

    if audit_path is not None:
        write_audit(
            audit_path,
            _audit_record(
                alert,
                provider,
                prompt_sha256,
                ok=True,
                error=None,
            ),
        )
    return TriageResult(alert_id=alert.alert_id, ai=ai)


def triage_alerts(
    alerts: Sequence[AlertEvent],
    provider: TriageProvider,
    audit_path: Path | None = None,
) -> list[TriageResult]:
    eligible = [alert for alert in alerts if alert.level in TRIAGE_LEVELS]
    eligible.sort(key=lambda alert: (-alert.risk, alert.alert_id))
    return [
        triage_alert(alert, provider, audit_path=audit_path) for alert in eligible
    ]
