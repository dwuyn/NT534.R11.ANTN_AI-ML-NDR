"""Deterministic response decisions and a simulated action log.

Nothing in this module touches a real firewall or network API. Decisions are
policy checks and every applied action is recorded as ``simulated``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ndr.contracts import AlertEvent
from ndr.response.policy import ResponsePolicy

DENY_MISSING_TARGET = "missing_target"
DENY_RISK = "risk_below_threshold"
DENY_CONFIDENCE = "confidence_below_threshold"
DENY_ALLOWLIST = "allowlisted"
DENY_RATE_LIMIT = "rate_limited"
ALLOW_POLICY = "policy_allow"

ACTION_BLOCK_IP = "block_ip"


@dataclass
class ResponseDecision:
    """Outcome of evaluating one alert against a :class:`ResponsePolicy`."""

    alert_id: str
    action: str
    target: str | None
    allowed: bool
    reason: str
    ttl_seconds: int
    simulated: bool = True


def decide_response(
    alert: AlertEvent,
    policy: ResponsePolicy,
    recent_actions: int = 0,
) -> ResponseDecision:
    """Decide whether ``alert`` may trigger a simulated network block.

    Checks run in a fixed order so the resulting reason is deterministic:
    missing target, risk threshold, confidence threshold, allowlist, rate limit.
    """

    target = alert.entities.get("src_ip")

    def denied(reason: str) -> ResponseDecision:
        return ResponseDecision(
            alert_id=alert.alert_id,
            action=ACTION_BLOCK_IP,
            target=target,
            allowed=False,
            reason=reason,
            ttl_seconds=0,
        )

    if not target:
        return denied(DENY_MISSING_TARGET)
    if alert.risk < policy.min_risk:
        return denied(DENY_RISK)
    if (alert.confidence or 0.0) < policy.min_confidence:
        return denied(DENY_CONFIDENCE)
    if target in policy.allowlist:
        return denied(DENY_ALLOWLIST)
    if recent_actions >= policy.max_actions_per_minute:
        return denied(DENY_RATE_LIMIT)
    return ResponseDecision(
        alert_id=alert.alert_id,
        action=ACTION_BLOCK_IP,
        target=target,
        allowed=True,
        reason=ALLOW_POLICY,
        ttl_seconds=policy.ttl_seconds,
    )


def _iso_timestamp(timestamp: datetime | float | int | str) -> str:
    if isinstance(timestamp, datetime):
        moment = timestamp
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    elif isinstance(timestamp, (float, int)):
        moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    else:
        return timestamp
    return moment.isoformat()


@dataclass
class ResponseSimulator:
    """Append-only log of simulated blocks and rollbacks."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def apply(
        self, decision: ResponseDecision, timestamp: datetime | float | int | str
    ) -> dict[str, Any] | None:
        """Record an allowed decision; denied decisions are ignored."""

        if not decision.allowed:
            return None
        record = {
            "type": decision.action,
            "alert_id": decision.alert_id,
            "target": decision.target,
            "ttl_seconds": decision.ttl_seconds,
            "reason": decision.reason,
            "timestamp": _iso_timestamp(timestamp),
            "simulated": True,
        }
        self.records.append(record)
        return record

    def rollback(
        self, alert_id: str, timestamp: datetime | float | int | str
    ) -> dict[str, Any]:
        """Record a rollback for the most recent block of ``alert_id``."""

        target: str | None = None
        for record in reversed(self.records):
            if record["type"] == ACTION_BLOCK_IP and record["alert_id"] == alert_id:
                target = record["target"]
                break
        record = {
            "type": "rollback",
            "alert_id": alert_id,
            "target": target,
            "timestamp": _iso_timestamp(timestamp),
            "simulated": True,
        }
        self.records.append(record)
        return record

    def write_jsonl(self, path: str | Path) -> None:
        """Write all records as JSONL."""

        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for record in self.records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
