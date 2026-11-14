"""Response guardrail policy and allowlist loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ResponsePolicy:
    """Thresholds and limits applied to automated response decisions."""

    min_risk: int = 85
    min_confidence: float = 0.9
    ttl_seconds: int = 3600
    max_actions_per_minute: int = 10
    allowlist: frozenset[str] = frozenset()


def load_allowlist(path: str | Path) -> frozenset[str]:
    """Load a JSON list of allowlisted IP addresses from ``path``."""

    allowlist_path = Path(path)
    if not allowlist_path.exists():
        raise FileNotFoundError(f"allowlist not found: {allowlist_path}")
    data = json.loads(allowlist_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{allowlist_path}: allowlist must be a JSON list")
    if not all(isinstance(item, str) for item in data):
        raise ValueError(f"{allowlist_path}: allowlist entries must be strings")
    return frozenset(data)
