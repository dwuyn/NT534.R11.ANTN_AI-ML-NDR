"""Append-only JSONL audit trail for LLM triage calls."""

from __future__ import annotations

import json
from pathlib import Path


def write_audit(path: Path, record: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, default=str, sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
