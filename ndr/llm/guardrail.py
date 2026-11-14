"""Output validation and secret redaction for LLM triage."""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from ndr.llm.contracts import TriageOutput

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|token|api_key)\s*=\s*[^\s,;]+"),
    re.compile(r"(?i)\bauthorization\s*:\s*(?:[A-Za-z]+\s+)?[^\s,;]+"),
)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(text: str) -> str:
    """Replace inline credentials, leaving IPs and domains intact."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def validate_provider_output(text: str) -> TriageOutput:
    """Parse and strictly validate a raw provider response."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid provider JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid provider JSON: expected an object")
    try:
        return TriageOutput.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid triage output: {exc}") from exc


def ipv4_addresses(text: str) -> set[str]:
    """Return every IPv4 literal found in ``text``."""
    return set(_IPV4_PATTERN.findall(text))
