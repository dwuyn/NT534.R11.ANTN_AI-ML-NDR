"""Provider boundary for LLM triage, with mock and OpenAI-compatible servers."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from ndr.contracts import AlertEvent
from ndr.llm.contracts import TriageOutput
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
                (
                    "Observed telemetry is consistent with "
                    f"{scenario.replace('_', ' ')} activity."
                )
            ],
            "mitre": alert.mitre.model_dump(),
            "actions": list(PLAYBOOKS.get(scenario, PLAYBOOKS["default"])),
            "confidence": confidence,
            "caveats": ["Synthetic mock provider; not a real LLM."],
        }
        return json.dumps(payload)


_SYSTEM_PROMPT = (
    "You are a defensive network detection and response (NDR) triage assistant. "
    "Return exactly one JSON object and nothing else: no markdown fences, no prose. "
    "The object must validate against this JSON schema:\n"
    f"{json.dumps(TriageOutput.model_json_schema(), separators=(',', ':'), sort_keys=True)}\n"
    "Rules:\n"
    "- Copy the alert's mitre object exactly; never invent tactics or techniques.\n"
    "- evidence may contain only IDs present in alert.evidence.detections or "
    "alert.evidence.uids.\n"
    "- actions may contain only actions from the supplied playbook.\n"
    "- confidence must be a number from 0.0 to 1.0; lower it when uncertain.\n"
    "- If evidence is insufficient, say so in caveats instead of inventing facts."
)


@dataclass(frozen=True)
class OpenAICompatibleProvider:
    """HTTP client for vLLM/llama.cpp exposed through ngrok or a local URL."""

    base_url: str
    model: str
    api_key: str | None = None
    timeout: float = 120.0
    max_tokens: int = 700
    temperature: float = 0.0
    json_mode: bool = True

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if not self.model.strip():
            raise ValueError("model is required")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))
        if self.api_key is not None and not self.api_key.strip():
            object.__setattr__(self, "api_key", None)

    @property
    def name(self) -> str:
        return f"openai-compatible:{self.model}"

    @classmethod
    def from_env(
        cls,
        *,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = True,
    ) -> OpenAICompatibleProvider:
        """Build from NDR_LLM_* variables, with explicit arguments taking priority."""

        def env(name: str) -> str | None:
            value = os.environ.get(name, "").strip()
            return value or None

        base_url = base_url or env("NDR_LLM_BASE_URL")
        model = model or env("NDR_LLM_MODEL")
        api_key = api_key or env("NDR_LLM_API_KEY")
        if not base_url:
            raise ValueError("NDR_LLM_BASE_URL is required")
        if not model:
            raise ValueError("NDR_LLM_MODEL is required")
        if timeout is None:
            raw = env("NDR_LLM_TIMEOUT")
            try:
                timeout = float(raw) if raw else 120.0
            except ValueError as exc:
                raise ValueError("NDR_LLM_TIMEOUT must be a number") from exc
        if max_tokens is None:
            raw = env("NDR_LLM_MAX_TOKENS")
            try:
                max_tokens = int(raw) if raw else 700
            except ValueError as exc:
                raise ValueError("NDR_LLM_MAX_TOKENS must be an integer") from exc
        return cls(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=timeout,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )

    @property
    def _chat_url(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/chat/completions"
        return f"{self.base_url}/v1/chat/completions"

    def complete(self, request: TriageRequest) -> str:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"PLAYBOOK:\n{request.playbook}\n"
                        f"ALERT:\n{request.alert.model_dump_json()}"
                    ),
                },
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        http_request = urllib.request.Request(
            self._chat_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                http_request, timeout=self.timeout
            ) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"LLM request failed: HTTP {exc.code}: {detail[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError(
                f"LLM request failed: timed out after {self.timeout:g}s"
            ) from exc

        try:
            envelope = json.loads(body)
            content = envelope["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                "LLM response missing choices[0].message.content"
            ) from exc

        if isinstance(content, list):
            parts = [
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            ]
            content = "".join(parts)
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("LLM response content is empty")
        return content
