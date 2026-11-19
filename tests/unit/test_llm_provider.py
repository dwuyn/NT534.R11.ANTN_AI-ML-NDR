from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Self

import pytest

from ndr.cli import _build_parser
from ndr.contracts import AlertEvent, Mitre, ResponseRecommendation
from ndr.llm.provider import (
    MockProvider,
    OpenAICompatibleProvider,
    TriageRequest,
)
from ndr.llm.rag import retrieve_playbook
from ndr.llm.triage import triage_alert


def _alert() -> AlertEvent:
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    return AlertEvent(
        timestamp=moment,
        first_seen=moment,
        last_seen=moment,
        alert_id="alert-1",
        risk=90,
        level="high",
        confidence=0.97,
        scenario="port_scan",
        entities={"src_ip": "192.168.217.132", "dst_ip": "192.168.217.10"},
        evidence={
            "detections": ["fs-1", "fs-2", "fs-3"],
            "uids": ["C-1", "C-2", "C-3"],
            "models": [],
            "rules": [],
            "anomaly_detections": [],
        },
        mitre=Mitre(tactic=["TA0007"], technique=["T1046"]),
        response=ResponseRecommendation(recommended="notify_and_request_approval"),
    )


def _request() -> TriageRequest:
    return TriageRequest(
        alert=_alert(),
        playbook=retrieve_playbook("port_scan"),
    )


class _Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


def _fake_urlopen(
    monkeypatch: pytest.MonkeyPatch,
    *,
    body: bytes = b"",
    error: Exception | None = None,
) -> list[tuple[urllib.request.Request, float | None]]:
    calls: list[tuple[urllib.request.Request, float | None]] = []

    def urlopen(
        request: urllib.request.Request, timeout: float | None = None
    ) -> _Response:
        calls.append((request, timeout))
        if error is not None:
            raise error
        return _Response(body)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return calls


def _envelope(content: str) -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def test_provider_posts_openai_chat_request(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _request()
    content = MockProvider().complete(request)
    calls = _fake_urlopen(monkeypatch, body=_envelope(content))

    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1",
        model="Qwen/Qwen2.5-7B-Instruct",
        api_key="secret",
    )

    assert provider.complete(request) == content
    sent, timeout = calls[0]
    assert sent.full_url == "https://abc.ngrok-free.app/v1/chat/completions"
    assert sent.headers["Authorization"] == "Bearer secret"
    assert sent.headers["Content-type"] == "application/json"
    assert timeout == 120.0

    payload = json.loads(sent.data)
    assert payload["model"] == "Qwen/Qwen2.5-7B-Instruct"
    assert payload["temperature"] == 0.0
    assert payload["max_tokens"] == 700
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["messages"][0]["role"] == "system"
    assert "TriageOutput" in payload["messages"][0]["content"]
    assert payload["messages"][1]["role"] == "user"
    assert payload["messages"][1]["content"].startswith("PLAYBOOK:")


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        (
            "https://abc.ngrok-free.app",
            "https://abc.ngrok-free.app/v1/chat/completions",
        ),
        (
            "https://abc.ngrok-free.app/v1/",
            "https://abc.ngrok-free.app/v1/chat/completions",
        ),
        (
            "https://abc.ngrok-free.app/v1/chat/completions",
            "https://abc.ngrok-free.app/v1/chat/completions",
        ),
    ],
)
def test_provider_normalizes_chat_url(base_url: str, expected: str) -> None:
    provider = OpenAICompatibleProvider(base_url=base_url, model="m")
    assert provider._chat_url == expected


def test_provider_without_auth_or_json_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_urlopen(monkeypatch, body=_envelope("{}"))
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1",
        model="m",
        json_mode=False,
    )

    assert provider.complete(_request()) == "{}"
    sent, _ = calls[0]
    assert "Authorization" not in sent.headers
    assert "response_format" not in json.loads(sent.data)


def test_provider_joins_content_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": "{"},
                            {"type": "text", "text": "}"},
                        ]
                    }
                }
            ]
        }
    ).encode()
    _fake_urlopen(monkeypatch, body=body)
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1", model="m"
    )

    assert provider.complete(_request()) == "{}"


def test_provider_http_error_is_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = urllib.error.HTTPError(
        "https://abc.ngrok-free.app/v1/chat/completions",
        401,
        "Unauthorized",
        None,
        io.BytesIO(b"bad key"),
    )
    _fake_urlopen(monkeypatch, error=error)
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1", model="m"
    )

    with pytest.raises(RuntimeError, match="HTTP 401: bad key"):
        provider.complete(_request())


def test_provider_network_error_is_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_urlopen(monkeypatch, error=urllib.error.URLError("dns failure"))
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1", model="m"
    )

    with pytest.raises(RuntimeError, match="dns failure"):
        provider.complete(_request())


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        b'{"choices": []}',
        b'{"choices": [{"message": {"content": ""}}]}',
        b'{"choices": [{"message": {"content": 3}}]}',
    ],
)
def test_provider_rejects_bad_response(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    _fake_urlopen(monkeypatch, body=body)
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1", model="m"
    )

    with pytest.raises(RuntimeError):
        provider.complete(_request())


def test_openai_provider_goes_through_triage_guardrail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alert = _alert()
    content = MockProvider().complete(_request())
    _fake_urlopen(monkeypatch, body=_envelope(content))
    provider = OpenAICompatibleProvider(
        base_url="https://abc.ngrok-free.app/v1",
        model="Qwen/Qwen2.5-7B-Instruct",
    )

    result = triage_alert(alert, provider)

    assert result.ai.model == "openai-compatible:Qwen/Qwen2.5-7B-Instruct"
    assert result.ai.mitre == alert.mitre
    assert result.ai.evidence == ["fs-1", "fs-2", "fs-3", "C-1", "C-2", "C-3"]


def test_from_env_reads_remote_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NDR_LLM_BASE_URL", "https://abc.ngrok-free.app/v1")
    monkeypatch.setenv("NDR_LLM_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    monkeypatch.setenv("NDR_LLM_API_KEY", "secret")
    monkeypatch.setenv("NDR_LLM_TIMEOUT", "30")
    monkeypatch.setenv("NDR_LLM_MAX_TOKENS", "512")

    provider = OpenAICompatibleProvider.from_env()

    assert provider.base_url == "https://abc.ngrok-free.app/v1"
    assert provider.model == "Qwen/Qwen2.5-7B-Instruct"
    assert provider.api_key == "secret"
    assert provider.timeout == 30.0
    assert provider.max_tokens == 512


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_url": "ftp://x", "model": "m"},
        {"base_url": "https://x", "model": ""},
        {"base_url": "https://x", "model": "m", "timeout": 0},
        {"base_url": "https://x", "model": "m", "max_tokens": 0},
        {"base_url": "https://x", "model": "m", "temperature": 3.0},
    ],
)
def test_provider_rejects_invalid_config(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(**kwargs)


def test_cli_accepts_remote_provider_options() -> None:
    args = _build_parser().parse_args(
        [
            "llm-eval",
            "--provider",
            "openai",
            "--base-url",
            "https://abc.ngrok-free.app/v1",
            "--model",
            "Qwen/Qwen2.5-7B-Instruct",
            "--no-json-mode",
        ]
    )

    assert args.provider == "openai"
    assert args.base_url == "https://abc.ngrok-free.app/v1"
    assert args.model == "Qwen/Qwen2.5-7B-Instruct"
    assert args.json_mode is False
