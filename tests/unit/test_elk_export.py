from __future__ import annotations

import base64
import io
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import AlertEvent, ResponseRecommendation
from ndr.elk import ElkConfig, export_alerts


def _alert() -> AlertEvent:
    timestamp = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    return AlertEvent(
        timestamp=timestamp,
        alert_id="alrt-test",
        risk=90,
        level="critical",
        entities={"src_ip": "192.168.217.132"},
        evidence={"detections": ["fs-1"]},
        response=ResponseRecommendation(recommended="monitor"),
    )


class _Response:
    status = 201

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def read(self) -> bytes:
        return b"{}"


def test_export_api_key_payload_and_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []

    def fake_urlopen(request, context=None, timeout=None):
        captured.append(request)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    alert = _alert()
    count = export_alerts(
        [alert], ElkConfig(url="https://elk:9200/", api_key="secret")
    )

    assert count == 1
    request = captured[0]
    assert request.full_url == "https://elk:9200/ndr-alerts/_doc?refresh=true"
    assert request.get_header("Authorization") == "ApiKey secret"
    assert request.get_header("Content-type") == "application/json"
    payload = json.loads(request.data)
    assert payload["@timestamp"] == payload["timestamp"]
    assert payload["alert_id"] == "alrt-test"


def test_export_basic_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[urllib.request.Request] = []

    def fake_urlopen(request, context=None, timeout=None):
        captured.append(request)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    export_alerts(
        [_alert()],
        ElkConfig(url="https://elk:9200", username="user", password="pass"),
    )

    token = base64.b64encode(b"user:pass").decode("ascii")
    assert captured[0].get_header("Authorization") == f"Basic {token}"


def test_empty_export_does_not_call_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("unexpected network call"),
    )
    assert export_alerts([], ElkConfig(url="https://elk:9200", api_key="secret")) == 0


def test_invalid_config(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires api_key or username/password"):
        ElkConfig(url="https://elk:9200")
    with pytest.raises(ValueError, match="requires api_key or username/password"):
        ElkConfig(
            url="https://elk:9200", api_key="key", username="u", password="p"
        )
    with pytest.raises(ValueError, match="must start with"):
        ElkConfig(url="elk:9200", api_key="key")
    with pytest.raises(FileNotFoundError):
        ElkConfig(
            url="https://elk:9200",
            api_key="key",
            ca_cert=tmp_path / "missing.crt",
        )


def test_from_env_treats_empty_values_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "NDR_ES_URL",
        "NDR_ES_API_KEY",
        "NDR_ES_USER",
        "NDR_ES_PASSWORD",
        "NDR_ES_CA_CERT",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValueError, match="NDR_ES_URL is required"):
        ElkConfig.from_env()

    monkeypatch.setenv("NDR_ES_URL", "https://elk:9200")
    monkeypatch.setenv("NDR_ES_API_KEY", "secret")
    monkeypatch.setenv("NDR_ES_USER", "")
    assert ElkConfig.from_env().api_key == "secret"


def test_http_error_becomes_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(request, context=None, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "Bad Request",
            {},
            io.BytesIO(b"bad request"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    with pytest.raises(RuntimeError, match="HTTP 400: bad request"):
        export_alerts([_alert()], ElkConfig(url="https://elk:9200", api_key="secret"))
