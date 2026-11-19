"""Write fused NDR alerts to an Elasticsearch ``ndr-alerts`` index."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ndr.contracts import AlertEvent


@dataclass(frozen=True)
class ElkConfig:
    url: str
    index: str = "ndr-alerts"
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    ca_cert: Path | None = None
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("Elasticsearch URL must start with http:// or https://")
        object.__setattr__(self, "url", self.url.rstrip("/"))
        has_api_key = bool(self.api_key)
        has_basic = bool(self.username) and bool(self.password)
        if has_api_key == has_basic:
            raise ValueError(
                "ElkConfig requires api_key or username/password"
            )
        if self.ca_cert is not None:
            ca_cert = Path(self.ca_cert)
            if not ca_cert.is_file():
                raise FileNotFoundError(ca_cert)
            object.__setattr__(self, "ca_cert", ca_cert)

    @classmethod
    def from_env(cls, index: str = "ndr-alerts") -> ElkConfig:
        def value(name: str) -> str | None:
            raw = os.environ.get(name)
            return raw if raw else None

        url = value("NDR_ES_URL")
        if url is None:
            raise ValueError("NDR_ES_URL is required")
        ca_cert = value("NDR_ES_CA_CERT")
        return cls(
            url=url,
            index=index,
            api_key=value("NDR_ES_API_KEY"),
            username=value("NDR_ES_USER"),
            password=value("NDR_ES_PASSWORD"),
            ca_cert=Path(ca_cert) if ca_cert else None,
        )


def _authorization(config: ElkConfig) -> str:
    if config.api_key:
        return f"ApiKey {config.api_key}"
    credentials = f"{config.username}:{config.password}".encode()
    token = base64.b64encode(credentials).decode("ascii")
    return f"Basic {token}"


def export_alerts(alerts: Sequence[AlertEvent], config: ElkConfig) -> int:
    if not alerts:
        return 0

    context = (
        ssl.create_default_context(cafile=str(config.ca_cert))
        if config.ca_cert is not None
        else ssl.create_default_context()
    )
    url = f"{config.url}/{config.index}/_doc?refresh=true"
    headers = {
        "Content-Type": "application/json",
        "Authorization": _authorization(config),
    }

    exported = 0
    for alert in alerts:
        payload = alert.model_dump(mode="json")
        payload["@timestamp"] = payload["timestamp"]
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, context=context, timeout=config.timeout
            ) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"ELK export failed: HTTP {exc.code}: {body[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"ELK export failed: {exc.reason}") from exc
        exported += 1
    return exported
