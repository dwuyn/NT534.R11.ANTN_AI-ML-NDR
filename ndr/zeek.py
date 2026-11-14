"""Parse Zeek conn.log JSON lines into normalized records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class ConnRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str | None
    duration: float | None
    orig_bytes: int
    resp_bytes: int
    orig_pkts: int
    resp_pkts: int
    conn_state: str | None


@dataclass(frozen=True)
class DnsRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    query: str
    qtype_name: str | None
    rcode_name: str | None
    answers: tuple[str, ...]
    ttls: tuple[float, ...]


def _require(obj: dict, key: str, where: str, prefix: str = "") -> object:
    if key not in obj:
        raise ValueError(f"{where}: missing field {prefix}{key}")
    return obj[key]


def _as_int(value: object, where: str, name: str, default: int = 0) -> int:
    if value is None or value == "" or value == "-":
        return default
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field {name}: {value!r}") from exc


def _as_optional_float(value: object, where: str, name: str) -> float | None:
    if value is None or value == "" or value == "-":
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field {name}: {value!r}") from exc


def _as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return None if text in ("", "-") else text


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if value is None or value == "" or value == "-":
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def _as_float_tuple(value: object) -> tuple[float, ...]:
    if value is None or value == "" or value == "-":
        return ()
    items = value if isinstance(value, (list, tuple)) else (value,)
    values: list[float] = []
    for item in items:
        if item is None or item == "" or item == "-":
            continue
        try:
            values.append(float(item))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return tuple(values)


def parse_conn_obj(obj: dict, where: str = "<obj>") -> ConnRecord:
    for name in ("ts", "uid", "proto"):
        _require(obj, name, where)

    conn_id = obj.get("id")
    if not isinstance(conn_id, dict):
        raise ValueError(f"{where}: missing field id")
    for name in ("orig_h", "orig_p", "resp_h", "resp_p"):
        _require(conn_id, name, where, prefix="id.")

    try:
        ts = float(obj["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field ts: {obj['ts']!r}") from exc

    try:
        orig_p = int(conn_id["orig_p"])
        resp_p = int(conn_id["resp_p"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid port field: {exc}") from exc

    return ConnRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=str(conn_id["orig_h"]),
        orig_p=orig_p,
        resp_h=str(conn_id["resp_h"]),
        resp_p=resp_p,
        proto=str(obj["proto"]),
        service=_as_optional_str(obj.get("service")),
        duration=_as_optional_float(obj.get("duration"), where, "duration"),
        orig_bytes=_as_int(obj.get("orig_bytes"), where, "orig_bytes"),
        resp_bytes=_as_int(obj.get("resp_bytes"), where, "resp_bytes"),
        orig_pkts=_as_int(obj.get("orig_pkts"), where, "orig_pkts"),
        resp_pkts=_as_int(obj.get("resp_pkts"), where, "resp_pkts"),
        conn_state=_as_optional_str(obj.get("conn_state")),
    )


def iter_conn_jsonl(path: Path) -> Iterator[ConnRecord]:
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno}: expected a JSON object")
            yield parse_conn_obj(obj, where=f"{path}:{lineno}")


def parse_dns_obj(obj: dict, where: str = "<obj>") -> DnsRecord:
    for name in ("ts", "uid", "query"):
        _require(obj, name, where)

    dns_id = obj.get("id")
    if not isinstance(dns_id, dict):
        raise ValueError(f"{where}: missing field id")
    for name in ("orig_h", "resp_h"):
        _require(dns_id, name, where, prefix="id.")

    try:
        ts = float(obj["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field ts: {obj['ts']!r}") from exc

    return DnsRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=str(dns_id["orig_h"]),
        orig_p=_as_int(dns_id.get("orig_p"), where, "id.orig_p"),
        resp_h=str(dns_id["resp_h"]),
        resp_p=_as_int(dns_id.get("resp_p"), where, "id.resp_p"),
        proto=str(obj.get("proto") or "udp"),
        query=str(obj["query"]),
        qtype_name=_as_optional_str(obj.get("qtype_name")),
        rcode_name=_as_optional_str(obj.get("rcode_name")),
        answers=_as_str_tuple(obj.get("answers")),
        ttls=_as_float_tuple(obj.get("TTLs")),
    )


def iter_dns_jsonl(path: Path) -> Iterator[DnsRecord]:
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{lineno}: expected a JSON object")
            yield parse_dns_obj(obj, where=f"{path}:{lineno}")
