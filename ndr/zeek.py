"""Parse Zeek conn.log JSON lines into normalized records."""

from __future__ import annotations

import json
from collections.abc import Callable
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


@dataclass(frozen=True)
class SshRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    auth_success: bool
    auth_attempts: int
    client: str | None


@dataclass(frozen=True)
class FtpRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    user: str | None
    command: str | None
    reply_code: int | None


@dataclass(frozen=True)
class HttpRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    method: str
    host: str
    uri: str
    status_code: int | None
    user_agent: str | None
    resp_body_len: int
    mime_type: str | None
    fuid: str | None


@dataclass(frozen=True)
class FileRecord:
    ts: float
    fuid: str
    tx_hosts: tuple[str, ...]
    rx_hosts: tuple[str, ...]
    source: str | None
    filename: str | None
    mime_type: str | None
    seen_bytes: int
    total_bytes: int
    md5: str | None
    sha1: str | None
    sha256: str | None


@dataclass(frozen=True)
class SslRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    ja3: str | None
    ja4: str | None
    sni: str | None


@dataclass(frozen=True)
class IntelRecord:
    ts: float
    indicator: str
    indicator_type: str | None
    seen_where: str | None


@dataclass(frozen=True)
class SmbMappingRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    path: str | None
    service: str | None


@dataclass(frozen=True)
class SmbFilesRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    action: str | None
    path: str | None
    name: str | None
    size: int


@dataclass(frozen=True)
class DceRpcRecord:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    endpoint: str | None
    operation: str | None
    named_pipe: str | None


def _as_bool(
    value: object, where: str, name: str, default: bool = False
) -> bool:
    if value is None or value == "" or value == "-":
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"t", "true", "1", "yes"}:
        return True
    if text in {"f", "false", "0", "no"}:
        return False
    raise ValueError(f"{where}: invalid field {name}: {value!r}")


def _as_optional_int(value: object, where: str, name: str) -> int | None:
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field {name}: {value!r}") from exc


def _as_first_str(value: object) -> str | None:
    values = _as_str_tuple(value)
    return values[0] if values else None


def _ts(obj: dict, where: str) -> float:
    _require(obj, "ts", where)
    try:
        return float(obj["ts"])  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where}: invalid field ts: {obj['ts']!r}") from exc


def _endpoints(obj: dict, where: str) -> tuple[str, int, str, int]:
    conn_id = obj.get("id")
    if not isinstance(conn_id, dict):
        raise ValueError(f"{where}: missing field id")
    for name in ("orig_h", "resp_h"):
        _require(conn_id, name, where, prefix="id.")
    return (
        str(conn_id["orig_h"]),
        _as_int(conn_id.get("orig_p"), where, "id.orig_p"),
        str(conn_id["resp_h"]),
        _as_int(conn_id.get("resp_p"), where, "id.resp_p"),
    )


def _iter_jsonl(path: Path, parser: Callable[[dict, str], object]) -> Iterator[object]:
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
            yield parser(obj, f"{path}:{lineno}")


def parse_ssh_obj(obj: dict, where: str = "<obj>") -> SshRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return SshRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        auth_success=_as_bool(obj.get("auth_success"), where, "auth_success"),
        auth_attempts=_as_int(obj.get("auth_attempts"), where, "auth_attempts"),
        client=_as_optional_str(obj.get("client")),
    )


def iter_ssh_jsonl(path: Path) -> Iterator[SshRecord]:
    yield from _iter_jsonl(path, parse_ssh_obj)  # type: ignore[misc]


def parse_ftp_obj(obj: dict, where: str = "<obj>") -> FtpRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return FtpRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        user=_as_optional_str(obj.get("user")),
        command=_as_optional_str(obj.get("command")),
        reply_code=_as_optional_int(obj.get("reply_code"), where, "reply_code"),
    )


def iter_ftp_jsonl(path: Path) -> Iterator[FtpRecord]:
    yield from _iter_jsonl(path, parse_ftp_obj)  # type: ignore[misc]


def parse_http_obj(obj: dict, where: str = "<obj>") -> HttpRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return HttpRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        method=_as_optional_str(obj.get("method")) or "",
        host=_as_optional_str(obj.get("host")) or "",
        uri=_as_optional_str(obj.get("uri")) or "",
        status_code=_as_optional_int(obj.get("status_code"), where, "status_code"),
        user_agent=_as_optional_str(obj.get("user_agent")),
        resp_body_len=_as_int(obj.get("resp_body_len"), where, "resp_body_len"),
        mime_type=_as_first_str(obj.get("resp_mime_types")),
        fuid=_as_first_str(obj.get("resp_fuids")),
    )


def iter_http_jsonl(path: Path) -> Iterator[HttpRecord]:
    yield from _iter_jsonl(path, parse_http_obj)  # type: ignore[misc]


def parse_files_obj(obj: dict, where: str = "<obj>") -> FileRecord:
    _require(obj, "fuid", where)
    ts = _ts(obj, where)
    return FileRecord(
        ts=ts,
        fuid=str(obj["fuid"]),
        tx_hosts=_as_str_tuple(obj.get("tx_hosts")),
        rx_hosts=_as_str_tuple(obj.get("rx_hosts")),
        source=_as_optional_str(obj.get("source")),
        filename=_as_optional_str(obj.get("filename")),
        mime_type=_as_optional_str(obj.get("mime_type")),
        seen_bytes=_as_int(obj.get("seen_bytes"), where, "seen_bytes"),
        total_bytes=_as_int(obj.get("total_bytes"), where, "total_bytes"),
        md5=_as_optional_str(obj.get("md5")),
        sha1=_as_optional_str(obj.get("sha1")),
        sha256=_as_optional_str(obj.get("sha256")),
    )


def iter_files_jsonl(path: Path) -> Iterator[FileRecord]:
    yield from _iter_jsonl(path, parse_files_obj)  # type: ignore[misc]


def parse_ssl_obj(obj: dict, where: str = "<obj>") -> SslRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return SslRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        ja3=_as_optional_str(obj.get("ja3")),
        ja4=_as_optional_str(obj.get("ja4")),
        sni=_as_optional_str(obj.get("server_name")),
    )


def iter_ssl_jsonl(path: Path) -> Iterator[SslRecord]:
    yield from _iter_jsonl(path, parse_ssl_obj)  # type: ignore[misc]


def parse_intel_obj(obj: dict, where: str = "<obj>") -> IntelRecord:
    _require(obj, "indicator", where)
    ts = _ts(obj, where)
    return IntelRecord(
        ts=ts,
        indicator=str(obj["indicator"]),
        indicator_type=_as_optional_str(obj.get("indicator_type")),
        seen_where=_as_optional_str(obj.get("seen_where")),
    )


def iter_intel_jsonl(path: Path) -> Iterator[IntelRecord]:
    yield from _iter_jsonl(path, parse_intel_obj)  # type: ignore[misc]


def parse_smb_mapping_obj(obj: dict, where: str = "<obj>") -> SmbMappingRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return SmbMappingRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        path=_as_optional_str(obj.get("path")),
        service=_as_optional_str(obj.get("service")),
    )


def iter_smb_mapping_jsonl(path: Path) -> Iterator[SmbMappingRecord]:
    yield from _iter_jsonl(path, parse_smb_mapping_obj)  # type: ignore[misc]


def parse_smb_files_obj(obj: dict, where: str = "<obj>") -> SmbFilesRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return SmbFilesRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        action=_as_optional_str(obj.get("action")),
        path=_as_optional_str(obj.get("path")),
        name=_as_optional_str(obj.get("name")),
        size=_as_int(obj.get("size"), where, "size"),
    )


def iter_smb_files_jsonl(path: Path) -> Iterator[SmbFilesRecord]:
    yield from _iter_jsonl(path, parse_smb_files_obj)  # type: ignore[misc]


def parse_dce_rpc_obj(obj: dict, where: str = "<obj>") -> DceRpcRecord:
    _require(obj, "uid", where)
    ts = _ts(obj, where)
    orig_h, orig_p, resp_h, resp_p = _endpoints(obj, where)
    return DceRpcRecord(
        ts=ts,
        uid=str(obj["uid"]),
        orig_h=orig_h,
        orig_p=orig_p,
        resp_h=resp_h,
        resp_p=resp_p,
        endpoint=_as_optional_str(obj.get("endpoint")),
        operation=_as_optional_str(obj.get("operation")),
        named_pipe=_as_optional_str(obj.get("named_pipe")),
    )


def iter_dce_rpc_jsonl(path: Path) -> Iterator[DceRpcRecord]:
    yield from _iter_jsonl(path, parse_dce_rpc_obj)  # type: ignore[misc]
