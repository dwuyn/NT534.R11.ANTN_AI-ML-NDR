from __future__ import annotations

from pathlib import Path

import pytest

from ndr.zeek import (
    iter_dce_rpc_jsonl,
    iter_files_jsonl,
    iter_ftp_jsonl,
    iter_http_jsonl,
    iter_intel_jsonl,
    iter_smb_files_jsonl,
    iter_smb_mapping_jsonl,
    iter_ssh_jsonl,
    iter_ssl_jsonl,
    parse_dce_rpc_obj,
    parse_files_obj,
    parse_ftp_obj,
    parse_http_obj,
    parse_intel_obj,
    parse_smb_files_obj,
    parse_smb_mapping_obj,
    parse_ssh_obj,
    parse_ssl_obj,
)


def _id(src: str = "10.0.0.1", dst: str = "10.0.0.2") -> dict:
    return {
        "orig_h": src,
        "orig_p": 40000,
        "resp_h": dst,
        "resp_p": 22,
    }


def test_ssh_full_and_defaults() -> None:
    record = parse_ssh_obj(
        {
            "ts": 1.5,
            "uid": "C1",
            "id": _id(),
            "auth_success": "T",
            "auth_attempts": 3,
            "client": "OpenSSH_9.0",
        }
    )
    assert record.ts == 1.5
    assert record.auth_success is True
    assert record.auth_attempts == 3
    assert record.client == "OpenSSH_9.0"

    defaulted = parse_ssh_obj({"ts": 2, "uid": "C2", "id": _id()})
    assert defaulted.auth_success is False
    assert defaulted.auth_attempts == 0
    assert defaulted.client is None


def test_ftp_full_and_optional() -> None:
    record = parse_ftp_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(dst="10.0.0.3"),
            "user": "anonymous",
            "command": "PASS",
            "reply_code": 530,
        }
    )
    assert record.user == "anonymous"
    assert record.command == "PASS"
    assert record.reply_code == 530

    defaulted = parse_ftp_obj({"ts": 2, "uid": "C2", "id": _id()})
    assert defaulted.user is None
    assert defaulted.reply_code is None


def test_http_alias_normalization() -> None:
    record = parse_http_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(),
            "method": "GET",
            "host": "example.test",
            "uri": "/a.exe",
            "status_code": 200,
            "user_agent": "curl",
            "resp_body_len": 1024,
            "resp_mime_types": ["application/octet-stream"],
            "resp_fuids": ["F1"],
        }
    )
    assert record.mime_type == "application/octet-stream"
    assert record.fuid == "F1"

    scalar = parse_http_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(),
            "resp_mime_types": "text/plain",
            "resp_fuids": "F2",
        }
    )
    assert scalar.mime_type == "text/plain"
    assert scalar.fuid == "F2"
    assert scalar.status_code is None
    assert scalar.resp_body_len == 0


def test_files_list_scalar_hosts() -> None:
    record = parse_files_obj(
        {
            "ts": 1,
            "fuid": "F1",
            "tx_hosts": ["10.0.0.1", "10.0.0.9"],
            "rx_hosts": "10.0.0.2",
            "filename": "a.exe",
            "mime_type": "application/x-dosexec",
            "seen_bytes": 10,
            "total_bytes": 20,
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "-",
            "sha256": "",
        }
    )
    assert record.tx_hosts == ("10.0.0.1", "10.0.0.9")
    assert record.rx_hosts == ("10.0.0.2",)
    assert record.seen_bytes == 10
    assert record.total_bytes == 20
    assert record.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert record.sha1 is None
    assert record.sha256 is None


def test_ssl_and_intel() -> None:
    ssl = parse_ssl_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(dst="10.0.0.4"),
            "ja3": "abc",
            "ja4": "def",
            "server_name": "rare.test",
        }
    )
    assert ssl.ja3 == "abc"
    assert ssl.ja4 == "def"
    assert ssl.sni == "rare.test"

    intel = parse_intel_obj(
        {"ts": 1, "indicator": "bad.test", "indicator_type": "domain"}
    )
    assert intel.indicator == "bad.test"
    assert intel.indicator_type == "domain"
    assert intel.seen_where is None


def test_smb_and_dce_rpc() -> None:
    mapping = parse_smb_mapping_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(),
            "path": "\\\\DC\\ADMIN$",
            "service": "ADMIN$",
        }
    )
    assert mapping.path == "\\\\DC\\ADMIN$"
    assert mapping.service == "ADMIN$"

    files = parse_smb_files_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(),
            "action": "write",
            "path": "\\\\DC\\ADMIN$",
            "name": "svc.exe",
            "size": 4096,
        }
    )
    assert files.action == "write"
    assert files.size == 4096

    dce = parse_dce_rpc_obj(
        {
            "ts": 1,
            "uid": "C1",
            "id": _id(),
            "endpoint": "svcctl",
            "operation": "CreateServiceW",
            "named_pipe": "\\pipe\\svcctl",
        }
    )
    assert dce.endpoint == "svcctl"
    assert dce.operation == "CreateServiceW"
    assert dce.named_pipe == "\\pipe\\svcctl"


@pytest.mark.parametrize(
    "parser",
    [
        parse_ssh_obj,
        parse_ftp_obj,
        parse_http_obj,
        parse_ssl_obj,
        parse_smb_mapping_obj,
        parse_smb_files_obj,
        parse_dce_rpc_obj,
    ],
)
def test_required_endpoint_fields(parser) -> None:
    with pytest.raises(ValueError, match="missing field id.orig_h"):
        parser({"ts": 1, "uid": "C1", "id": {"resp_h": "10.0.0.2"}})


def test_required_fuid_and_ts() -> None:
    with pytest.raises(ValueError, match="missing field fuid"):
        parse_files_obj({"ts": 1})
    with pytest.raises(ValueError, match="missing field ts"):
        parse_ssh_obj({"uid": "C1", "id": _id()})
    with pytest.raises(ValueError, match="missing field indicator"):
        parse_intel_obj({"ts": 1})


def test_bad_bool_rejected() -> None:
    with pytest.raises(ValueError, match="invalid field auth_success"):
        parse_ssh_obj(
            {"ts": 1, "uid": "C1", "id": _id(), "auth_success": "maybe"}
        )


def test_iterators_report_path_line(tmp_path: Path) -> None:
    path = tmp_path / "ssh.jsonl"
    path.write_text('{"ts": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match=f"{path}:1: missing field uid"):
        list(iter_ssh_jsonl(path))

    path.write_text("{bad}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=f"{path}:1: invalid JSON"):
        list(iter_ftp_jsonl(path))


@pytest.mark.parametrize(
    "iterator",
    [
        iter_dce_rpc_jsonl,
        iter_files_jsonl,
        iter_http_jsonl,
        iter_intel_jsonl,
        iter_smb_files_jsonl,
        iter_smb_mapping_jsonl,
        iter_ssl_jsonl,
    ],
)
def test_new_iterators_parse_one_record(iterator, tmp_path: Path) -> None:
    path = tmp_path / "input.jsonl"
    if iterator is iter_files_jsonl:
        line = {"ts": 1, "fuid": "F1"}
    elif iterator is iter_intel_jsonl:
        line = {"ts": 1, "indicator": "bad.test"}
    else:
        line = {"ts": 1, "uid": "C1", "id": _id()}
    import json

    path.write_text(json.dumps(line) + "\n", encoding="utf-8")
    records = list(iterator(path))
    assert len(records) == 1
