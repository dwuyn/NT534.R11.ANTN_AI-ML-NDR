from pathlib import Path

import pytest

from ndr.zeek import iter_conn_jsonl, parse_conn_obj


def _obj() -> dict:
    return {
        "ts": 1.5,
        "uid": "C1",
        "id": {
            "orig_h": "10.0.0.1",
            "orig_p": 1234,
            "resp_h": "10.0.0.2",
            "resp_p": 80,
        },
        "proto": "tcp",
        "service": "http",
        "duration": 0.5,
        "orig_bytes": 10,
        "resp_bytes": 20,
        "orig_pkts": 2,
        "resp_pkts": 3,
        "conn_state": "SF",
    }


def test_parse_full_record() -> None:
    record = parse_conn_obj(_obj())
    assert record.ts == 1.5
    assert record.uid == "C1"
    assert record.orig_h == "10.0.0.1"
    assert record.orig_p == 1234
    assert record.resp_h == "10.0.0.2"
    assert record.resp_p == 80
    assert record.proto == "tcp"
    assert record.service == "http"
    assert record.duration == 0.5
    assert record.orig_bytes == 10
    assert record.resp_bytes == 20
    assert record.orig_pkts == 2
    assert record.resp_pkts == 3
    assert record.conn_state == "SF"


def test_missing_optional_fields_use_defaults() -> None:
    record = parse_conn_obj(
        {
            "ts": 1.0,
            "uid": "C2",
            "id": {
                "orig_h": "10.0.0.1",
                "orig_p": 1,
                "resp_h": "10.0.0.2",
                "resp_p": 443,
            },
            "proto": "tcp",
        }
    )
    assert record.service is None
    assert record.duration is None
    assert record.orig_bytes == 0
    assert record.resp_bytes == 0
    assert record.orig_pkts == 0
    assert record.resp_pkts == 0
    assert record.conn_state is None


def test_dash_service_becomes_none() -> None:
    obj = _obj()
    obj["service"] = "-"
    assert parse_conn_obj(obj).service is None


def test_malformed_json_reports_path_and_line(tmp_path: Path) -> None:
    path = tmp_path / "conn.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        list(iter_conn_jsonl(path))
    assert f"{path}:1" in str(error.value)


def test_missing_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing field id"):
        parse_conn_obj({"ts": 1, "uid": "C", "proto": "tcp"})


def test_missing_nested_id_field_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing field id.resp_p"):
        parse_conn_obj(
            {
                "ts": 1,
                "uid": "C",
                "id": {"orig_h": "10.0.0.1", "orig_p": 1, "resp_h": "10.0.0.2"},
                "proto": "tcp",
            }
        )
