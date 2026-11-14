from pathlib import Path

import pytest

from ndr.zeek import iter_dns_jsonl, parse_dns_obj


def _obj() -> dict:
    return {
        "ts": 1.5,
        "uid": "C1",
        "id": {
            "orig_h": "10.0.0.1",
            "orig_p": 1234,
            "resp_h": "10.0.0.2",
            "resp_p": 53,
        },
        "proto": "udp",
        "query": "abcdef.example.com",
        "qtype_name": "TXT",
        "rcode_name": "NOERROR",
        "answers": ["ok"],
        "TTLs": [60.0],
    }


def test_parse_full_dns_record() -> None:
    record = parse_dns_obj(_obj())
    assert record.ts == 1.5
    assert record.uid == "C1"
    assert record.orig_h == "10.0.0.1"
    assert record.orig_p == 1234
    assert record.resp_h == "10.0.0.2"
    assert record.resp_p == 53
    assert record.proto == "udp"
    assert record.query == "abcdef.example.com"
    assert record.qtype_name == "TXT"
    assert record.rcode_name == "NOERROR"
    assert record.answers == ("ok",)
    assert record.ttls == (60.0,)


def test_missing_optional_dns_fields_use_defaults() -> None:
    record = parse_dns_obj(
        {
            "ts": 1.0,
            "uid": "C2",
            "id": {"orig_h": "10.0.0.1", "resp_h": "10.0.0.2"},
            "query": "example.com",
        }
    )
    assert record.orig_p == 0
    assert record.resp_p == 0
    assert record.proto == "udp"
    assert record.qtype_name is None
    assert record.rcode_name is None
    assert record.answers == ()
    assert record.ttls == ()


def test_scalar_answers_and_ttls_are_normalized() -> None:
    obj = _obj()
    obj["answers"] = "203.0.113.1"
    obj["TTLs"] = 30
    record = parse_dns_obj(obj)
    assert record.answers == ("203.0.113.1",)
    assert record.ttls == (30.0,)


def test_non_numeric_ttls_are_ignored() -> None:
    obj = _obj()
    obj["TTLs"] = [60.0, "junk", None]
    assert parse_dns_obj(obj).ttls == (60.0,)


def test_dash_optional_names_become_none() -> None:
    obj = _obj()
    obj["qtype_name"] = "-"
    obj["rcode_name"] = ""
    record = parse_dns_obj(obj)
    assert record.qtype_name is None
    assert record.rcode_name is None


def test_malformed_dns_json_reports_path_and_line(tmp_path: Path) -> None:
    path = tmp_path / "dns.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        list(iter_dns_jsonl(path))
    assert f"{path}:1" in str(error.value)


def test_missing_query_is_rejected() -> None:
    obj = _obj()
    del obj["query"]
    with pytest.raises(ValueError, match="missing field query"):
        parse_dns_obj(obj)


def test_missing_nested_dns_id_field_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing field id.resp_h"):
        parse_dns_obj(
            {
                "ts": 1,
                "uid": "C",
                "id": {"orig_h": "10.0.0.1"},
                "query": "example.com",
            }
        )
