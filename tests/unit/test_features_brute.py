import json
import math
from pathlib import Path

import pytest

from ndr.features.brute import (
    AuthRecord,
    BruteBaselineProfile,
    build_brute_snapshots,
    compute_brute_features,
    load_auth_records,
)


def _baseline() -> BruteBaselineProfile:
    return BruteBaselineProfile(
        feature_set_version="v0.5.0",
        client_counts={"OpenSSH_9.3": 100},
        total_auth=100,
    )


def _ssh_records(count: int = 10, success_last: bool = True) -> list[AuthRecord]:
    return [
        AuthRecord(
            ts=float(index * 10),
            uid=f"c{index}",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.9",
            dst_port=22,
            service="ssh",
            success=(success_last and index == count - 1),
            failed=not (success_last and index == count - 1),
            attempts=1,
            client="hydra",
            reply_code=None,
            orig_bytes=100,
        )
        for index in range(count)
    ]


def test_golden_ssh_window_features() -> None:
    features = compute_brute_features(_ssh_records(), _baseline())

    assert features["auth_fail_count"] == 9
    assert features["auth_fail_ratio"] == pytest.approx(0.9)
    assert features["auth_conn_count"] == 10
    assert features["auth_unique_dst"] == 1
    assert features["auth_interval_cv"] == pytest.approx(0.0)
    assert features["auth_bytes_per_attempt"] == pytest.approx(100.0)
    assert features["ssh_client_banner_rarity"] == pytest.approx(math.log2(101))
    assert features["ftp_530_ratio"] == pytest.approx(0.0)
    assert features["auth_success_after_fail"] == pytest.approx(1.0)


def test_success_before_failure_does_not_set_flag() -> None:
    records = _ssh_records(count=5, success_last=False)
    records[0] = AuthRecord(
        ts=0.0,
        uid="c0",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.9",
        dst_port=22,
        service="ssh",
        success=True,
        failed=False,
        attempts=1,
        client="hydra",
        reply_code=None,
        orig_bytes=100,
    )
    features = compute_brute_features(records, _baseline())
    assert features["auth_success_after_fail"] == pytest.approx(0.0)


def test_ftp_window_features() -> None:
    records = [
        AuthRecord(
            ts=float(index * 5),
            uid=f"f{index}",
            src_ip="10.0.0.2",
            dst_ip="10.0.0.9",
            dst_port=21,
            service="ftp",
            success=index < 5,
            failed=index >= 5,
            attempts=1,
            client=None,
            reply_code=230 if index < 5 else 530,
            orig_bytes=200,
        )
        for index in range(10)
    ]
    features = compute_brute_features(records, _baseline())

    assert features["auth_fail_count"] == 5
    assert features["auth_fail_ratio"] == pytest.approx(0.5)
    assert features["ftp_530_ratio"] == pytest.approx(0.5)
    assert features["ssh_client_banner_rarity"] == pytest.approx(0.0)
    assert features["auth_success_after_fail"] == pytest.approx(0.0)
    assert features["auth_bytes_per_attempt"] == pytest.approx(200.0)


def test_build_brute_snapshots_drops_small_windows() -> None:
    assert build_brute_snapshots(_ssh_records(9), _baseline()) == []
    snapshots = build_brute_snapshots(_ssh_records(10), _baseline())
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.entity.type == "host"
    assert snapshot.entity.src_ip == "10.0.0.1"
    assert snapshot.context["service"] == "ssh"
    assert snapshot.context["auth_events"] == 10
    assert snapshot.snapshot_id == "fs-brute-0-10.0.0.1-ssh"


def test_load_auth_records_joins_conn_bytes(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    def conn(uid: str, orig_bytes: int) -> dict:
        return {
            "ts": 1.0,
            "uid": uid,
            "id": {
                "orig_h": "10.0.0.1",
                "orig_p": 40000,
                "resp_h": "10.0.0.9",
                "resp_p": 22,
            },
            "proto": "tcp",
            "orig_bytes": orig_bytes,
        }

    (run_dir / "conn.jsonl").write_text(
        "\n".join(json.dumps(item) for item in (conn("c1", 111), conn("c2", 222)))
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "ssh.jsonl").write_text(
        json.dumps(
            {
                "ts": 1.0,
                "uid": "c1",
                "id": {
                    "orig_h": "10.0.0.1",
                    "orig_p": 40000,
                    "resp_h": "10.0.0.9",
                    "resp_p": 22,
                },
                "auth_success": True,
                "auth_attempts": 3,
                "client": "OpenSSH_9.3",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "ftp.jsonl").write_text(
        json.dumps(
            {
                "ts": 2.0,
                "uid": "c2",
                "id": {
                    "orig_h": "10.0.0.1",
                    "orig_p": 40001,
                    "resp_h": "10.0.0.9",
                    "resp_p": 21,
                },
                "user": "admin",
                "command": "PASS",
                "reply_code": 530,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    records = load_auth_records(run_dir)
    assert [record.service for record in records] == ["ssh", "ftp"]

    ssh, ftp = records
    assert ssh.success is True
    assert ssh.failed is False
    assert ssh.attempts == 3
    assert ssh.orig_bytes == 111
    assert ftp.success is False
    assert ftp.failed is True
    assert ftp.reply_code == 530
    assert ftp.orig_bytes == 222


def test_load_auth_records_missing_logs_are_empty(tmp_path: Path) -> None:
    run_dir = tmp_path / "empty"
    run_dir.mkdir()
    assert load_auth_records(run_dir) == []
