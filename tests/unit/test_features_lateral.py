from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from ndr.features.lateral import (
    LATERAL_FEATURE_NAMES,
    LATERAL_WINDOW_SECONDS,
    LateralBaselineProfile,
    LateralEvent,
    build_lateral_snapshots,
    build_raw_lateral_profile,
    compute_lateral_features,
    group_lateral_windows,
    load_lateral_events,
    load_lateral_profile,
    save_lateral_profile,
)


def _baseline() -> LateralBaselineProfile:
    return LateralBaselineProfile(
        feature_set_version="v0.7.0",
        path_counts={
            "\\\\b\\ADMIN$": 2,
            "\\\\c\\C$": 2,
        },
        host_pairs={"10.0.0.1|10.0.0.2"},
        critical_hosts=set(),
        total_events=4,
    )


def _golden_events() -> list[LateralEvent]:
    source = "10.0.0.1"
    return [
        LateralEvent(
            ts=1.0,
            uid="C1",
            src_ip=source,
            dst_ip="10.0.0.2",
            kind="mapping",
            path="\\\\b\\ADMIN$",
        ),
        LateralEvent(
            ts=2.0,
            uid="C2",
            src_ip=source,
            dst_ip="10.0.0.3",
            kind="mapping",
            path="\\\\c\\C$",
        ),
        LateralEvent(
            ts=3.0,
            uid="C3",
            src_ip=source,
            dst_ip="10.0.0.4",
            kind="mapping",
            path="\\\\d\\C$",
        ),
        LateralEvent(
            ts=10.0,
            uid="C4",
            src_ip=source,
            dst_ip="10.0.0.2",
            kind="file",
            path="\\\\b\\ADMIN$",
            action="write",
            name="svc.exe",
            size=71_680,
        ),
        LateralEvent(
            ts=20.0,
            uid="C5",
            src_ip=source,
            dst_ip="10.0.0.2",
            kind="dce_rpc",
            endpoint="svcctl",
            operation="CreateServiceW",
        ),
        LateralEvent(
            ts=30.0,
            uid="C6",
            src_ip=source,
            dst_ip="10.0.0.3",
            kind="dce_rpc",
            endpoint="atsvc",
            operation="SchRpcRun",
        ),
        LateralEvent(
            ts=40.0,
            uid="C7",
            src_ip=source,
            dst_ip="10.0.0.4",
            kind="file",
            path="\\\\d\\C$",
            action="read",
            name="notes.txt",
            size=1024,
        ),
    ]


def test_golden_window_features() -> None:
    features = compute_lateral_features(_golden_events(), _baseline(), 0.0)

    assert set(features) == set(LATERAL_FEATURE_NAMES)
    assert features["smb_unique_dsts"] == 3.0
    assert features["smb_admin_share_count"] == 5.0
    assert features["smb_exe_write_count"] == 1.0
    assert features["smb_mapping_rarity"] == pytest.approx(
        (1.0 + 1.0 + math.log2(6.0)) / 3.0
    )
    assert features["dce_rpc_svcctl_count"] == 1.0
    assert features["dce_rpc_atsvc_count"] == 1.0
    assert features["service_creation_count"] == 1.0
    assert features["smb_write_to_service_delta"] == pytest.approx(10.0)
    assert features["new_host_pair_count"] == 2.0
    assert features["graph_out_degree"] == 3.0
    assert features["graph_new_edges"] == 2.0
    assert features["graph_betweenness"] == pytest.approx(1.0)
    assert features["asset_criticality"] == 0.0


def test_smb_unique_dsts_excludes_dce_only_destinations() -> None:
    events = [
        LateralEvent(
            ts=1.0,
            uid="C1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            kind="mapping",
            path="\\\\b\\ADMIN$",
        ),
        LateralEvent(
            ts=2.0,
            uid="C2",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            kind="file",
            action="read",
            name="a.txt",
        ),
        LateralEvent(
            ts=3.0,
            uid="C3",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.4",
            kind="dce_rpc",
            endpoint="svcctl",
            operation="CreateServiceW",
        ),
    ]
    features = compute_lateral_features(events, _baseline(), 0.0)
    assert features["smb_unique_dsts"] == 2.0
    assert features["graph_out_degree"] == 3.0
    assert features["new_host_pair_count"] == 2.0
    assert features["graph_new_edges"] == 2.0


def test_graph_betweenness_is_zero_for_two_nodes() -> None:
    events = [
        LateralEvent(
            ts=1.0,
            uid="C1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            kind="mapping",
            path="\\\\b\\ADMIN$",
        ),
        LateralEvent(
            ts=2.0,
            uid="C2",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            kind="file",
            action="read",
            name="a.txt",
        ),
        LateralEvent(
            ts=3.0,
            uid="C3",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            kind="file",
            action="read",
            name="b.txt",
        ),
    ]
    features = compute_lateral_features(events, _baseline(), 0.0)
    assert features["graph_betweenness"] == 0.0


def test_group_and_build_snapshots() -> None:
    events = [
        LateralEvent(
            ts=float(index),
            uid=f"C{index}",
            src_ip="10.0.0.9",
            dst_ip="10.0.0.8",
            kind="mapping",
            path="\\\\b\\ADMIN$",
        )
        for index in range(2)
    ]
    assert build_lateral_snapshots(events, _baseline()) == []

    events = [
        LateralEvent(
            ts=float(index * 100),
            uid=f"C{index}",
            src_ip="10.0.0.9",
            dst_ip="10.0.0.8",
            kind="mapping",
            path="\\\\b\\ADMIN$",
        )
        for index in range(3)
    ]
    snapshots = build_lateral_snapshots(events, _baseline())
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.snapshot_id == "fs-lateral-0-10.0.0.9"
    assert snapshot.entity.type == "host"
    assert snapshot.entity.src_ip == "10.0.0.9"
    assert snapshot.window.size_sec == LATERAL_WINDOW_SECONDS
    assert snapshot.context["event_count"] == 3

    windows = list(group_lateral_windows(events))
    assert len(windows) == 1
    assert windows[0][0].src_ip == "10.0.0.9"


def test_load_lateral_events_joins_logs(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mapping = {
        "ts": 1,
        "uid": "M1",
        "id": {
            "orig_h": "10.0.0.1",
            "orig_p": 50000,
            "resp_h": "10.0.0.2",
            "resp_p": 445,
        },
        "path": "\\\\b\\ADMIN$",
        "service": "ADMIN$",
    }
    files = {
        "ts": 2,
        "uid": "F1",
        "id": {
            "orig_h": "10.0.0.1",
            "orig_p": 50000,
            "resp_h": "10.0.0.2",
            "resp_p": 445,
        },
        "action": "write",
        "path": "\\\\b\\ADMIN$",
        "name": "svc.exe",
        "size": 100,
    }
    dce = {
        "ts": 3,
        "uid": "D1",
        "id": {
            "orig_h": "10.0.0.1",
            "orig_p": 50000,
            "resp_h": "10.0.0.2",
            "resp_p": 445,
        },
        "endpoint": "svcctl",
        "operation": "CreateServiceW",
        "named_pipe": "\\pipe\\svcctl",
    }
    (run_dir / "smb_mapping.jsonl").write_text(
        json.dumps(mapping) + "\n", encoding="utf-8"
    )
    (run_dir / "smb_files.jsonl").write_text(
        json.dumps(files) + "\n", encoding="utf-8"
    )
    (run_dir / "dce_rpc.jsonl").write_text(
        json.dumps(dce) + "\n", encoding="utf-8"
    )

    events = load_lateral_events(run_dir)
    assert [event.kind for event in events] == ["mapping", "file", "dce_rpc"]
    assert events[1].name == "svc.exe"
    assert events[2].operation == "CreateServiceW"

    (run_dir / "smb_files.jsonl").unlink()
    (run_dir / "dce_rpc.jsonl").unlink()
    assert len(load_lateral_events(run_dir)) == 1


def test_profile_roundtrip(tmp_path: Path) -> None:
    profile = build_raw_lateral_profile(_golden_events())
    assert profile.critical_hosts == {"192.168.217.129"}
    assert "10.0.0.1|10.0.0.2" in profile.host_pairs

    path = tmp_path / "lateral_baseline.json"
    save_lateral_profile(profile, path)
    loaded = load_lateral_profile(path)
    assert loaded.path_counts == profile.path_counts
    assert loaded.host_pairs == profile.host_pairs
    assert loaded.critical_hosts == profile.critical_hosts
    assert loaded.total_events == profile.total_events
