from __future__ import annotations

import math

import pytest

from ndr.features.baseline import BaselineProfile
from ndr.features.scan import (
    SCAN_FEATURE_NAMES,
    build_scan_snapshots,
    compute_scan_features,
)
from ndr.zeek import ConnRecord

PORTS = (80, 80, 443, 443, 22, 22, 8080, 3306, 53, 123, 3389, 5900)
STATES = ("S0", "S0", "S0", "S0", "S0", "REJ", "REJ", "RSTO", "RSTR", "SF", "SF", "SF")


def _records() -> list[ConnRecord]:
    records: list[ConnRecord] = []
    for index, (port, state) in enumerate(zip(PORTS, STATES)):
        records.append(
            ConnRecord(
                ts=900.0 + index * 10.0,
                uid=f"C{index}",
                orig_h="10.0.0.1",
                orig_p=50000 + index,
                resp_h="10.0.0.2" if index < 6 else "10.0.0.3",
                resp_p=port,
                proto="tcp",
                service="http" if port in (80, 8080) else None,
                duration=0.1 if state == "SF" else None,
                orig_bytes=100 if state == "SF" else 0,
                resp_bytes=200 if state == "SF" else 0,
                orig_pkts=1 if state == "SF" else 0,
                resp_pkts=1 if state == "SF" else 0,
                conn_state=state,
            )
        )
    return records


def _baseline() -> BaselineProfile:
    return BaselineProfile(
        feature_set_version="v0.4.0",
        port_counts={80: 100, 443: 100},
        total_conns=200,
        num_ports=2,
        host_pairs={"10.0.0.1|10.0.0.2"},
        dst_host_counts={"10.0.0.2": 200},
    )


def test_golden_scan_window_features() -> None:
    features = compute_scan_features(_records(), _baseline())
    assert tuple(features) == SCAN_FEATURE_NAMES
    assert features["scan_unique_ports"] == pytest.approx(9)
    assert features["scan_unique_hosts"] == pytest.approx(2)
    assert features["scan_failed_ratio"] == pytest.approx(9 / 12)
    assert features["scan_syn_ratio"] == pytest.approx(5 / 12)
    assert features["scan_port_entropy"] == pytest.approx(
        0.5 * math.log2(6) + 0.5 * math.log2(12)
    )
    assert features["scan_rate"] == pytest.approx(12 / 300)
    assert features["scan_interval_cv"] == pytest.approx(0)
    assert features["scan_new_host_ratio"] == pytest.approx(0.5)
    assert features["scan_service_null_ratio"] == pytest.approx(0.75)


def test_build_scan_snapshots_entity_and_min_events() -> None:
    baseline = _baseline()
    assert build_scan_snapshots(_records()[:5], baseline) == []

    snapshots = build_scan_snapshots(_records(), baseline)
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.snapshot_id == "fs-scan-900-10.0.0.1"
    assert snapshot.feature_set_version == "v0.4.0"
    assert snapshot.window.size_sec == 300
    assert snapshot.entity.type == "host"
    assert snapshot.entity.src_ip == "10.0.0.1"
    assert snapshot.context["conn_count"] == 12
    assert len(snapshot.context["uids"]) == 12
    assert snapshot.context["uids"][0] == "C0"
