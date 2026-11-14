from __future__ import annotations

import pytest

from ndr.contracts import FeatureSnapshot
from ndr.features.baseline import BaselineProfile
from ndr.features.conn import (
    build_snapshots,
    compute_conn_features,
    interval_cv,
    port_entropy,
)
from ndr.zeek import ConnRecord


def _records() -> list[ConnRecord]:
    records: list[ConnRecord] = []
    for index in range(20):
        port = 80 if index < 10 else 443
        service = "http" if port == 80 else "https"
        records.append(
            ConnRecord(
                ts=index * 0.5,
                uid=f"C{index}",
                orig_h="10.0.0.1",
                orig_p=50000 + index,
                resp_h="10.0.0.2",
                resp_p=port,
                proto="tcp",
                service=service,
                duration=1.0,
                orig_bytes=100,
                resp_bytes=200,
                orig_pkts=2,
                resp_pkts=2,
                conn_state="SF",
            )
        )
    return records


def _baseline() -> BaselineProfile:
    return BaselineProfile(
        feature_set_version="v0.1.0",
        port_counts={80: 10, 443: 10},
        total_conns=20,
        num_ports=2,
        host_pairs={"10.0.0.1|10.0.0.2"},
    )


def test_golden_window_features() -> None:
    features = compute_conn_features(_records(), _baseline())
    assert features["conn_count"] == pytest.approx(20)
    assert features["unique_dst_hosts"] == pytest.approx(1)
    assert features["unique_dst_ports"] == pytest.approx(2)
    assert features["failed_ratio"] == pytest.approx(0)
    assert features["syn_only_ratio"] == pytest.approx(0)
    assert features["bytes_out"] == pytest.approx(2000)
    assert features["bytes_in"] == pytest.approx(4000)
    assert features["bytes_ratio"] == pytest.approx(2000 / 4001)
    assert features["bytes_per_pkt"] == pytest.approx(75)
    assert features["duration_mean"] == pytest.approx(1)
    assert features["duration_std"] == pytest.approx(0)
    assert features["port_entropy"] == pytest.approx(1)
    assert features["dst_port_rarity"] == pytest.approx(1)
    assert features["host_pair_novelty_ratio"] == pytest.approx(0)
    assert features["scan_rate"] == pytest.approx(20 / 300)
    assert features["scan_interval_cv"] == pytest.approx(0)
    assert features["unique_dst_ports_per_host"] == pytest.approx(2)
    assert features["service_null_ratio"] == pytest.approx(0)


def test_port_entropy_edges() -> None:
    assert port_entropy([80]) == 0.0
    assert port_entropy([80, 80, 443, 443]) == pytest.approx(1.0)


def test_interval_cv_edges() -> None:
    assert interval_cv([0.0, 1.0, 2.0]) == pytest.approx(0.0)
    assert interval_cv([0.0, 0.0]) == pytest.approx(0.0)


def test_missing_durations_are_zero() -> None:
    records = [
        ConnRecord(
            ts=float(index),
            uid=f"C{index}",
            orig_h="10.0.0.1",
            orig_p=50000 + index,
            resp_h="10.0.0.2",
            resp_p=80,
            proto="tcp",
            service="http",
            duration=None,
            orig_bytes=10,
            resp_bytes=20,
            orig_pkts=1,
            resp_pkts=1,
            conn_state="SF",
        )
        for index in range(20)
    ]
    features = compute_conn_features(records, _baseline())
    assert features["duration_mean"] == 0.0
    assert features["duration_std"] == 0.0


def test_build_snapshots_requires_min_events() -> None:
    baseline = _baseline()
    assert build_snapshots(_records()[:19], baseline) == []
    snapshots = build_snapshots(_records(), baseline)
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert isinstance(snapshot, FeatureSnapshot)
    assert snapshot.entity.src_ip == "10.0.0.1"
    assert snapshot.window.size_sec == 300
    assert snapshot.context["conn_count"] == 20
