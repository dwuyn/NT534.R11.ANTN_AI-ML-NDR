from __future__ import annotations

import pytest

from ndr.features.baseline import BaselineProfile
from ndr.features.beacon import (
    autocorr_lag1,
    build_beacon_snapshots,
    compute_beacon_features,
)
from ndr.zeek import ConnRecord


def _records() -> list[ConnRecord]:
    return [
        ConnRecord(
            ts=index * 30.0,
            uid=f"C{index}",
            orig_h="10.0.0.1",
            orig_p=50000 + index,
            resp_h="10.0.0.2",
            resp_p=443,
            proto="tcp",
            service="ssl",
            duration=0.2,
            orig_bytes=1200,
            resp_bytes=800,
            orig_pkts=2,
            resp_pkts=2,
            conn_state="SF",
        )
        for index in range(20)
    ]


def _baseline() -> BaselineProfile:
    return BaselineProfile(
        feature_set_version="v0.2.0",
        port_counts={443: 100},
        total_conns=100,
        num_ports=1,
        host_pairs={"10.0.0.1|10.0.0.2"},
        dst_host_counts={"10.0.0.2": 100},
    )


def test_golden_beacon_window_features() -> None:
    features = compute_beacon_features(_records(), _baseline(), 0.0)
    assert features["conn_count"] == pytest.approx(20)
    assert features["conn_rate"] == pytest.approx(20 / 600)
    assert features["interval_mean"] == pytest.approx(30)
    assert features["interval_std"] == pytest.approx(0)
    assert features["interval_cv"] == pytest.approx(0)
    assert features["interval_median"] == pytest.approx(30)
    assert features["interval_mad"] == pytest.approx(0)
    assert features["interval_min"] == pytest.approx(30)
    assert features["interval_max"] == pytest.approx(30)
    assert features["autocorr_lag1"] == pytest.approx(0)
    assert features["same_size_ratio"] == pytest.approx(1)
    assert features["bytes_out_mean"] == pytest.approx(1200)
    assert features["bytes_in_mean"] == pytest.approx(800)
    assert features["bytes_cv"] == pytest.approx(0)
    assert features["duration_mean"] == pytest.approx(0.2)
    assert features["duration_cv"] == pytest.approx(0)
    assert features["failed_ratio"] == pytest.approx(0)
    assert features["dst_rarity"] == pytest.approx(0)
    assert features["host_pair_novelty_ratio"] == pytest.approx(0)
    assert features["fft_peak_ratio"] > 0.25
    assert features["fft_entropy"] < 0.9
    assert 0.3 < features["periodicity_score"] <= 1.0


def test_autocorr_lag1_edges() -> None:
    assert autocorr_lag1([1, 2, 1, 2]) == pytest.approx(-0.75)
    assert autocorr_lag1([5, 5, 5]) == 0.0
    assert autocorr_lag1([1]) == 0.0


def test_build_beacon_snapshots_entity_and_min_events() -> None:
    baseline = _baseline()
    assert build_beacon_snapshots(_records()[:5], baseline) == []
    snapshots = build_beacon_snapshots(_records(), baseline)
    assert len(snapshots) == 1
    entity = snapshots[0].entity
    assert entity.type == "host_pair"
    assert entity.src_ip == "10.0.0.1"
    assert entity.dst_ip == "10.0.0.2"
    assert entity.dst_port == 443
    assert entity.proto == "tcp"
    assert snapshots[0].window.size_sec == 600
