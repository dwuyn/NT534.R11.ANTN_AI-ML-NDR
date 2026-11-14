from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.baseline import (
    BaselineProfile,
    finalize_profile,
    load_profile,
    save_profile,
)


def _snapshot(values: dict[str, float]) -> FeatureSnapshot:
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return FeatureSnapshot(
        snapshot_id="fs-test",
        feature_set_version="v0.1.0",
        window=Window(start=moment, end=moment, size_sec=300),
        entity=Entity(src_ip="10.0.0.1"),
        features=values,
    )


def test_port_freq_laplace() -> None:
    profile = BaselineProfile(
        feature_set_version="v0.1.0",
        port_counts={80: 10, 443: 10},
        total_conns=20,
        num_ports=2,
        host_pairs=set(),
    )
    assert profile.port_freq(80) == pytest.approx(0.5)
    assert profile.port_freq(8080) == pytest.approx(1 / 22)


def test_finalize_profile_mean_std_and_zero_std() -> None:
    profile = BaselineProfile(
        feature_set_version="v0.1.0",
        port_counts={},
        total_conns=0,
        num_ports=0,
        host_pairs=set(),
    )
    profile = finalize_profile(
        profile,
        [_snapshot({"a": 1.0, "b": 2.0}), _snapshot({"a": 3.0, "b": 2.0})],
    )
    assert profile.feature_mean["a"] == pytest.approx(2.0)
    assert profile.feature_std["a"] == pytest.approx(1.0)
    assert profile.feature_mean["b"] == pytest.approx(2.0)
    assert profile.feature_std["b"] == pytest.approx(1.0)


def test_profile_json_roundtrip(tmp_path: Path) -> None:
    profile = BaselineProfile(
        feature_set_version="v0.1.0",
        port_counts={80: 3, 443: 7},
        total_conns=10,
        num_ports=2,
        host_pairs={"10.0.0.1|10.0.0.2"},
        feature_mean={"a": 1.0},
        feature_std={"a": 0.5},
    )
    path = tmp_path / "baseline.json"
    save_profile(profile, path)
    loaded = load_profile(path)
    assert loaded.port_counts == {80: 3, 443: 7}
    assert loaded.host_pairs == {"10.0.0.1|10.0.0.2"}
    assert loaded.feature_mean == {"a": 1.0}
    assert loaded.feature_std == {"a": 0.5}
