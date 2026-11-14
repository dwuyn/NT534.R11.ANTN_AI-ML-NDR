"""Baseline profile for rarity and novelty features."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from ndr.contracts import FeatureSnapshot
from ndr.zeek import ConnRecord


@dataclass
class BaselineProfile:
    feature_set_version: str
    port_counts: dict[int, int]
    total_conns: int
    num_ports: int
    host_pairs: set[str]
    dst_host_counts: dict[str, int] = field(default_factory=dict)
    feature_mean: dict[str, float] = field(default_factory=dict)
    feature_std: dict[str, float] = field(default_factory=dict)

    def port_freq(self, port: int) -> float:
        denominator = self.total_conns + self.num_ports
        if denominator <= 0:
            return 1.0
        return (self.port_counts.get(port, 0) + 1) / denominator

    def dst_host_freq(self, host: str) -> float:
        denominator = self.total_conns + len(self.dst_host_counts)
        if denominator <= 0:
            return 1.0
        return (self.dst_host_counts.get(host, 0) + 1) / denominator

    def to_json(self) -> dict:
        return {
            "feature_set_version": self.feature_set_version,
            "port_counts": {str(port): count for port, count in sorted(self.port_counts.items())},
            "total_conns": self.total_conns,
            "num_ports": self.num_ports,
            "host_pairs": sorted(self.host_pairs),
            "dst_host_counts": dict(sorted(self.dst_host_counts.items())),
            "feature_mean": dict(self.feature_mean),
            "feature_std": dict(self.feature_std),
        }

    @classmethod
    def from_json(cls, data: dict) -> "BaselineProfile":
        return cls(
            feature_set_version=str(data["feature_set_version"]),
            port_counts={int(port): int(count) for port, count in data["port_counts"].items()},
            total_conns=int(data["total_conns"]),
            num_ports=int(data["num_ports"]),
            host_pairs=set(data["host_pairs"]),
            dst_host_counts={
                str(host): int(count)
                for host, count in data.get("dst_host_counts", {}).items()
            },
            feature_mean={key: float(value) for key, value in data.get("feature_mean", {}).items()},
            feature_std={key: float(value) for key, value in data.get("feature_std", {}).items()},
        )


def build_raw_profile(records: Iterable[ConnRecord]) -> BaselineProfile:
    from ndr.features.conn import FEATURE_SET_VERSION

    port_counts: dict[int, int] = {}
    dst_host_counts: dict[str, int] = {}
    host_pairs: set[str] = set()
    total = 0
    for record in records:
        port_counts[record.resp_p] = port_counts.get(record.resp_p, 0) + 1
        dst_host_counts[record.resp_h] = dst_host_counts.get(record.resp_h, 0) + 1
        host_pairs.add(f"{record.orig_h}|{record.resp_h}")
        total += 1
    return BaselineProfile(
        feature_set_version=FEATURE_SET_VERSION,
        port_counts=port_counts,
        total_conns=total,
        num_ports=len(port_counts),
        host_pairs=host_pairs,
        dst_host_counts=dst_host_counts,
    )


def finalize_profile(
    profile: BaselineProfile, snapshots: Sequence[FeatureSnapshot]
) -> BaselineProfile:
    if not snapshots:
        raise ValueError("finalize_profile requires at least one snapshot")
    names = list(snapshots[0].features.keys())
    for name in names:
        values = np.asarray([snapshot.features[name] for snapshot in snapshots], dtype=float)
        profile.feature_mean[name] = float(np.mean(values))
        std = float(np.std(values, ddof=0))
        profile.feature_std[name] = std if std > 0.0 else 1.0
    return profile


def save_profile(profile: BaselineProfile, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile.to_json(), indent=2, sort_keys=True), encoding="utf-8")


def load_profile(path: Path) -> BaselineProfile:
    return BaselineProfile.from_json(json.loads(path.read_text(encoding="utf-8")))
