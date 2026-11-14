"""Baseline profile for DNS parent/subdomain rarity."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from ndr.contracts import FeatureSnapshot
from ndr.zeek import DnsRecord


@dataclass
class DnsBaselineProfile:
    feature_set_version: str
    parent_counts: dict[str, int]
    subdomain_counts: dict[str, int]
    total_queries: int
    feature_mean: dict[str, float] = field(default_factory=dict)
    feature_std: dict[str, float] = field(default_factory=dict)

    def parent_freq(self, parent: str) -> float:
        denominator = self.total_queries + len(self.parent_counts)
        if denominator <= 0:
            return 1.0
        return (self.parent_counts.get(parent, 0) + 1) / denominator

    def subdomain_freq(self, subdomain: str) -> float:
        denominator = self.total_queries + len(self.subdomain_counts)
        if denominator <= 0:
            return 1.0
        return (self.subdomain_counts.get(subdomain, 0) + 1) / denominator

    def to_json(self) -> dict:
        return {
            "feature_set_version": self.feature_set_version,
            "parent_counts": dict(sorted(self.parent_counts.items())),
            "subdomain_counts": dict(sorted(self.subdomain_counts.items())),
            "total_queries": self.total_queries,
            "feature_mean": dict(self.feature_mean),
            "feature_std": dict(self.feature_std),
        }

    @classmethod
    def from_json(cls, data: dict) -> "DnsBaselineProfile":
        return cls(
            feature_set_version=str(data["feature_set_version"]),
            parent_counts={
                str(name): int(count)
                for name, count in data.get("parent_counts", {}).items()
            },
            subdomain_counts={
                str(name): int(count)
                for name, count in data.get("subdomain_counts", {}).items()
            },
            total_queries=int(data.get("total_queries", 0)),
            feature_mean={
                key: float(value)
                for key, value in data.get("feature_mean", {}).items()
            },
            feature_std={
                key: float(value) for key, value in data.get("feature_std", {}).items()
            },
        )


def build_raw_dns_profile(records: Iterable[DnsRecord]) -> DnsBaselineProfile:
    from ndr.features.dns import (
        DNS_FEATURE_SET_VERSION,
        parent_domain,
        subdomain_or_first_label,
    )

    parent_counts: dict[str, int] = {}
    subdomain_counts: dict[str, int] = {}
    total = 0
    for record in records:
        parent = parent_domain(record.query)
        subdomain = subdomain_or_first_label(record.query)
        parent_counts[parent] = parent_counts.get(parent, 0) + 1
        subdomain_counts[subdomain] = subdomain_counts.get(subdomain, 0) + 1
        total += 1
    return DnsBaselineProfile(
        feature_set_version=DNS_FEATURE_SET_VERSION,
        parent_counts=parent_counts,
        subdomain_counts=subdomain_counts,
        total_queries=total,
    )


def finalize_dns_profile(
    profile: DnsBaselineProfile, snapshots: Sequence[FeatureSnapshot]
) -> DnsBaselineProfile:
    if not snapshots:
        raise ValueError("finalize_dns_profile requires at least one snapshot")
    names = list(snapshots[0].features.keys())
    for name in names:
        values = np.asarray(
            [snapshot.features[name] for snapshot in snapshots], dtype=float
        )
        profile.feature_mean[name] = float(np.mean(values))
        std = float(np.std(values, ddof=0))
        profile.feature_std[name] = std if std > 0.0 else 1.0
    return profile


def save_dns_profile(profile: DnsBaselineProfile, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(profile.to_json(), indent=2, sort_keys=True), encoding="utf-8"
    )


def load_dns_profile(path: Path) -> DnsBaselineProfile:
    return DnsBaselineProfile.from_json(
        json.loads(path.read_text(encoding="utf-8"))
    )
