"""D3 brute-force features over (source host, service) auth windows."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Iterable, Iterator, Sequence

import numpy as np

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.conn import interval_cv
from ndr.zeek import iter_conn_jsonl, iter_ftp_jsonl, iter_ssh_jsonl

BRUTE_WINDOW_SECONDS = 300
BRUTE_MIN_EVENTS = 10
BRUTE_FEATURE_SET_VERSION = "v0.5.0"

BRUTE_FEATURE_NAMES: tuple[str, ...] = (
    "auth_fail_count",
    "auth_fail_ratio",
    "auth_conn_count",
    "auth_unique_dst",
    "auth_interval_cv",
    "auth_bytes_per_attempt",
    "ssh_client_banner_rarity",
    "ftp_530_ratio",
    "auth_success_after_fail",
)

SSH_SERVICE = "ssh"
FTP_SERVICE = "ftp"


@dataclass(frozen=True)
class AuthRecord:
    ts: float
    uid: str
    src_ip: str
    dst_ip: str
    dst_port: int
    service: str
    success: bool
    failed: bool
    attempts: int
    client: str | None
    reply_code: int | None
    orig_bytes: int


def load_auth_records(run_dir: Path) -> list[AuthRecord]:
    """Load SSH and FTP auth records from one run directory.

    ``conn.jsonl`` is optional; when present it supplies ``orig_bytes``
    keyed by connection UID. Missing auth logs simply produce no records.
    """
    run_dir = Path(run_dir)
    conn_bytes: dict[str, int] = {}
    conn_path = run_dir / "conn.jsonl"
    if conn_path.is_file():
        for record in iter_conn_jsonl(conn_path):
            conn_bytes[record.uid] = record.orig_bytes

    records: list[AuthRecord] = []
    ssh_path = run_dir / "ssh.jsonl"
    if ssh_path.is_file():
        for record in iter_ssh_jsonl(ssh_path):
            records.append(
                AuthRecord(
                    ts=record.ts,
                    uid=record.uid,
                    src_ip=record.orig_h,
                    dst_ip=record.resp_h,
                    dst_port=record.resp_p,
                    service=SSH_SERVICE,
                    success=record.auth_success,
                    failed=not record.auth_success,
                    attempts=record.auth_attempts,
                    client=record.client,
                    reply_code=None,
                    orig_bytes=conn_bytes.get(record.uid, 0),
                )
            )

    ftp_path = run_dir / "ftp.jsonl"
    if ftp_path.is_file():
        for record in iter_ftp_jsonl(ftp_path):
            records.append(
                AuthRecord(
                    ts=record.ts,
                    uid=record.uid,
                    src_ip=record.orig_h,
                    dst_ip=record.resp_h,
                    dst_port=record.resp_p,
                    service=FTP_SERVICE,
                    success=record.reply_code == 230,
                    failed=record.reply_code == 530,
                    attempts=1,
                    client=None,
                    reply_code=record.reply_code,
                    orig_bytes=conn_bytes.get(record.uid, 0),
                )
            )

    records.sort(key=lambda item: (item.ts, item.src_ip, item.service, item.uid))
    return records


@dataclass(frozen=True)
class AuthKey:
    src_ip: str
    service: str
    start_ts: float


def group_auth_windows(
    records: Iterable[AuthRecord], window_sec: int = BRUTE_WINDOW_SECONDS
) -> Iterator[tuple[AuthKey, list[AuthRecord]]]:
    buckets: dict[AuthKey, list[AuthRecord]] = {}
    for record in records:
        start = math.floor(record.ts / window_sec) * window_sec
        key = AuthKey(
            src_ip=record.src_ip,
            service=record.service,
            start_ts=float(start),
        )
        buckets.setdefault(key, []).append(record)

    for key in sorted(
        buckets, key=lambda item: (item.start_ts, item.src_ip, item.service)
    ):
        yield key, sorted(buckets[key], key=lambda record: (record.ts, record.uid))


def compute_brute_features(
    records: Sequence[AuthRecord], baseline: "BruteBaselineProfile"
) -> dict[str, float]:
    if not records:
        raise ValueError("cannot compute features for an empty auth window")

    count = float(len(records))
    failed = sum(1 for record in records if record.failed)
    total_attempts = sum(max(0, record.attempts) for record in records)
    total_bytes = sum(max(0, record.orig_bytes) for record in records)
    ssh_records = [record for record in records if record.service == SSH_SERVICE]
    ftp_records = [record for record in records if record.service == FTP_SERVICE]

    if ssh_records:
        rarity = fmean(
            0.0
            if record.client is None
            else -math.log2(baseline.client_freq(record.client))
            for record in ssh_records
        )
    else:
        rarity = 0.0

    seen_failure = False
    success_after_failure = 0.0
    for record in sorted(records, key=lambda item: (item.ts, item.uid)):
        if record.failed:
            seen_failure = True
        elif record.success and seen_failure:
            success_after_failure = 1.0
            break

    return {
        "auth_fail_count": float(failed),
        "auth_fail_ratio": failed / count,
        "auth_conn_count": count,
        "auth_unique_dst": float(len({record.dst_ip for record in records})),
        "auth_interval_cv": interval_cv([record.ts for record in records]),
        "auth_bytes_per_attempt": total_bytes / max(1, total_attempts),
        "ssh_client_banner_rarity": float(rarity),
        "ftp_530_ratio": (
            sum(1 for record in ftp_records if record.failed) / len(ftp_records)
            if ftp_records
            else 0.0
        ),
        "auth_success_after_fail": success_after_failure,
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_brute_snapshots(
    records: Iterable[AuthRecord],
    baseline: "BruteBaselineProfile",
    min_events: int = BRUTE_MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_records in group_auth_windows(records):
        if len(window_records) < min_events:
            continue
        start = key.start_ts
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=f"fs-brute-{int(start)}-{key.src_ip}-{key.service}",
                feature_set_version=BRUTE_FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(start),
                    end=_utc(start + BRUTE_WINDOW_SECONDS),
                    size_sec=BRUTE_WINDOW_SECONDS,
                ),
                entity=Entity(src_ip=key.src_ip),
                features=compute_brute_features(window_records, baseline),
                context={
                    "service": key.service,
                    "auth_events": len(window_records),
                    "uids": sorted({record.uid for record in window_records})[:100],
                },
            )
        )
    return snapshots


@dataclass
class BruteBaselineProfile:
    feature_set_version: str
    client_counts: dict[str, int]
    total_auth: int
    feature_mean: dict[str, float] = field(default_factory=dict)
    feature_std: dict[str, float] = field(default_factory=dict)

    def client_freq(self, client: str) -> float:
        denominator = self.total_auth + len(self.client_counts)
        if denominator <= 0:
            return 1.0
        return (self.client_counts.get(client, 0) + 1) / denominator

    def to_json(self) -> dict:
        return {
            "feature_set_version": self.feature_set_version,
            "client_counts": dict(sorted(self.client_counts.items())),
            "total_auth": self.total_auth,
            "feature_mean": dict(self.feature_mean),
            "feature_std": dict(self.feature_std),
        }

    @classmethod
    def from_json(cls, data: dict) -> "BruteBaselineProfile":
        return cls(
            feature_set_version=str(data["feature_set_version"]),
            client_counts={
                str(name): int(count)
                for name, count in data.get("client_counts", {}).items()
            },
            total_auth=int(data.get("total_auth", 0)),
            feature_mean={
                key: float(value)
                for key, value in data.get("feature_mean", {}).items()
            },
            feature_std={
                key: float(value)
                for key, value in data.get("feature_std", {}).items()
            },
        )


def build_raw_brute_profile(
    records: Iterable[AuthRecord],
) -> BruteBaselineProfile:
    client_counts: dict[str, int] = {}
    total = 0
    for record in records:
        total += 1
        if record.service == SSH_SERVICE and record.client:
            client_counts[record.client] = (
                client_counts.get(record.client, 0) + 1
            )
    return BruteBaselineProfile(
        feature_set_version=BRUTE_FEATURE_SET_VERSION,
        client_counts=client_counts,
        total_auth=total,
    )


def finalize_brute_profile(
    profile: BruteBaselineProfile, snapshots: Sequence[FeatureSnapshot]
) -> BruteBaselineProfile:
    if not snapshots:
        raise ValueError("finalize_brute_profile requires at least one snapshot")
    names = list(snapshots[0].features.keys())
    for name in names:
        values = np.asarray(
            [snapshot.features[name] for snapshot in snapshots], dtype=float
        )
        profile.feature_mean[name] = float(np.mean(values))
        std = float(np.std(values, ddof=0))
        profile.feature_std[name] = std if std > 0.0 else 1.0
    return profile


def save_brute_profile(profile: BruteBaselineProfile, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(profile.to_json(), indent=2, sort_keys=True), encoding="utf-8"
    )


def load_brute_profile(path: Path) -> BruteBaselineProfile:
    return BruteBaselineProfile.from_json(
        json.loads(path.read_text(encoding="utf-8"))
    )
