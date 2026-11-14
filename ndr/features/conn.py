"""Feature extraction for connection windows."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from statistics import fmean, pstdev
from typing import Iterable, Sequence

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.baseline import BaselineProfile
from ndr.features.windows import MIN_EVENTS, WINDOW_SECONDS, group_windows
from ndr.zeek import ConnRecord

FEATURE_SET_VERSION = "v0.1.0"

FEATURE_NAMES: tuple[str, ...] = (
    "conn_count",
    "unique_dst_hosts",
    "unique_dst_ports",
    "failed_ratio",
    "syn_only_ratio",
    "bytes_out",
    "bytes_in",
    "bytes_ratio",
    "bytes_per_pkt",
    "duration_mean",
    "duration_std",
    "port_entropy",
    "dst_port_rarity",
    "host_pair_novelty_ratio",
    "scan_rate",
    "scan_interval_cv",
    "unique_dst_ports_per_host",
    "service_null_ratio",
)


def port_entropy(ports: Sequence[int]) -> float:
    total = len(ports)
    if total == 0:
        return 0.0
    counts = Counter(ports)
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def interval_cv(timestamps: Sequence[float]) -> float:
    if len(timestamps) < 3:
        return 0.0
    ordered = sorted(timestamps)
    intervals = [later - earlier for earlier, later in zip(ordered, ordered[1:])]
    mean = fmean(intervals)
    if mean <= 0.0:
        return 0.0
    return float(pstdev(intervals) / mean)


def compute_conn_features(
    records: Sequence[ConnRecord], baseline: BaselineProfile
) -> dict[str, float]:
    if not records:
        raise ValueError("cannot compute features for an empty window")

    count = float(len(records))
    unique_dst_hosts = float(len({record.resp_h for record in records}))
    unique_dst_ports = float(len({record.resp_p for record in records}))
    failed = sum(
        1 for record in records if record.conn_state in {"S0", "REJ", "RSTO", "RSTR"}
    )
    syn_only = sum(1 for record in records if record.conn_state == "S0")
    bytes_out = float(sum(record.orig_bytes for record in records))
    bytes_in = float(sum(record.resp_bytes for record in records))
    packets = sum(record.orig_pkts + record.resp_pkts for record in records)
    durations = [record.duration for record in records if record.duration is not None]
    duration_mean = float(fmean(durations)) if durations else 0.0
    duration_std = float(pstdev(durations)) if durations else 0.0
    entropy = port_entropy([record.resp_p for record in records])
    rarity = float(
        fmean(-math.log2(baseline.port_freq(record.resp_p)) for record in records)
    )
    novel_pairs = sum(
        1
        for record in records
        if f"{record.orig_h}|{record.resp_h}" not in baseline.host_pairs
    )

    return {
        "conn_count": count,
        "unique_dst_hosts": unique_dst_hosts,
        "unique_dst_ports": unique_dst_ports,
        "failed_ratio": failed / count,
        "syn_only_ratio": syn_only / count,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "bytes_ratio": bytes_out / (bytes_in + 1.0),
        "bytes_per_pkt": (bytes_out + bytes_in) / max(1, packets),
        "duration_mean": duration_mean,
        "duration_std": duration_std,
        "port_entropy": entropy,
        "dst_port_rarity": rarity,
        "host_pair_novelty_ratio": novel_pairs / count,
        "scan_rate": count / WINDOW_SECONDS,
        "scan_interval_cv": interval_cv([record.ts for record in records]),
        "unique_dst_ports_per_host": unique_dst_ports / max(1.0, unique_dst_hosts),
        "service_null_ratio": sum(
            1 for record in records if record.service in (None, "")
        )
        / count,
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_snapshots(
    records: Iterable[ConnRecord],
    baseline: BaselineProfile,
    min_events: int = MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_records in group_windows(records):
        if len(window_records) < min_events:
            continue
        start = key.start_ts
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=f"fs-{int(start)}-{key.src_ip}",
                feature_set_version=FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(start),
                    end=_utc(start + WINDOW_SECONDS),
                    size_sec=WINDOW_SECONDS,
                ),
                entity=Entity(src_ip=key.src_ip),
                features=compute_conn_features(window_records, baseline),
                context={
                    "conn_count": len(window_records),
                    "uids": sorted({record.uid for record in window_records})[:100],
                },
            )
        )
    return snapshots
