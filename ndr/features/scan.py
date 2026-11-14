"""D2 port-scan features for connection windows."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Sequence

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.baseline import BaselineProfile
from ndr.features.conn import interval_cv, port_entropy
from ndr.features.windows import group_windows
from ndr.zeek import ConnRecord

SCAN_WINDOW_SECONDS = 300
SCAN_MIN_EVENTS = 10
SCAN_FEATURE_SET_VERSION = "v0.4.0"

SCAN_FEATURE_NAMES: tuple[str, ...] = (
    "scan_unique_ports",
    "scan_unique_hosts",
    "scan_failed_ratio",
    "scan_syn_ratio",
    "scan_port_entropy",
    "scan_rate",
    "scan_interval_cv",
    "scan_new_host_ratio",
    "scan_service_null_ratio",
)

FAILED_STATES = frozenset({"S0", "REJ", "RSTO", "RSTR"})


def compute_scan_features(
    records: Sequence[ConnRecord], baseline: BaselineProfile
) -> dict[str, float]:
    if not records:
        raise ValueError("cannot compute scan features for an empty window")

    count = float(len(records))
    unique_hosts = {record.resp_h for record in records}
    new_hosts = sum(1 for record in records if record.resp_h not in baseline.dst_host_counts)
    failed = sum(1 for record in records if record.conn_state in FAILED_STATES)
    syn_only = sum(1 for record in records if record.conn_state == "S0")

    return {
        "scan_unique_ports": float(len({record.resp_p for record in records})),
        "scan_unique_hosts": float(len(unique_hosts)),
        "scan_failed_ratio": failed / count,
        "scan_syn_ratio": syn_only / count,
        "scan_port_entropy": port_entropy([record.resp_p for record in records]),
        "scan_rate": count / SCAN_WINDOW_SECONDS,
        "scan_interval_cv": interval_cv([record.ts for record in records]),
        "scan_new_host_ratio": new_hosts / count,
        "scan_service_null_ratio": sum(
            1 for record in records if record.service in (None, "")
        )
        / count,
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_scan_snapshots(
    records: Iterable[ConnRecord],
    baseline: BaselineProfile,
    min_events: int = SCAN_MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_records in group_windows(
        records, window_sec=SCAN_WINDOW_SECONDS
    ):
        if len(window_records) < min_events:
            continue
        start = key.start_ts
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=f"fs-scan-{int(start)}-{key.src_ip}",
                feature_set_version=SCAN_FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(start),
                    end=_utc(start + SCAN_WINDOW_SECONDS),
                    size_sec=SCAN_WINDOW_SECONDS,
                ),
                entity=Entity(src_ip=key.src_ip),
                features=compute_scan_features(window_records, baseline),
                context={
                    "conn_count": len(window_records),
                    "uids": sorted({record.uid for record in window_records})[:100],
                },
            )
        )
    return snapshots
