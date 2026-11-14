"""D6 lateral-movement features over source-host SMB/DCE windows."""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Iterable, Sequence

import numpy as np

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.zeek import (
    iter_dce_rpc_jsonl,
    iter_smb_files_jsonl,
    iter_smb_mapping_jsonl,
)

LATERAL_WINDOW_SECONDS = 600
LATERAL_MIN_EVENTS = 3
LATERAL_CRITICAL_HOSTS = frozenset({"192.168.217.129"})
LATERAL_FEATURE_SET_VERSION = "v0.7.0"

LATERAL_FEATURE_NAMES: tuple[str, ...] = (
    "smb_unique_dsts",
    "smb_admin_share_count",
    "smb_exe_write_count",
    "smb_mapping_rarity",
    "dce_rpc_svcctl_count",
    "dce_rpc_atsvc_count",
    "service_creation_count",
    "smb_write_to_service_delta",
    "new_host_pair_count",
    "graph_out_degree",
    "graph_new_edges",
    "graph_betweenness",
    "asset_criticality",
)

EXECUTABLE_EXTENSIONS = frozenset({"exe", "dll", "ps1", "bat"})
SERVICE_ENDPOINTS = frozenset({"svcctl", "atsvc"})


@dataclass(frozen=True)
class LateralEvent:
    ts: float
    uid: str
    src_ip: str
    dst_ip: str
    kind: str
    path: str | None = None
    action: str | None = None
    name: str | None = None
    size: int = 0
    endpoint: str | None = None
    operation: str | None = None


@dataclass
class LateralBaselineProfile:
    feature_set_version: str
    path_counts: dict[str, int]
    host_pairs: set[str]
    critical_hosts: set[str]
    total_events: int
    feature_mean: dict[str, float] = field(default_factory=dict)
    feature_std: dict[str, float] = field(default_factory=dict)

    def path_freq(self, path: str) -> float:
        denominator = self.total_events + len(self.path_counts)
        if denominator <= 0:
            return 1.0
        return (self.path_counts.get(path, 0) + 1) / denominator

    def to_json(self) -> dict:
        return {
            "feature_set_version": self.feature_set_version,
            "path_counts": dict(sorted(self.path_counts.items())),
            "host_pairs": sorted(self.host_pairs),
            "critical_hosts": sorted(self.critical_hosts),
            "total_events": self.total_events,
            "feature_mean": dict(self.feature_mean),
            "feature_std": dict(self.feature_std),
        }

    @classmethod
    def from_json(cls, data: dict) -> "LateralBaselineProfile":
        return cls(
            feature_set_version=str(data["feature_set_version"]),
            path_counts={
                str(name): int(count)
                for name, count in data.get("path_counts", {}).items()
            },
            host_pairs={str(pair) for pair in data.get("host_pairs", [])},
            critical_hosts={
                str(host) for host in data.get("critical_hosts", [])
            },
            total_events=int(data.get("total_events", 0)),
            feature_mean={
                key: float(value)
                for key, value in data.get("feature_mean", {}).items()
            },
            feature_std={
                key: float(value)
                for key, value in data.get("feature_std", {}).items()
            },
        )


def load_lateral_events(run_dir: Path) -> list[LateralEvent]:
    """Load SMB mapping/file and DCE-RPC events for one run directory.

    ``smb_mapping.jsonl`` is required; missing ``smb_files.jsonl`` and
    ``dce_rpc.jsonl`` files are treated as empty logs.
    """
    events: list[LateralEvent] = []

    mapping_path = run_dir / "smb_mapping.jsonl"
    for record in iter_smb_mapping_jsonl(mapping_path):
        events.append(
            LateralEvent(
                ts=record.ts,
                uid=record.uid,
                src_ip=record.orig_h,
                dst_ip=record.resp_h,
                kind="mapping",
                path=record.path,
            )
        )

    files_path = run_dir / "smb_files.jsonl"
    if files_path.is_file():
        for record in iter_smb_files_jsonl(files_path):
            events.append(
                LateralEvent(
                    ts=record.ts,
                    uid=record.uid,
                    src_ip=record.orig_h,
                    dst_ip=record.resp_h,
                    kind="file",
                    path=record.path,
                    action=record.action,
                    name=record.name,
                    size=record.size,
                )
            )

    dce_path = run_dir / "dce_rpc.jsonl"
    if dce_path.is_file():
        for record in iter_dce_rpc_jsonl(dce_path):
            events.append(
                LateralEvent(
                    ts=record.ts,
                    uid=record.uid,
                    src_ip=record.orig_h,
                    dst_ip=record.resp_h,
                    kind="dce_rpc",
                    endpoint=record.endpoint,
                    operation=record.operation,
                )
            )

    return sorted(events, key=lambda event: (event.ts, event.uid, event.kind))


def build_raw_lateral_profile(
    events: Iterable[LateralEvent],
) -> LateralBaselineProfile:
    path_counts: dict[str, int] = {}
    host_pairs: set[str] = set()
    total = 0
    for event in events:
        total += 1
        host_pairs.add(f"{event.src_ip}|{event.dst_ip}")
        if event.kind == "mapping":
            path = event.path or ""
            path_counts[path] = path_counts.get(path, 0) + 1
    return LateralBaselineProfile(
        feature_set_version=LATERAL_FEATURE_SET_VERSION,
        path_counts=path_counts,
        host_pairs=host_pairs,
        critical_hosts=set(LATERAL_CRITICAL_HOSTS),
        total_events=total,
    )


def finalize_lateral_profile(
    profile: LateralBaselineProfile, snapshots: Sequence[FeatureSnapshot]
) -> LateralBaselineProfile:
    if not snapshots:
        raise ValueError("finalize_lateral_profile requires at least one snapshot")
    names = list(snapshots[0].features.keys())
    for name in names:
        values = np.asarray(
            [snapshot.features[name] for snapshot in snapshots], dtype=float
        )
        profile.feature_mean[name] = float(np.mean(values))
        std = float(np.std(values, ddof=0))
        profile.feature_std[name] = std if std > 0.0 else 1.0
    return profile


def save_lateral_profile(
    profile: LateralBaselineProfile, path: Path
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(profile.to_json(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_lateral_profile(path: Path) -> LateralBaselineProfile:
    return LateralBaselineProfile.from_json(
        json.loads(path.read_text(encoding="utf-8"))
    )


@dataclass(frozen=True)
class LateralWindowKey:
    src_ip: str
    start_ts: float


def group_lateral_windows(
    events: Iterable[LateralEvent], window_sec: int = LATERAL_WINDOW_SECONDS
) -> Iterable[tuple[LateralWindowKey, list[LateralEvent]]]:
    buckets: dict[LateralWindowKey, list[LateralEvent]] = {}
    for event in events:
        start = math.floor(event.ts / window_sec) * window_sec
        key = LateralWindowKey(src_ip=event.src_ip, start_ts=float(start))
        buckets.setdefault(key, []).append(event)
    for key in sorted(buckets, key=lambda item: (item.start_ts, item.src_ip)):
        yield key, sorted(
            buckets[key], key=lambda event: (event.ts, event.uid, event.kind)
        )


def _extension(event: LateralEvent) -> str:
    candidate = event.name or ""
    if not candidate and event.path:
        candidate = event.path.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in candidate:
        return ""
    return candidate.rsplit(".", 1)[-1].lower()


def is_executable_write(event: LateralEvent) -> bool:
    if event.kind != "file" or (event.action or "").lower() != "write":
        return False
    return _extension(event) in EXECUTABLE_EXTENSIONS


def _is_admin_share(event: LateralEvent) -> bool:
    path = (event.path or "").upper()
    return "ADMIN$" in path or "C$" in path


def _service_text(event: LateralEvent) -> str:
    return f"{event.endpoint or ''} {event.operation or ''}".strip().lower()


def is_service_event(event: LateralEvent) -> bool:
    if event.kind != "dce_rpc":
        return False
    endpoint = (event.endpoint or "").strip().lower()
    operation = (event.operation or "").strip().lower()
    return (
        endpoint in SERVICE_ENDPOINTS
        or "svcctl" in endpoint
        or "atsvc" in endpoint
        or "create" in operation
    )


def _brandes_betweenness(
    edges: Iterable[tuple[str, str]], source: str
) -> float:
    adjacency: dict[str, set[str]] = {}
    for src, dst in edges:
        adjacency.setdefault(src, set()).add(dst)
        adjacency.setdefault(dst, set()).add(src)

    nodes = sorted(adjacency)
    n = len(nodes)
    if n <= 2 or source not in adjacency:
        return 0.0

    betweenness = {node: 0.0 for node in nodes}
    for start in nodes:
        stack: list[str] = []
        predecessors: dict[str, list[str]] = {node: [] for node in nodes}
        sigma = {node: 0.0 for node in nodes}
        sigma[start] = 1.0
        distance = {node: -1 for node in nodes}
        distance[start] = 0
        queue: deque[str] = deque([start])

        while queue:
            vertex = queue.popleft()
            stack.append(vertex)
            for neighbour in sorted(adjacency[vertex]):
                if distance[neighbour] < 0:
                    distance[neighbour] = distance[vertex] + 1
                    queue.append(neighbour)
                if distance[neighbour] == distance[vertex] + 1:
                    sigma[neighbour] += sigma[vertex]
                    predecessors[neighbour].append(vertex)

        delta = {node: 0.0 for node in nodes}
        while stack:
            vertex = stack.pop()
            for predecessor in predecessors[vertex]:
                if sigma[vertex] > 0.0:
                    delta[predecessor] += (
                        sigma[predecessor] / sigma[vertex]
                    ) * (1.0 + delta[vertex])
            if vertex != start:
                betweenness[vertex] += delta[vertex]

    denominator = float((n - 1) * (n - 2))
    value = betweenness[source] / denominator
    return max(0.0, min(1.0, value))


def compute_lateral_features(
    events: Sequence[LateralEvent],
    baseline: LateralBaselineProfile,
    start_ts: float,
) -> dict[str, float]:
    if not events:
        raise ValueError("cannot compute lateral features for an empty window")

    mapping_events = [event for event in events if event.kind == "mapping"]
    file_events = [event for event in events if event.kind == "file"]
    dce_events = [event for event in events if event.kind == "dce_rpc"]

    # Graph metrics use each unique host pair once, regardless of how many
    # log lines touched it in the window.
    edges = list(
        dict.fromkeys((event.src_ip, event.dst_ip) for event in events)
    )
    destinations = {event.dst_ip for event in events}
    smb_destinations = {
        event.dst_ip
        for event in events
        if event.kind in {"mapping", "file"}
    }
    new_edges = [
        edge
        for edge in edges
        if f"{edge[0]}|{edge[1]}" not in baseline.host_pairs
    ]

    mapping_paths = [event.path or "" for event in mapping_events]
    mapping_rarity = (
        float(
            fmean(
                -math.log2(baseline.path_freq(path))
                for path in mapping_paths
            )
        )
        if mapping_paths
        else 0.0
    )

    svcctl_count = sum(
        1 for event in dce_events if "svcctl" in _service_text(event)
    )
    atsvc_count = sum(
        1 for event in dce_events if "atsvc" in _service_text(event)
    )
    service_creation_count = 0
    for event in dce_events:
        operation = (event.operation or "").strip().lower()
        if "create" in operation or operation in SERVICE_ENDPOINTS:
            service_creation_count += 1

    executable_writes = [
        event for event in file_events if is_executable_write(event)
    ]
    service_events = [
        event for event in dce_events if is_service_event(event)
    ]
    deltas = [
        service.ts - write.ts
        for write in executable_writes
        for service in service_events
        if service.ts - write.ts > 0.0
    ]
    write_to_service_delta = float(min(deltas)) if deltas else 0.0

    source = events[0].src_ip
    return {
        "smb_unique_dsts": float(len(smb_destinations)),
        "smb_admin_share_count": float(
            sum(1 for event in events if _is_admin_share(event))
        ),
        "smb_exe_write_count": float(len(executable_writes)),
        "smb_mapping_rarity": mapping_rarity,
        "dce_rpc_svcctl_count": float(svcctl_count),
        "dce_rpc_atsvc_count": float(atsvc_count),
        "service_creation_count": float(service_creation_count),
        "smb_write_to_service_delta": write_to_service_delta,
        "new_host_pair_count": float(len(new_edges)),
        "graph_out_degree": float(len(destinations)),
        "graph_new_edges": float(len(new_edges)),
        "graph_betweenness": _brandes_betweenness(edges, source),
        "asset_criticality": (
            1.0 if source in baseline.critical_hosts else 0.0
        ),
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_lateral_snapshots(
    events: Iterable[LateralEvent],
    baseline: LateralBaselineProfile,
    min_events: int = LATERAL_MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_events in group_lateral_windows(events):
        if len(window_events) < min_events:
            continue
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=(
                    f"fs-lateral-{int(key.start_ts)}-{key.src_ip}"
                ),
                feature_set_version=LATERAL_FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(key.start_ts),
                    end=_utc(key.start_ts + LATERAL_WINDOW_SECONDS),
                    size_sec=LATERAL_WINDOW_SECONDS,
                ),
                entity=Entity(type="host", src_ip=key.src_ip),
                features=compute_lateral_features(
                    window_events, baseline, key.start_ts
                ),
                context={
                    "event_count": len(window_events),
                    "uids": sorted(
                        {event.uid for event in window_events}
                    )[:100],
                },
            )
        )
    return snapshots
