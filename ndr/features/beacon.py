"""D5 beaconing features for host-pair windows."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from statistics import fmean, median, pstdev
from typing import Iterable, Sequence

import numpy as np

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.baseline import BaselineProfile
from ndr.features.windows import (
    BEACON_MIN_EVENTS,
    BEACON_WINDOW_SECONDS,
    group_host_pair_windows,
)
from ndr.zeek import ConnRecord

BEACON_FEATURE_SET_VERSION = "v0.2.0"
BEACON_BIN_SECONDS = 5

BEACON_FEATURE_NAMES: tuple[str, ...] = (
    "conn_count",
    "conn_rate",
    "interval_mean",
    "interval_std",
    "interval_cv",
    "interval_median",
    "interval_mad",
    "interval_min",
    "interval_max",
    "autocorr_lag1",
    "fft_peak_ratio",
    "fft_entropy",
    "same_size_ratio",
    "bytes_out_mean",
    "bytes_in_mean",
    "bytes_cv",
    "duration_mean",
    "duration_cv",
    "failed_ratio",
    "dst_rarity",
    "host_pair_novelty_ratio",
    "periodicity_score",
)


def autocorr_lag1(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = fmean(values)
    denominator = sum((value - mean) ** 2 for value in values)
    if denominator <= 0.0:
        return 0.0
    numerator = sum(
        (values[index] - mean) * (values[index - 1] - mean)
        for index in range(1, len(values))
    )
    return float(numerator / denominator)


def fft_features(
    timestamps: Sequence[float], start_ts: float
) -> tuple[float, float]:
    n_bins = BEACON_WINDOW_SECONDS // BEACON_BIN_SECONDS
    counts = np.zeros(n_bins, dtype=float)
    for timestamp in timestamps:
        index = int((timestamp - start_ts) // BEACON_BIN_SECONDS)
        if 0 <= index < n_bins:
            counts[index] += 1.0

    centered = counts - counts.mean()
    power = np.abs(np.fft.rfft(centered)) ** 2
    power = power[1:]
    total = float(power.sum())
    if total <= 0.0:
        return 0.0, 0.0

    peak_ratio = float(power.max() / total)
    probabilities = power[power > 0] / total
    entropy = 0.0
    if len(power) > 1:
        entropy = float(
            -np.sum(probabilities * np.log2(probabilities)) / math.log2(len(power))
        )
    return peak_ratio, max(0.0, min(1.0, entropy))


def compute_beacon_features(
    records: Sequence[ConnRecord],
    baseline: BaselineProfile,
    start_ts: float,
) -> dict[str, float]:
    if not records:
        raise ValueError("cannot compute beacon features for an empty window")

    count = float(len(records))
    timestamps = sorted(record.ts for record in records)
    intervals = [
        later - earlier for earlier, later in zip(timestamps, timestamps[1:])
    ]
    if intervals:
        interval_mean = float(fmean(intervals))
        interval_std = float(pstdev(intervals))
        interval_median = float(median(intervals))
        interval_mad = float(
            median(abs(interval - interval_median) for interval in intervals)
        )
        interval_min = float(min(intervals))
        interval_max = float(max(intervals))
    else:
        interval_mean = interval_std = interval_median = 0.0
        interval_mad = interval_min = interval_max = 0.0
    interval_cv = interval_std / interval_mean if interval_mean > 0.0 else 0.0

    autocorr = autocorr_lag1(intervals)
    fft_peak, fft_entropy = fft_features(timestamps, start_ts)

    size_counts = Counter(
        (record.orig_bytes, record.resp_bytes) for record in records
    )
    same_size_ratio = size_counts.most_common(1)[0][1] / count

    bytes_out_mean = float(fmean(record.orig_bytes for record in records))
    bytes_in_mean = float(fmean(record.resp_bytes for record in records))
    total_bytes = [
        float(record.orig_bytes + record.resp_bytes) for record in records
    ]
    total_bytes_mean = float(fmean(total_bytes))
    if total_bytes_mean > 0.0 and len(total_bytes) > 1:
        bytes_cv = float(pstdev(total_bytes) / total_bytes_mean)
    else:
        bytes_cv = 0.0

    durations = [record.duration for record in records if record.duration is not None]
    if durations:
        duration_mean = float(fmean(durations))
        if len(durations) > 1 and duration_mean > 0.0:
            duration_cv = float(pstdev(durations) / duration_mean)
        else:
            duration_cv = 0.0
    else:
        duration_mean = duration_cv = 0.0

    failed_ratio = sum(
        1 for record in records if record.conn_state in {"S0", "REJ", "RSTO", "RSTR"}
    ) / count
    dst_rarity = -math.log2(baseline.dst_host_freq(records[0].resp_h))
    novelty_ratio = sum(
        1
        for record in records
        if f"{record.orig_h}|{record.resp_h}" not in baseline.host_pairs
    ) / count

    periodicity_score = (
        0.5 * fft_peak
        + 0.3 * max(0.0, autocorr)
        + 0.2 * max(0.0, 1.0 - min(interval_cv, 1.0))
    )

    return {
        "conn_count": count,
        "conn_rate": count / BEACON_WINDOW_SECONDS,
        "interval_mean": interval_mean,
        "interval_std": interval_std,
        "interval_cv": interval_cv,
        "interval_median": interval_median,
        "interval_mad": interval_mad,
        "interval_min": interval_min,
        "interval_max": interval_max,
        "autocorr_lag1": autocorr,
        "fft_peak_ratio": fft_peak,
        "fft_entropy": fft_entropy,
        "same_size_ratio": same_size_ratio,
        "bytes_out_mean": bytes_out_mean,
        "bytes_in_mean": bytes_in_mean,
        "bytes_cv": bytes_cv,
        "duration_mean": duration_mean,
        "duration_cv": duration_cv,
        "failed_ratio": failed_ratio,
        "dst_rarity": float(dst_rarity),
        "host_pair_novelty_ratio": novelty_ratio,
        "periodicity_score": periodicity_score,
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_beacon_snapshots(
    records: Iterable[ConnRecord],
    baseline: BaselineProfile,
    min_events: int = BEACON_MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_records in group_host_pair_windows(records):
        if len(window_records) < min_events:
            continue
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=(
                    f"fs-beacon-{int(key.start_ts)}-{key.src_ip}-"
                    f"{key.dst_ip}-{key.dst_port}"
                ),
                feature_set_version=BEACON_FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(key.start_ts),
                    end=_utc(key.start_ts + BEACON_WINDOW_SECONDS),
                    size_sec=BEACON_WINDOW_SECONDS,
                ),
                entity=Entity(
                    type="host_pair",
                    src_ip=key.src_ip,
                    dst_ip=key.dst_ip,
                    dst_port=key.dst_port,
                    proto=key.proto,
                ),
                features=compute_beacon_features(
                    window_records, baseline, key.start_ts
                ),
                context={
                    "conn_count": len(window_records),
                    "uids": sorted({record.uid for record in window_records})[:100],
                    "service": next(
                        (
                            record.service
                            for record in window_records
                            if record.service
                        ),
                        None,
                    ),
                },
            )
        )
    return snapshots
