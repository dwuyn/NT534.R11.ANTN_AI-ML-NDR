"""Window grouping for connection records."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Iterator

from ndr.zeek import ConnRecord

WINDOW_SECONDS = 300
MIN_EVENTS = 20


@dataclass(frozen=True)
class WindowKey:
    src_ip: str
    start_ts: float


def group_windows(
    records: Iterable[ConnRecord], window_sec: int = WINDOW_SECONDS
) -> Iterator[tuple[WindowKey, list[ConnRecord]]]:
    buckets: dict[WindowKey, list[ConnRecord]] = {}
    for record in records:
        start = math.floor(record.ts / window_sec) * window_sec
        key = WindowKey(src_ip=record.orig_h, start_ts=float(start))
        buckets.setdefault(key, []).append(record)

    for key in sorted(buckets, key=lambda item: (item.start_ts, item.src_ip)):
        yield key, sorted(buckets[key], key=lambda record: (record.ts, record.uid))
