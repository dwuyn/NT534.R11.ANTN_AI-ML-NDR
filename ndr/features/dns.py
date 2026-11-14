"""D7 DNS tunneling features over (host, parent domain) windows."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from statistics import fmean
from typing import TYPE_CHECKING, Iterable, Sequence

from ndr.contracts import Entity, FeatureSnapshot, Window
from ndr.features.conn import interval_cv
from ndr.features.windows import (
    DNS_MIN_EVENTS,
    DNS_WINDOW_SECONDS,
    group_dns_windows,
)
from ndr.zeek import DnsRecord

if TYPE_CHECKING:
    from ndr.features.dns_baseline import DnsBaselineProfile

DNS_FEATURE_SET_VERSION = "v0.3.0"

DNS_FEATURE_NAMES: tuple[str, ...] = (
    "query_count",
    "query_rate",
    "unique_subdomains",
    "unique_subdomain_ratio",
    "query_len_mean",
    "query_len_max",
    "label_count_mean",
    "label_count_max",
    "first_label_len_mean",
    "first_label_len_max",
    "entropy_mean",
    "entropy_max",
    "unique_char_ratio_mean",
    "digit_ratio_mean",
    "vowel_ratio_mean",
    "consonant_ratio_mean",
    "txt_ratio",
    "null_ratio",
    "nxdomain_ratio",
    "answer_count_mean",
    "ttl_mean",
    "interval_cv",
    "parent_rarity",
    "subdomain_rarity_mean",
    "dga_like_score_mean",
    "tunnel_score",
)

VOWELS = frozenset("aeiou")


def _normalize(query: str) -> str:
    text = query.strip().lower()
    if text.endswith("."):
        text = text[:-1]
    return text


def query_labels(query: str) -> list[str]:
    return [label for label in _normalize(query).split(".") if label]


def parent_domain(query: str) -> str:
    labels = query_labels(query)
    if len(labels) < 2:
        return _normalize(query)
    return ".".join(labels[-2:])


def subdomain(query: str) -> str:
    labels = query_labels(query)
    if len(labels) <= 2:
        return ""
    return ".".join(labels[:-2])


def lexical_text(query: str) -> str:
    labels = query_labels(query)
    sub = subdomain(query)
    if sub:
        return sub
    if labels:
        return labels[0]
    return _normalize(query)


def subdomain_or_first_label(query: str) -> str:
    return subdomain(query) or lexical_text(query)


def char_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    counts = Counter(text)
    return float(
        -sum((count / total) * math.log2(count / total) for count in counts.values())
    )


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _lexical_stats(query: str) -> dict[str, float]:
    text = lexical_text(query)
    length = max(1, len(text))
    entropy = char_entropy(text)
    unique_char_ratio = len(set(text)) / length
    digit_ratio = sum(character.isdigit() for character in text) / length
    vowel_ratio = sum(character in VOWELS for character in text) / length
    consonant_ratio = (
        sum(character.isalpha() and character not in VOWELS for character in text)
        / length
    )
    dga_like = _clamp01(
        0.5 * min(entropy / 5.0, 1.0)
        + 0.3 * digit_ratio
        + 0.2 * (1.0 - vowel_ratio)
    )
    return {
        "entropy": entropy,
        "unique_char_ratio": unique_char_ratio,
        "digit_ratio": digit_ratio,
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "dga_like": dga_like,
    }


def compute_dns_features(
    records: Sequence[DnsRecord],
    baseline: DnsBaselineProfile,
    start_ts: float,
) -> dict[str, float]:
    if not records:
        raise ValueError("cannot compute dns features for an empty window")

    count = float(len(records))
    lexical = [_lexical_stats(record.query) for record in records]
    query_lengths = [len(_normalize(record.query)) for record in records]
    label_counts = [len(query_labels(record.query)) for record in records]
    first_label_lengths = [
        len(query_labels(record.query)[0]) if query_labels(record.query) else 0
        for record in records
    ]
    answer_counts = [len(record.answers) for record in records]
    ttls = [fmean(record.ttls) if record.ttls else 0.0 for record in records]
    subdomain_names = [subdomain_or_first_label(record.query) for record in records]
    unique_subdomains = float(len(set(subdomain_names)))

    query_len_mean = float(fmean(query_lengths))
    entropy_mean = float(fmean(item["entropy"] for item in lexical))
    query_rate = count / DNS_WINDOW_SECONDS
    unique_subdomain_ratio = unique_subdomains / count
    parent = parent_domain(records[0].query)

    return {
        "query_count": count,
        "query_rate": query_rate,
        "unique_subdomains": unique_subdomains,
        "unique_subdomain_ratio": unique_subdomain_ratio,
        "query_len_mean": query_len_mean,
        "query_len_max": float(max(query_lengths)),
        "label_count_mean": float(fmean(label_counts)),
        "label_count_max": float(max(label_counts)),
        "first_label_len_mean": float(fmean(first_label_lengths)),
        "first_label_len_max": float(max(first_label_lengths)),
        "entropy_mean": entropy_mean,
        "entropy_max": float(max(item["entropy"] for item in lexical)),
        "unique_char_ratio_mean": float(
            fmean(item["unique_char_ratio"] for item in lexical)
        ),
        "digit_ratio_mean": float(fmean(item["digit_ratio"] for item in lexical)),
        "vowel_ratio_mean": float(fmean(item["vowel_ratio"] for item in lexical)),
        "consonant_ratio_mean": float(
            fmean(item["consonant_ratio"] for item in lexical)
        ),
        "txt_ratio": sum(
            1 for record in records if record.qtype_name == "TXT"
        )
        / count,
        "null_ratio": sum(
            1 for record in records if record.qtype_name == "NULL"
        )
        / count,
        "nxdomain_ratio": sum(
            1 for record in records if record.rcode_name == "NXDOMAIN"
        )
        / count,
        "answer_count_mean": float(fmean(answer_counts)),
        "ttl_mean": float(fmean(ttls)),
        "interval_cv": interval_cv([record.ts for record in records]),
        "parent_rarity": float(-math.log2(baseline.parent_freq(parent))),
        "subdomain_rarity_mean": float(
            fmean(
                -math.log2(baseline.subdomain_freq(name))
                for name in subdomain_names
            )
        ),
        "dga_like_score_mean": float(fmean(item["dga_like"] for item in lexical)),
        "tunnel_score": _clamp01(
            0.4 * min(query_len_mean / 60.0, 1.0)
            + 0.3 * min(entropy_mean / 5.0, 1.0)
            + 0.2 * min(query_rate / 1.0, 1.0)
            + 0.1 * unique_subdomain_ratio
        ),
    }


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def build_dns_snapshots(
    records: Iterable[DnsRecord],
    baseline: DnsBaselineProfile,
    min_events: int = DNS_MIN_EVENTS,
) -> list[FeatureSnapshot]:
    snapshots: list[FeatureSnapshot] = []
    for key, window_records in group_dns_windows(records):
        if len(window_records) < min_events:
            continue
        snapshots.append(
            FeatureSnapshot(
                snapshot_id=(
                    f"fs-dns-{int(key.start_ts)}-{key.src_ip}-{key.parent_domain}"
                ),
                feature_set_version=DNS_FEATURE_SET_VERSION,
                window=Window(
                    start=_utc(key.start_ts),
                    end=_utc(key.start_ts + DNS_WINDOW_SECONDS),
                    size_sec=DNS_WINDOW_SECONDS,
                ),
                entity=Entity(
                    type="host_domain",
                    src_ip=key.src_ip,
                    domain=key.parent_domain,
                ),
                features=compute_dns_features(
                    window_records, baseline, key.start_ts
                ),
                context={
                    "query_count": len(window_records),
                    "uids": sorted({record.uid for record in window_records})[:100],
                },
            )
        )
    return snapshots
