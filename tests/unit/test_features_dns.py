import math

import pytest

from ndr.features.dns import (
    build_dns_snapshots,
    char_entropy,
    compute_dns_features,
    lexical_text,
    parent_domain,
    subdomain,
)
from ndr.features.dns_baseline import DnsBaselineProfile
from ndr.zeek import DnsRecord


def _baseline() -> DnsBaselineProfile:
    return DnsBaselineProfile(
        feature_set_version="v0.3.0",
        parent_counts={"example.com": 100},
        subdomain_counts={"abcdefghij": 100},
        total_queries=100,
    )


def _records(count: int = 10) -> list[DnsRecord]:
    return [
        DnsRecord(
            ts=float(index * 10),
            uid=f"C{index}",
            orig_h="10.0.0.1",
            orig_p=1234,
            resp_h="10.0.0.2",
            resp_p=53,
            proto="udp",
            query="abcdefghij.example.com",
            qtype_name="TXT",
            rcode_name="NXDOMAIN",
            answers=(),
            ttls=(),
        )
        for index in range(count)
    ]


def test_golden_window_features() -> None:
    features = compute_dns_features(_records(), _baseline(), 0.0)

    assert features["query_count"] == 10
    assert features["query_rate"] == pytest.approx(10 / 300)
    assert features["unique_subdomains"] == 1
    assert features["unique_subdomain_ratio"] == pytest.approx(0.1)
    assert features["query_len_mean"] == 22
    assert features["query_len_max"] == 22
    assert features["label_count_mean"] == 3
    assert features["label_count_max"] == 3
    assert features["first_label_len_mean"] == 10
    assert features["first_label_len_max"] == 10
    assert features["entropy_mean"] == pytest.approx(math.log2(10))
    assert features["entropy_max"] == pytest.approx(math.log2(10))
    assert features["unique_char_ratio_mean"] == pytest.approx(1.0)
    assert features["digit_ratio_mean"] == pytest.approx(0.0)
    assert features["vowel_ratio_mean"] == pytest.approx(0.3)
    assert features["consonant_ratio_mean"] == pytest.approx(0.7)
    assert features["txt_ratio"] == pytest.approx(1.0)
    assert features["null_ratio"] == pytest.approx(0.0)
    assert features["nxdomain_ratio"] == pytest.approx(1.0)
    assert features["answer_count_mean"] == pytest.approx(0.0)
    assert features["ttl_mean"] == pytest.approx(0.0)
    assert features["interval_cv"] == pytest.approx(0.0)
    assert features["parent_rarity"] == pytest.approx(0.0)
    assert features["subdomain_rarity_mean"] == pytest.approx(0.0)
    assert features["dga_like_score_mean"] == pytest.approx(0.472193, abs=1e-5)
    assert features["tunnel_score"] == pytest.approx(0.36265, abs=1e-5)


def test_query_normalization_helpers() -> None:
    assert parent_domain("a.b.Example.COM.") == "example.com"
    assert subdomain("a.b.example.com") == "a.b"
    assert lexical_text("www.google.com") == "www"
    assert parent_domain("localhost") == "localhost"
    assert char_entropy("") == 0.0


def test_build_dns_snapshots_drops_small_windows() -> None:
    assert build_dns_snapshots(_records(9), _baseline()) == []
    snapshots = build_dns_snapshots(_records(10), _baseline())
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.entity.type == "host_domain"
    assert snapshot.entity.domain == "example.com"
    assert snapshot.entity.src_ip == "10.0.0.1"
    assert snapshot.context["query_count"] == 10
    assert snapshot.snapshot_id == "fs-dns-0-10.0.0.1-example.com"
