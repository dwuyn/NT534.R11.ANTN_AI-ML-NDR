"""Deterministic synthetic Zeek dns.log generation."""

from __future__ import annotations

import json
import random
import zlib
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.generate import make_uid, to_utc

DNS_BASE_TS = 1770100800.0
DNS_RUN_SECONDS = 1800
RESOLVER = "192.168.217.2"
BENIGN_HOSTS = tuple(f"192.168.217.{index}" for index in range(101, 111))
ATTACK_HOST = "192.168.217.132"
VICTIM_HOST = "192.168.217.129"

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
HEX = "0123456789abcdef"

# Intervals are faster than the plan's nominal 60 s / 30 s because
# DNS_MIN_EVENTS=10 per 5-minute (host, parent) window needs >=1 query/30 s.
BENIGN_SPECS: tuple[tuple[str, str], ...] = (
    ("benign_dns_browsing", "standard"),
    ("benign_dns_update", "25s"),
    ("benign_dns_av", "20s"),
    ("benign_dns_cdn", "5s"),
    ("benign_dns_browsing", "standard"),
    ("benign_dns_update", "25s"),
)

ATTACK_SPECS: tuple[tuple[str, str, str, str, float, str], ...] = (
    ("attack_dns_iodine", "5qps", "iodine.test", "TXT", 5.0, "base32:40"),
    ("attack_dns_dnscat", "3qps", "dnscat.test", "TXT", 3.0, "hex:50"),
    ("attack_dns_low_entropy", "1qps", "lowent.test", "TXT", 1.0, "low:40"),
    ("attack_dns_slow", "0.1qps", "slow.test", "TXT", 0.1, "base32:30"),
    ("attack_dns_null", "2qps", "null.test", "NULL", 2.0, "hex:40"),
    ("attack_dns_mixed", "1qps", "mixed.test", "TXT/A", 1.0, "base32:30"),
)

BROWSING_DOMAINS = (
    "www.google.com",
    "mail.google.com",
    "cdn.jsdelivr.net",
    "github.com",
    "docs.python.org",
    "www.wikipedia.org",
    "outlook.office.com",
    "api.github.com",
)


def _event(
    ts: float,
    src: str,
    query: str,
    qtype: str,
    rcode: str,
    answers: list[str],
    ttls: list[float],
    rng: random.Random,
) -> dict:
    return {
        "ts": round(float(ts), 6),
        "id": {
            "orig_h": src,
            "orig_p": rng.randint(49152, 65535),
            "resp_h": RESOLVER,
            "resp_p": 53,
        },
        "proto": "udp",
        "query": query,
        "qtype_name": qtype,
        "rcode_name": rcode,
        "answers": answers,
        "TTLs": ttls,
    }


def _browsing(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    end = start + DNS_RUN_SECONDS
    for host in BENIGN_HOSTS:
        timestamp = start + rng.uniform(0.0, 2.0)
        while timestamp < end:
            query = rng.choice(BROWSING_DOMAINS)
            qtype = "A" if rng.random() < 0.9 else "AAAA"
            count = rng.randint(1, 3)
            if qtype == "A":
                answers = [
                    f"203.0.113.{rng.randint(1, 254)}" for _ in range(count)
                ]
            else:
                answers = [
                    f"2001:db8::{rng.randint(1, 0xFFFF):x}" for _ in range(count)
                ]
            ttl = float(rng.randint(30, 300))
            events.append(
                _event(
                    timestamp,
                    host,
                    query,
                    qtype,
                    "NOERROR",
                    answers,
                    [ttl] * count,
                    rng,
                )
            )
            timestamp += rng.uniform(1.0, 4.0)
    return events


def _periodic_benign(
    start: float,
    query: str,
    interval: float,
    jitter: float,
    ttl: float,
    rng: random.Random,
) -> list[dict]:
    events: list[dict] = []
    end = start + DNS_RUN_SECONDS
    for host in BENIGN_HOSTS:
        timestamp = start + rng.uniform(0.0, interval)
        while timestamp < end:
            events.append(
                _event(
                    timestamp,
                    host,
                    query,
                    "A",
                    "NOERROR",
                    ["203.0.113.10"],
                    [ttl],
                    rng,
                )
            )
            timestamp += max(1.0, rng.uniform(interval - jitter, interval + jitter))
    return events


def _cdn(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    end = start + DNS_RUN_SECONDS
    for host in BENIGN_HOSTS:
        timestamp = start + rng.uniform(0.0, 5.0)
        while timestamp < end:
            index = rng.randint(1, 50)
            events.append(
                _event(
                    timestamp,
                    host,
                    f"img{index}.cdn.example.net",
                    "A",
                    "NOERROR",
                    ["203.0.113.20"],
                    [120.0],
                    rng,
                )
            )
            timestamp += max(1.0, rng.uniform(3.0, 7.0))
    return events


def _benign_events(
    scenario: str, start: float, rng: random.Random
) -> list[dict]:
    if scenario == "benign_dns_browsing":
        return _browsing(start, rng)
    if scenario == "benign_dns_update":
        return _periodic_benign(
            start, "update.example.com", 25.0, 5.0, 60.0, rng
        )
    if scenario == "benign_dns_av":
        return _periodic_benign(
            start, "telemetry.av.example.com", 20.0, 3.0, 30.0, rng
        )
    if scenario == "benign_dns_cdn":
        return _cdn(start, rng)
    raise ValueError(f"unknown benign dns scenario: {scenario}")


def _random_label(length: int, alphabet: str, rng: random.Random) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _attack_events(
    start: float,
    parent: str,
    qtype: str,
    rate: float,
    pattern: str,
    rng: random.Random,
) -> list[dict]:
    kind, _, raw_length = pattern.partition(":")
    length = int(raw_length)
    interval = 1.0 / rate
    events: list[dict] = []
    end = start + DNS_RUN_SECONDS
    index = 0
    timestamp = start
    while timestamp < end:
        if kind == "low":
            subdomain = "a" * (length - 4) + f"{index:04d}"
        elif kind == "hex":
            subdomain = _random_label(length, HEX, rng)
        else:
            subdomain = _random_label(length, BASE32, rng)
        subdomain = subdomain[:63]
        query = f"{subdomain}.{parent}"
        current_qtype = qtype
        if qtype == "TXT/A":
            current_qtype = "TXT" if index % 2 == 0 else "A"
        rcode = "NOERROR"
        answers: list[str] = []
        ttls: list[float] = []
        if current_qtype == "TXT":
            answers = ["ok"]
            ttls = [60.0]
        elif current_qtype == "A":
            answers = ["203.0.113.9"]
            ttls = [60.0]
        if qtype == "TXT/A" and rng.random() < 0.2:
            rcode = "NXDOMAIN"
            answers = []
            ttls = []
        events.append(
            _event(
                timestamp,
                ATTACK_HOST,
                query,
                current_qtype,
                rcode,
                answers,
                ttls,
                rng,
            )
        )
        index += 1
        timestamp = start + index * interval
    return events


def write_dns_run(
    out_dir: Path,
    run_id: str,
    ground_truth: GroundTruthRun,
    events: list[dict],
) -> Path:
    events = sorted(events, key=lambda event: event["ts"])
    for index, event in enumerate(events):
        event["uid"] = make_uid(run_id, index)

    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    with (run_dir / "dns.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    (run_dir / "run.json").write_text(
        ground_truth.model_dump_json(indent=2), encoding="utf-8"
    )
    return run_dir


def generate_dns_corpus(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 6,
    attack_runs: int = 6,
) -> list[Path]:
    if benign_runs < 6 or attack_runs < 5:
        raise ValueError("dns corpus needs >=6 benign and >=5 attack runs")

    specs: list[tuple[str, str]] = [
        BENIGN_SPECS[index % len(BENIGN_SPECS)] for index in range(benign_runs)
    ]
    specs.extend(
        (scenario, variant)
        for scenario, variant, *_ in (
            ATTACK_SPECS[index % len(ATTACK_SPECS)]
            for index in range(attack_runs)
        )
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    run_dirs: list[Path] = []

    for index, (scenario, variant) in enumerate(specs):
        run_id = f"dns-{index:02d}-{scenario}-{variant}"
        start = DNS_BASE_TS + index * 3600
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))

        if scenario.startswith("benign_"):
            events = _benign_events(scenario, start, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="benign",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + DNS_RUN_SECONDS),
                attacker_ip=None,
                victim_ip=None,
                tool="synthetic_dns_benign",
                mitre_tactic=[],
                mitre_technique=[],
                expected_detection=[],
                notes="synthetic dns corpus",
            )
        else:
            _, _, parent, qtype, rate, pattern = next(
                item for item in ATTACK_SPECS if item[0] == scenario
            )
            events = _attack_events(start, parent, qtype, rate, pattern, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="attack",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + DNS_RUN_SECONDS),
                attacker_ip=ATTACK_HOST,
                victim_ip=VICTIM_HOST,
                tool="synthetic_dns_tunnel",
                mitre_tactic=["TA0010", "TA0011"],
                mitre_technique=["T1048", "T1071.004"],
                expected_detection=["D7"],
                notes="synthetic dns corpus",
            )

        run_dirs.append(write_dns_run(out_dir, run_id, ground_truth, events))

    return run_dirs
