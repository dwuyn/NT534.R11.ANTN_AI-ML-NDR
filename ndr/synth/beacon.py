"""Deterministic synthetic corpus for D5 beaconing."""

from __future__ import annotations

import random
import zlib
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.generate import (
    browsing_events,
    make_conn_obj,
    to_utc,
    write_run,
)
from ndr.synth.scenarios import ATTACKER_IP

BEACON_BASE_TS = 1770100800.0
BEACON_RUN_SECONDS = 1800

BENIGN_HOSTS = tuple(f"192.168.217.{index}" for index in range(101, 111))
ATTACK_HOST = ATTACKER_IP

BENIGN_SPECS: tuple[tuple[str, str], ...] = (
    ("benign_browsing", "standard"),
    ("benign_ntp", "64s"),
    ("benign_update", "30s"),
    ("benign_telemetry", "60s"),
)

ATTACK_SPECS: tuple[tuple[str, str, str, float, float, bool], ...] = (
    ("attack_beacon_10s", "10s", "203.0.113.50", 10.0, 1.0, False),
    ("attack_beacon_30s", "30s", "203.0.113.51", 30.0, 0.0, False),
    ("attack_beacon_30s_jitter20", "jitter20", "203.0.113.52", 30.0, 6.0, False),
    ("attack_beacon_60s", "60s", "203.0.113.53", 60.0, 0.0, False),
    ("attack_beacon_60s_jitter35", "jitter35", "203.0.113.54", 60.0, 21.0, False),
    ("attack_beacon_variable_size", "variable", "203.0.113.55", 30.0, 2.0, True),
)


def _periodic(
    start: float,
    hosts: tuple[str, ...],
    dst: str,
    dst_port: int,
    proto: str,
    service: str,
    interval: float,
    jitter: float,
    out_bytes: int,
    in_bytes: int,
    duration: float,
    orig_port: int | None,
    rng: random.Random,
) -> list[dict]:
    events: list[dict] = []
    end = start + BEACON_RUN_SECONDS
    for host in hosts:
        timestamp = start + rng.uniform(0.0, interval)
        while timestamp < end:
            source_port = (
                orig_port if orig_port is not None else rng.randint(49152, 65535)
            )
            events.append(
                make_conn_obj(
                    timestamp,
                    host,
                    source_port,
                    dst,
                    dst_port,
                    service,
                    duration,
                    out_bytes,
                    in_bytes,
                    2,
                    2,
                    "SF",
                    proto=proto,
                )
            )
            timestamp += max(
                1.0, rng.uniform(interval - jitter, interval + jitter)
            )
    return events


def _benign_events(scenario: str, start: float, rng: random.Random) -> list[dict]:
    if scenario == "benign_browsing":
        return browsing_events(start, BEACON_RUN_SECONDS, rng)
    if scenario == "benign_ntp":
        return _periodic(
            start,
            BENIGN_HOSTS,
            "203.0.113.123",
            123,
            "udp",
            "ntp",
            64.0,
            1.0,
            48,
            48,
            0.01,
            123,
            rng,
        )
    if scenario == "benign_update":
        return _periodic(
            start,
            BENIGN_HOSTS,
            "198.51.100.10",
            443,
            "tcp",
            "ssl",
            30.0,
            2.0,
            800,
            800,
            0.05,
            None,
            rng,
        )
    if scenario == "benign_telemetry":
        return _periodic(
            start,
            BENIGN_HOSTS,
            "203.0.113.200",
            443,
            "tcp",
            "ssl",
            60.0,
            3.0,
            500,
            500,
            0.1,
            None,
            rng,
        )
    raise ValueError(f"unknown benign beacon scenario: {scenario}")


def _attack_events(
    start: float,
    destination: str,
    interval: float,
    jitter: float,
    variable_size: bool,
    rng: random.Random,
) -> list[dict]:
    if not variable_size:
        return _periodic(
            start,
            (ATTACK_HOST,),
            destination,
            443,
            "tcp",
            "ssl",
            interval,
            jitter,
            1200,
            800,
            0.2,
            None,
            rng,
        )

    events: list[dict] = []
    end = start + BEACON_RUN_SECONDS
    timestamp = start + rng.uniform(0.0, interval)
    while timestamp < end:
        events.append(
            make_conn_obj(
                timestamp,
                ATTACK_HOST,
                rng.randint(49152, 65535),
                destination,
                443,
                "ssl",
                0.2,
                rng.randint(500, 5000),
                800,
                2,
                2,
                "SF",
            )
        )
        timestamp += max(1.0, rng.uniform(interval - jitter, interval + jitter))
    return events


def generate_beacon_corpus(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 6,
    attack_runs: int = 6,
) -> list[Path]:
    if benign_runs < 6 or attack_runs < 5:
        raise ValueError("beacon corpus needs >=6 benign and >=5 attack runs")

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
        run_id = f"beacon-{index:02d}-{scenario}-{variant}"
        start = BEACON_BASE_TS + index * 7200
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))

        if scenario.startswith("benign_"):
            events = _benign_events(scenario, start, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="benign",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + BEACON_RUN_SECONDS),
                attacker_ip=None,
                victim_ip=None,
                tool="synthetic_benign_periodic",
                mitre_tactic=[],
                mitre_technique=[],
                expected_detection=[],
                notes="synthetic beacon corpus",
            )
        else:
            spec = next(item for item in ATTACK_SPECS if item[0] == scenario)
            _, _, destination, interval, jitter, variable_size = spec
            events = _attack_events(
                start, destination, interval, jitter, variable_size, rng
            )
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="attack",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + BEACON_RUN_SECONDS),
                attacker_ip=ATTACK_HOST,
                victim_ip="192.168.217.129",
                tool="synthetic_beacon",
                mitre_tactic=["TA0011"],
                mitre_technique=["T1071.001", "T1573"],
                expected_detection=["D5"],
                notes="synthetic beacon corpus",
            )

        run_dirs.append(write_run(out_dir, run_id, ground_truth, events))

    return run_dirs
