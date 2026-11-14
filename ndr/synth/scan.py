"""Deterministic synthetic corpus for D2 port scans."""

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

SCAN_BASE_TS = 1770300000.0
SCAN_RUN_SECONDS = 1800

BENIGN_HOSTS = tuple(f"192.168.217.{index}" for index in range(101, 111))
ATTACK_HOST = ATTACKER_IP
VICTIM_HOST = "192.168.217.129"

BENIGN_SPECS: tuple[tuple[str, str], ...] = (
    ("benign_browsing", "standard"),
    ("benign_admin", "standard"),
    ("benign_update", "standard"),
    ("benign_mixed", "standard"),
    ("benign_monitoring", "30s"),
    ("benign_backup", "30s"),
)

ATTACK_SPECS: tuple[tuple[str, str], ...] = (
    ("attack_scan_fast", "vertical_200_ports"),
    ("attack_scan_slow", "vertical_40_ports_10min"),
    ("attack_scan_horizontal", "horizontal_50_hosts_445"),
    ("attack_scan_service", "service_scan_8_ports_80_hosts"),
    ("attack_scan_jittered", "low_rate"),
    ("attack_scan_noisy", "mixed_success"),
)

SERVICE_PORTS = (21, 22, 23, 25, 80, 443, 445, 3389)


def _conn(
    ts: float,
    src: str,
    dst: str,
    dst_port: int,
    state: str,
    service: str | None,
    rng: random.Random,
    duration: float | None = None,
    orig_bytes: int = 0,
    resp_bytes: int = 0,
) -> dict:
    return make_conn_obj(
        ts,
        src,
        rng.randint(49152, 65535),
        dst,
        dst_port,
        service,
        duration,
        orig_bytes,
        resp_bytes,
        1 if duration is not None else 0,
        1 if duration is not None else 0,
        state,
    )


def _periodic(
    start: float,
    hosts: tuple[str, ...],
    destination: str,
    dst_port: int,
    service: str,
    interval: float,
    jitter: float,
    rng: random.Random,
) -> list[dict]:
    events: list[dict] = []
    end = start + SCAN_RUN_SECONDS
    for host in hosts:
        timestamp = start + rng.uniform(0.0, 1.0)
        while timestamp < end:
            events.append(
                _conn(
                    timestamp,
                    host,
                    destination,
                    dst_port,
                    "SF",
                    service,
                    rng,
                    duration=0.1,
                    orig_bytes=200,
                    resp_bytes=400,
                )
            )
            timestamp += max(1.0, rng.uniform(interval - jitter, interval + jitter))
    return events


def _monitoring(start: float, rng: random.Random) -> list[dict]:
    hosts = BENIGN_HOSTS[:5]
    destinations = tuple(f"192.168.217.{index}" for index in range(121, 126))
    events: list[dict] = []
    end = start + SCAN_RUN_SECONDS
    for host in hosts:
        timestamp = start + rng.uniform(0.0, 1.0)
        while timestamp < end:
            events.append(
                _conn(
                    timestamp,
                    host,
                    rng.choice(destinations),
                    443,
                    "SF",
                    "ssl",
                    rng,
                    duration=0.05,
                    orig_bytes=400,
                    resp_bytes=800,
                )
            )
            timestamp += rng.uniform(29.0, 31.0)
    return events


def _backup(start: float, rng: random.Random) -> list[dict]:
    hosts = BENIGN_HOSTS[5:10]
    events: list[dict] = []
    end = start + SCAN_RUN_SECONDS
    for host in hosts:
        timestamp = start + rng.uniform(0.0, 1.0)
        while timestamp < end:
            events.append(
                _conn(
                    timestamp,
                    host,
                    VICTIM_HOST,
                    445,
                    "SF",
                    "smb",
                    rng,
                    duration=rng.uniform(0.5, 3.0),
                    orig_bytes=rng.randint(2000, 8000),
                    resp_bytes=rng.randint(500, 2000),
                )
            )
            timestamp += rng.uniform(29.0, 31.0)
    return events


def _admin(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    end = start + SCAN_RUN_SECONDS
    for host in BENIGN_HOSTS[:2]:
        timestamp = start + rng.uniform(0.0, 1.0)
        while timestamp < end:
            events.append(
                _conn(
                    timestamp,
                    host,
                    VICTIM_HOST,
                    22,
                    "SF",
                    "ssh",
                    rng,
                    duration=0.2,
                    orig_bytes=300,
                    resp_bytes=600,
                )
            )
            timestamp += rng.uniform(29.0, 31.0)
    return events


def _update(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    destinations = ("198.51.100.10", "198.51.100.11", "198.51.100.12")
    end = start + SCAN_RUN_SECONDS
    for host in BENIGN_HOSTS[2:5]:
        timestamp = start + rng.uniform(0.0, 1.0)
        while timestamp < end:
            events.append(
                _conn(
                    timestamp,
                    host,
                    rng.choice(destinations),
                    443,
                    "SF",
                    "ssl",
                    rng,
                    duration=0.05,
                    orig_bytes=800,
                    resp_bytes=800,
                )
            )
            timestamp += rng.uniform(29.0, 31.0)
    return events


def _benign_events(scenario: str, start: float, rng: random.Random) -> list[dict]:
    if scenario == "benign_browsing":
        return browsing_events(start, SCAN_RUN_SECONDS, rng)
    if scenario == "benign_admin":
        return _admin(start, rng)
    if scenario == "benign_update":
        return _update(start, rng)
    if scenario == "benign_monitoring":
        return _monitoring(start, rng)
    if scenario == "benign_backup":
        return _backup(start, rng)
    if scenario == "benign_mixed":
        return (
            browsing_events(start, SCAN_RUN_SECONDS, rng)
            + _backup(start, rng)
            + _update(start, rng)
        )
    raise ValueError(f"unknown benign scan scenario: {scenario}")


def _fast_vertical(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(200):
        state = "S0" if rng.random() < 0.7 else "REJ"
        events.append(
            _conn(start + index * 0.3, ATTACK_HOST, VICTIM_HOST, index + 1, state, None, rng)
        )
    return events


def _slow_vertical(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(40):
        events.append(
            _conn(start + index * 15.0, ATTACK_HOST, VICTIM_HOST, index + 1, "S0", None, rng)
        )
    return events


def _horizontal(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(50):
        destination = f"192.168.217.{121 + index}"
        state = "S0" if rng.random() < 0.8 else "REJ"
        events.append(
            _conn(start + index * 3.0, ATTACK_HOST, destination, 445, state, None, rng)
        )
    return events


def _service_scan(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    index = 0
    for host_index in range(80):
        destination = f"192.168.217.{121 + host_index}"
        for port in SERVICE_PORTS:
            state = "S0" if rng.random() < 0.75 else "REJ"
            events.append(
                _conn(
                    start + index * 2.8,
                    ATTACK_HOST,
                    destination,
                    port,
                    state,
                    None,
                    rng,
                )
            )
            index += 1
    return events


def _jittered(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    timestamp = start
    for index in range(60):
        events.append(
            _conn(timestamp, ATTACK_HOST, VICTIM_HOST, (index % 60) + 1, "S0", None, rng)
        )
        timestamp += rng.uniform(0.5, 4.0)
    return events


def _noisy(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(180):
        state_roll = rng.random()
        if state_roll < 0.4:
            state = "S0"
        elif state_roll < 0.7:
            state = "REJ"
        else:
            state = "SF"
        service = "http" if state == "SF" else None
        events.append(
            _conn(
                start + index * 1.5,
                ATTACK_HOST,
                VICTIM_HOST,
                rng.randint(1, 1024),
                state,
                service,
                rng,
                duration=0.01 if state == "SF" else None,
                orig_bytes=120 if state == "SF" else 0,
                resp_bytes=300 if state == "SF" else 0,
            )
        )
    return events


def _attack_events(scenario: str, start: float, rng: random.Random) -> list[dict]:
    if scenario == "attack_scan_fast":
        return _fast_vertical(start, rng)
    if scenario == "attack_scan_slow":
        return _slow_vertical(start, rng)
    if scenario == "attack_scan_horizontal":
        return _horizontal(start, rng)
    if scenario == "attack_scan_service":
        return _service_scan(start, rng)
    if scenario == "attack_scan_jittered":
        return _jittered(start, rng)
    if scenario == "attack_scan_noisy":
        return _noisy(start, rng)
    raise ValueError(f"unknown attack scan scenario: {scenario}")


def generate_scan_corpus(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 6,
    attack_runs: int = 6,
) -> list[Path]:
    if benign_runs < 6 or attack_runs < 6:
        raise ValueError("scan corpus needs >=6 benign and >=6 attack runs")

    specs: list[tuple[str, str]] = [
        BENIGN_SPECS[index % len(BENIGN_SPECS)] for index in range(benign_runs)
    ]
    specs.extend(
        ATTACK_SPECS[index % len(ATTACK_SPECS)] for index in range(attack_runs)
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    run_dirs: list[Path] = []

    for index, (scenario, variant) in enumerate(specs):
        run_id = f"scan-{index:02d}-{scenario}-{variant}"
        start = SCAN_BASE_TS + index * 3600
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))

        if scenario.startswith("benign_"):
            events = _benign_events(scenario, start, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="benign",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + SCAN_RUN_SECONDS),
                attacker_ip=None,
                victim_ip=None,
                tool="synthetic_benign_scan",
                mitre_tactic=[],
                mitre_technique=[],
                expected_detection=[],
                notes="synthetic scan corpus",
            )
        else:
            events = _attack_events(scenario, start, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="attack",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + SCAN_RUN_SECONDS),
                attacker_ip=ATTACK_HOST,
                victim_ip=VICTIM_HOST,
                tool="synthetic_scan",
                mitre_tactic=["TA0007"],
                mitre_technique=["T1046"],
                expected_detection=["D2"],
                notes="synthetic scan corpus",
            )

        run_dirs.append(write_run(out_dir, run_id, ground_truth, events))

    return run_dirs
