"""Deterministic synthetic Zeek conn.log generation."""

from __future__ import annotations

import hashlib
import json
import random
import zlib
from datetime import datetime, timezone
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.scenarios import ATTACK_SPECS, BASE_TS, BENIGN_SPECS, RunSpec

PROTO = "tcp"


def to_utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def make_uid(run_id: str, index: int) -> str:
    digest = hashlib.sha1(f"{run_id}:{index}".encode("utf-8")).hexdigest()
    return "C" + digest[:15]


def make_conn_obj(
    ts: float,
    orig_h: str,
    orig_p: int,
    resp_h: str,
    resp_p: int,
    service: str | None,
    duration: float | None,
    orig_bytes: int,
    resp_bytes: int,
    orig_pkts: int,
    resp_pkts: int,
    conn_state: str | None,
    proto: str = PROTO,
) -> dict:
    obj = {
        "ts": round(float(ts), 6),
        "id": {
            "orig_h": orig_h,
            "orig_p": int(orig_p),
            "resp_h": resp_h,
            "resp_p": int(resp_p),
        },
        "proto": proto,
        "service": service if service is not None else "-",
        "orig_bytes": int(orig_bytes),
        "resp_bytes": int(resp_bytes),
        "orig_pkts": int(orig_pkts),
        "resp_pkts": int(resp_pkts),
        "conn_state": conn_state if conn_state is not None else "-",
    }
    if duration is not None:
        obj["duration"] = round(float(duration), 3)
    return obj


def browsing_events(start: float, duration_sec: int, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    hosts = [f"192.168.217.{index}" for index in range(101, 111)]
    destinations = [f"203.0.113.{index}" for index in range(1, 9)]
    end = start + duration_sec

    for host in hosts:
        timestamp = start + rng.uniform(0.0, 10.0)
        while timestamp < end:
            state = "SF" if rng.random() >= 0.02 else "S0"
            port = 443 if rng.random() < 0.6 else 80
            service = "https" if port == 443 else "http"
            if state == "SF":
                duration = rng.uniform(0.05, 20.0)
                orig_bytes = rng.randint(200, 2000)
                resp_bytes = rng.randint(500, 50000)
                orig_pkts = max(1, orig_bytes // 600)
                resp_pkts = max(1, resp_bytes // 600)
            else:
                duration = None
                orig_bytes = 0
                resp_bytes = 0
                orig_pkts = 0
                resp_pkts = 0
            events.append(
                make_conn_obj(
                    timestamp,
                    host,
                    rng.randint(49152, 65535),
                    rng.choice(destinations),
                    port,
                    service,
                    duration,
                    orig_bytes,
                    resp_bytes,
                    orig_pkts,
                    resp_pkts,
                    state,
                )
            )
            timestamp += rng.uniform(8.0, 12.0)
    return events


def _admin(start: float, duration_sec: int, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    end = start + duration_sec
    for host in ("192.168.217.101", "192.168.217.102"):
        timestamp = start
        while timestamp < end:
            events.append(
                make_conn_obj(
                    timestamp,
                    host,
                    rng.randint(49152, 65535),
                    "192.168.217.129",
                    22,
                    "ssh",
                    0.1,
                    200,
                    400,
                    1,
                    2,
                    "SF",
                )
            )
            timestamp += 60.0
    return events


def _update(start: float, duration_sec: int, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    hosts = ("192.168.217.103", "192.168.217.104", "192.168.217.105")
    destinations = ("198.51.100.10", "198.51.100.11", "198.51.100.12")
    end = start + duration_sec
    for host in hosts:
        timestamp = start + rng.uniform(0.0, 10.0)
        while timestamp < end:
            events.append(
                make_conn_obj(
                    timestamp,
                    host,
                    rng.randint(49152, 65535),
                    rng.choice(destinations),
                    443,
                    "ssl",
                    0.05,
                    800,
                    800,
                    1,
                    2,
                    "SF",
                )
            )
            timestamp += rng.uniform(9.0, 11.0)
    return events


def _fast_scan(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(200):
        destination = "192.168.217.129" if index % 2 == 0 else "192.168.217.130"
        state = "S0" if rng.random() < 0.7 else "REJ"
        events.append(
            make_conn_obj(
                start + index * 0.3,
                "192.168.217.132",
                rng.randint(49152, 65535),
                destination,
                index + 1,
                None,
                None,
                0,
                0,
                0,
                0,
                state,
            )
        )
    return events


def _slow_scan(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    ports = (22, 80, 443)
    for index in range(40):
        events.append(
            make_conn_obj(
                start + index * 6.0,
                "192.168.217.132",
                rng.randint(49152, 65535),
                f"192.168.217.{121 + index % 20}",
                ports[index % len(ports)],
                None,
                None,
                0,
                0,
                0,
                0,
                "S0",
            )
        )
    return events


def _beacon(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(50):
        events.append(
            make_conn_obj(
                start + index * 6.0,
                "192.168.217.132",
                rng.randint(49152, 65535),
                "203.0.113.50",
                443,
                "ssl",
                0.2,
                1200,
                800,
                2,
                2,
                "SF",
            )
        )
    return events


def _exfil(start: float, rng: random.Random) -> list[dict]:
    events: list[dict] = []
    for index in range(20):
        orig_bytes = rng.randint(2_000_000, 5_000_000)
        events.append(
            make_conn_obj(
                start + index * 6.0,
                "192.168.217.132",
                rng.randint(49152, 65535),
                "203.0.113.60",
                443,
                "ssl",
                rng.uniform(1.0, 3.0),
                orig_bytes,
                500,
                max(1, orig_bytes // 1400),
                1,
                "SF",
            )
        )
    return events


def _build_events(
    scenario: str, start: float, duration_sec: int, rng: random.Random
) -> list[dict]:
    if scenario == "benign_browsing":
        return browsing_events(start, duration_sec, rng)
    if scenario == "benign_admin":
        return _admin(start, duration_sec, rng)
    if scenario == "benign_update":
        return _update(start, duration_sec, rng)
    if scenario == "attack_fast_scan":
        return _fast_scan(start, rng)
    if scenario == "attack_slow_scan":
        return _slow_scan(start, rng)
    if scenario == "attack_beacon":
        return _beacon(start, rng)
    if scenario == "attack_exfil":
        return _exfil(start, rng)
    raise ValueError(f"unknown scenario: {scenario}")


def write_run(
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
    with (run_dir / "conn.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    (run_dir / "run.json").write_text(
        ground_truth.model_dump_json(indent=2), encoding="utf-8"
    )
    return run_dir


def generate(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 4,
    attack_runs: int = 4,
    benign_minutes: int = 60,
) -> list[Path]:
    if benign_runs < 1 or attack_runs < 1:
        raise ValueError("benign_runs and attack_runs must be >= 1")
    if benign_minutes < 1:
        raise ValueError("benign_minutes must be >= 1")

    specs: list[RunSpec] = [
        BENIGN_SPECS[index % len(BENIGN_SPECS)] for index in range(benign_runs)
    ]
    specs.extend(
        ATTACK_SPECS[index % len(ATTACK_SPECS)] for index in range(attack_runs)
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    run_dirs: list[Path] = []
    used_scenarios: set[str] = set()

    for index, spec in enumerate(specs):
        base_id = f"lab-{index:02d}-{spec.scenario}-{spec.variant}"
        run_id = base_id
        if spec.scenario in used_scenarios:
            run_id = f"{base_id}-r{index:02d}"
        used_scenarios.add(spec.scenario)

        start = BASE_TS + index * 7200
        duration_sec = benign_minutes * 60 if spec.kind == "benign" else 300
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))
        events = _build_events(spec.scenario, start, duration_sec, rng)
        ground_truth = GroundTruthRun(
            run_id=run_id,
            scenario=spec.scenario,
            kind=spec.kind,
            variant=spec.variant,
            start_ts=to_utc(start),
            end_ts=to_utc(start + duration_sec),
            attacker_ip=spec.attacker_ip,
            victim_ip=spec.victim_ip,
            tool=spec.tool,
            mitre_tactic=list(spec.mitre_tactic),
            mitre_technique=list(spec.mitre_technique),
            expected_detection=list(spec.expected_detection),
            notes=f"synthetic {spec.variant} run generated by ndr synth",
        )
        run_dirs.append(write_run(out_dir, run_id, ground_truth, events))

    return run_dirs
