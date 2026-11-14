"""Deterministic synthetic Zeek ssh/ftp auth corpora for D3 brute force."""

from __future__ import annotations

import json
import random
import zlib
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.generate import browsing_events, make_conn_obj, make_uid, to_utc

BRUTE_BASE_TS = 1770400000.0
BRUTE_RUN_SECONDS = 1800

ATTACK_HOST = "192.168.217.132"
VICTIM_HOST = "192.168.217.129"

OPENSSH_CLIENT = "OpenSSH_9.3"
MONITORING_CLIENT = "libssh_0.10"

BENIGN_SPECS: tuple[tuple[str, str], ...] = (
    ("benign_ssh_admin", "standard"),
    ("benign_ssh_monitoring", "25s"),
    ("benign_ftp_backup", "30s"),
    ("benign_ssh_update", "25s"),
    ("benign_http_browsing", "standard"),
    ("benign_brute_mixed", "standard"),
)

ATTACK_SPECS: tuple[tuple[str, str], ...] = (
    ("attack_ssh_hydra", "5qps"),
    ("attack_ssh_slow", "0.1qps"),
    ("attack_ftp_fail", "2qps"),
    ("attack_ssh_spray", "10hosts"),
    ("attack_ssh_success_after_fail", "success_after_fail"),
    ("attack_mixed_ssh_ftp", "mixed"),
)


def _auth(
    ts: float,
    src: str,
    dst: str,
    port: int,
    service: str,
    success: bool,
    rng: random.Random,
    *,
    attempts: int = 1,
    client: str | None = None,
    orig_bytes: int = 0,
    user: str = "root",
    command: str = "PASS",
    reply_code: int | None = None,
) -> dict:
    if reply_code is None:
        reply_code = 230 if success else 530
    return {
        "ts": round(float(ts), 6),
        "src": src,
        "dst": dst,
        "port": int(port),
        "service": service,
        "success": bool(success),
        "attempts": int(attempts),
        "client": client,
        "orig_bytes": int(orig_bytes),
        "user": user,
        "command": command,
        "reply_code": int(reply_code),
        "src_port": rng.randint(49152, 65535),
    }


def _periodic(
    start: float,
    hosts: tuple[str, ...],
    dst: str,
    port: int,
    service: str,
    interval: float,
    rng: random.Random,
    *,
    client: str | None,
    user: str = "root",
    orig_bytes: int = 200,
    attempts: int = 1,
) -> list[dict]:
    events: list[dict] = []
    end = start + BRUTE_RUN_SECONDS
    for host in hosts:
        timestamp = start + rng.uniform(0.0, interval)
        while timestamp < end:
            events.append(
                _auth(
                    timestamp,
                    host,
                    dst,
                    port,
                    service,
                    True,
                    rng,
                    attempts=attempts,
                    client=client,
                    orig_bytes=orig_bytes,
                    user=user,
                )
            )
            timestamp += interval
    return events


def _benign_run(
    scenario: str, start: float, rng: random.Random
) -> tuple[list[dict], list[dict] | None]:
    if scenario == "benign_ssh_admin":
        return (
            _periodic(
                start,
                ("192.168.217.101", "192.168.217.102"),
                VICTIM_HOST,
                22,
                "ssh",
                30.0,
                rng,
                client=OPENSSH_CLIENT,
                orig_bytes=220,
            ),
            None,
        )
    if scenario == "benign_ssh_monitoring":
        return (
            _periodic(
                start,
                ("192.168.217.103", "192.168.217.104"),
                VICTIM_HOST,
                22,
                "ssh",
                25.0,
                rng,
                client=MONITORING_CLIENT,
                user="monitor",
                orig_bytes=140,
            ),
            None,
        )
    if scenario == "benign_ftp_backup":
        return (
            _periodic(
                start,
                ("192.168.217.105",),
                VICTIM_HOST,
                21,
                "ftp",
                30.0,
                rng,
                client=None,
                user="backup",
                orig_bytes=300,
            ),
            None,
        )
    if scenario == "benign_ssh_update":
        return (
            _periodic(
                start,
                ("192.168.217.106", "192.168.217.107"),
                VICTIM_HOST,
                22,
                "ssh",
                25.0,
                rng,
                client=OPENSSH_CLIENT,
                user="update",
                orig_bytes=180,
            ),
            None,
        )
    if scenario == "benign_http_browsing":
        return [], browsing_events(start, BRUTE_RUN_SECONDS, rng)
    if scenario == "benign_brute_mixed":
        events = _periodic(
            start,
            ("192.168.217.108", "192.168.217.109"),
            VICTIM_HOST,
            22,
            "ssh",
            30.0,
            rng,
            client=OPENSSH_CLIENT,
            orig_bytes=210,
        )
        events.extend(
            _periodic(
                start,
                ("192.168.217.110",),
                VICTIM_HOST,
                21,
                "ftp",
                30.0,
                rng,
                client=None,
                user="backup",
                orig_bytes=320,
            )
        )
        return events, None
    raise ValueError(f"unknown benign brute scenario: {scenario}")


def _attack_run(
    scenario: str, start: float, rng: random.Random
) -> list[dict]:
    events: list[dict] = []
    if scenario == "attack_ssh_hydra":
        for index in range(300):
            events.append(
                _auth(
                    start + index * 0.2,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    22,
                    "ssh",
                    False,
                    rng,
                    client="hydra",
                    orig_bytes=40,
                )
            )
        return events
    if scenario == "attack_ssh_slow":
        for index in range(180):
            events.append(
                _auth(
                    start + index * 10.0,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    22,
                    "ssh",
                    False,
                    rng,
                    client="paramiko_3.4",
                    orig_bytes=60,
                )
            )
        return events
    if scenario == "attack_ftp_fail":
        for index in range(600):
            events.append(
                _auth(
                    start + index * 0.5,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    21,
                    "ftp",
                    False,
                    rng,
                    user="admin",
                    command="PASS",
                    reply_code=530,
                    orig_bytes=30,
                )
            )
        return events
    if scenario == "attack_ssh_spray":
        for index in range(100):
            events.append(
                _auth(
                    start + index * 6.0,
                    ATTACK_HOST,
                    f"192.168.217.{121 + index % 10}",
                    22,
                    "ssh",
                    False,
                    rng,
                    client="hydra",
                    user=f"user{index % 5}",
                    orig_bytes=50,
                )
            )
        return events
    if scenario == "attack_ssh_success_after_fail":
        for index in range(60):
            events.append(
                _auth(
                    start + index,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    22,
                    "ssh",
                    False,
                    rng,
                    client="hydra",
                    orig_bytes=40,
                )
            )
        for index in range(10):
            events.append(
                _auth(
                    start + 60.0 + index * 5.0,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    22,
                    "ssh",
                    True,
                    rng,
                    client="hydra",
                    orig_bytes=100,
                )
            )
        return events
    if scenario == "attack_mixed_ssh_ftp":
        for index in range(100):
            events.append(
                _auth(
                    start + index * 1.5,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    22,
                    "ssh",
                    False,
                    rng,
                    client="hydra",
                    orig_bytes=40,
                )
            )
        for index in range(75):
            events.append(
                _auth(
                    start + index * 2.0,
                    ATTACK_HOST,
                    VICTIM_HOST,
                    21,
                    "ftp",
                    False,
                    rng,
                    user="admin",
                    reply_code=530,
                    orig_bytes=30,
                )
            )
        return events
    raise ValueError(f"unknown attack brute scenario: {scenario}")


def _conn_obj(event: dict) -> dict:
    return make_conn_obj(
        event["ts"],
        event["src"],
        event["src_port"],
        event["dst"],
        event["port"],
        event["service"],
        0.1,
        event["orig_bytes"],
        200 if event["success"] else 0,
        1,
        1,
        "SF",
    )


def _endpoint(event: dict) -> dict:
    return {
        "orig_h": event["src"],
        "orig_p": event["src_port"],
        "resp_h": event["dst"],
        "resp_p": event["port"],
    }


def _ssh_obj(event: dict) -> dict:
    return {
        "ts": event["ts"],
        "id": _endpoint(event),
        "auth_success": event["success"],
        "auth_attempts": event["attempts"],
        "client": event["client"] if event["client"] else "-",
        "user": event["user"],
        "service": "ssh",
    }


def _ftp_obj(event: dict) -> dict:
    return {
        "ts": event["ts"],
        "id": _endpoint(event),
        "user": event["user"],
        "command": event["command"],
        "reply_code": event["reply_code"],
        "service": "ftp",
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_brute_run(
    out_dir: Path,
    run_id: str,
    ground_truth: GroundTruthRun,
    events: list[dict],
    conn_events: list[dict] | None = None,
) -> Path:
    auth_events = sorted(
        events, key=lambda event: (event["ts"], event["src"], event["service"])
    )
    conn_rows: list[dict] = []
    ssh_rows: list[dict] = []
    ftp_rows: list[dict] = []

    for index, event in enumerate(auth_events):
        uid = make_uid(run_id, index)
        conn = _conn_obj(event)
        conn["uid"] = uid
        conn_rows.append(conn)
        if event["service"] == "ssh":
            row = _ssh_obj(event)
            row["uid"] = uid
            ssh_rows.append(row)
        else:
            row = _ftp_obj(event)
            row["uid"] = uid
            ftp_rows.append(row)

    if conn_events is not None:
        for index, event in enumerate(
            sorted(conn_events, key=lambda item: item["ts"])
        ):
            conn = dict(event)
            conn["uid"] = make_uid(run_id, 100000 + index)
            conn_rows.append(conn)

    conn_rows.sort(key=lambda row: (row["ts"], row["uid"]))
    ssh_rows.sort(key=lambda row: (row["ts"], row["uid"]))
    ftp_rows.sort(key=lambda row: (row["ts"], row["uid"]))

    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(run_dir / "conn.jsonl", conn_rows)
    _write_jsonl(run_dir / "ssh.jsonl", ssh_rows)
    _write_jsonl(run_dir / "ftp.jsonl", ftp_rows)
    (run_dir / "run.json").write_text(
        ground_truth.model_dump_json(indent=2), encoding="utf-8"
    )
    return run_dir


def _benign_truth(
    run_id: str, scenario: str, variant: str, start: float
) -> GroundTruthRun:
    return GroundTruthRun(
        run_id=run_id,
        scenario=scenario,
        kind="benign",
        variant=variant,
        start_ts=to_utc(start),
        end_ts=to_utc(start + BRUTE_RUN_SECONDS),
        attacker_ip=None,
        victim_ip=None,
        tool="synthetic_brute_benign",
        mitre_tactic=[],
        mitre_technique=[],
        expected_detection=[],
        notes="synthetic brute-force corpus",
    )


def _attack_truth(
    run_id: str, scenario: str, variant: str, start: float
) -> GroundTruthRun:
    return GroundTruthRun(
        run_id=run_id,
        scenario=scenario,
        kind="attack",
        variant=variant,
        start_ts=to_utc(start),
        end_ts=to_utc(start + BRUTE_RUN_SECONDS),
        attacker_ip=ATTACK_HOST,
        victim_ip=VICTIM_HOST,
        tool="synthetic_brute",
        mitre_tactic=["TA0006"],
        mitre_technique=["T1110"],
        expected_detection=["D3"],
        notes="synthetic brute-force corpus",
    )


def generate_brute_corpus(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 6,
    attack_runs: int = 6,
) -> list[Path]:
    if benign_runs < 6 or attack_runs < 6:
        raise ValueError("brute corpus needs >=6 benign and >=6 attack runs")

    specs: list[tuple[str, str, str]] = [
        ("benign", *BENIGN_SPECS[index % len(BENIGN_SPECS)])
        for index in range(benign_runs)
    ]
    specs.extend(
        ("attack", *ATTACK_SPECS[index % len(ATTACK_SPECS)])
        for index in range(attack_runs)
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    run_dirs: list[Path] = []

    for index, (kind, scenario, variant) in enumerate(specs):
        run_id = f"brute-{index:02d}-{scenario}-{variant}"
        start = BRUTE_BASE_TS + index * 3600
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))

        if kind == "benign":
            events, conn_events = _benign_run(scenario, start, rng)
            truth = _benign_truth(run_id, scenario, variant, start)
        else:
            events = _attack_run(scenario, start, rng)
            conn_events = None
            truth = _attack_truth(run_id, scenario, variant, start)

        run_dirs.append(
            write_brute_run(out_dir, run_id, truth, events, conn_events)
        )

    return run_dirs
