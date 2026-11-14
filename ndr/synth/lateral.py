"""Deterministic synthetic corpus for D6 lateral movement."""

from __future__ import annotations

import json
import random
import zlib
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.synth.generate import make_conn_obj, make_uid, to_utc

LATERAL_BASE_TS = 1770600000.0
LATERAL_RUN_SECONDS = 1800

BENIGN_HOSTS = tuple(f"192.168.217.{index}" for index in range(101, 107))
ATTACK_HOST = "192.168.217.132"
VICTIM_HOST = "192.168.217.129"
ATTACK_TARGETS = ("192.168.217.120", "192.168.217.121", "192.168.217.122")

ADMIN_SHARE = "\\\\192.168.217.129\\ADMIN$"
C_SHARE = "\\\\192.168.217.129\\C$"
DEPLOY_TARGETS = (
    "192.168.217.129",
    "192.168.217.128",
    "192.168.217.127",
)

BENIGN_SPECS: tuple[tuple[str, str], ...] = (
    ("benign_smb_admin_share", "standard"),
    ("benign_smb_backup", "nightly"),
    ("benign_smb_software_deploy", "msi"),
    ("benign_smb_it_audit", "readonly"),
    ("benign_smb_file_server", "share"),
    ("benign_smb_mixed", "standard"),
)

ATTACK_SPECS: tuple[tuple[str, str], ...] = (
    ("attack_lateral_psexec", "svcctl"),
    ("attack_lateral_smbexec", "bat"),
    ("attack_lateral_atexec", "atsvc"),
    ("attack_lateral_remote_service", "create"),
    ("attack_lateral_chain", "multi"),
    ("attack_lateral_credential_reuse", "spray"),
)

WINDOWS_PER_RUN = 3


def _conn(ts: float, src: str, dst: str, rng: random.Random) -> dict:
    return make_conn_obj(
        ts,
        src,
        rng.randint(49152, 65535),
        dst,
        445,
        "smb",
        0.5,
        1200,
        4000,
        3,
        5,
        "SF",
    )


def _mapping(
    ts: float, src: str, dst: str, path: str, service: str, rng: random.Random
) -> dict:
    return {
        "ts": round(float(ts), 6),
        "id": {
            "orig_h": src,
            "orig_p": rng.randint(49152, 65535),
            "resp_h": dst,
            "resp_p": 445,
        },
        "path": path,
        "service": service,
    }


def _file(
    ts: float,
    src: str,
    dst: str,
    action: str,
    path: str,
    name: str,
    size: int,
    rng: random.Random,
) -> dict:
    return {
        "ts": round(float(ts), 6),
        "id": {
            "orig_h": src,
            "orig_p": rng.randint(49152, 65535),
            "resp_h": dst,
            "resp_p": 445,
        },
        "action": action,
        "path": path,
        "name": name,
        "size": int(size),
    }


def _dce(
    ts: float,
    src: str,
    dst: str,
    endpoint: str,
    operation: str,
    named_pipe: str,
    rng: random.Random,
) -> dict:
    return {
        "ts": round(float(ts), 6),
        "id": {
            "orig_h": src,
            "orig_p": rng.randint(49152, 65535),
            "resp_h": dst,
            "resp_p": 445,
        },
        "endpoint": endpoint,
        "operation": operation,
        "named_pipe": named_pipe,
    }


def _benign_admin_share(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host in BENIGN_HOSTS[:2]:
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "read",
                    ADMIN_SHARE,
                    "audit.log",
                    2048,
                    rng,
                )
            )
            files.append(
                _file(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "read",
                    ADMIN_SHARE,
                    "config.txt",
                    1024,
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_backup(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host in BENIGN_HOSTS[2:4]:
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, C_SHARE, "C$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "write",
                    C_SHARE,
                    f"backup-{window}.bak",
                    10_485_760,
                    rng,
                )
            )
            files.append(
                _file(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "write",
                    C_SHARE,
                    f"catalog-{window}.bak",
                    4096,
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_software_deploy(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host_index, host in enumerate(BENIGN_HOSTS[4:6]):
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            if host_index == 0 and window == 0:
                # One fleet-wide deployment window touches three file servers.
                # Exactly one benign window shares the attack out-degree shape,
                # making a split feasible under min_child_samples=10 on this
                # small synthetic corpus without turning deployment into noise.
                for offset, target in enumerate(DEPLOY_TARGETS):
                    timestamp = base + 10 + offset * 10
                    mapping.append(
                        _mapping(
                            timestamp, host, target, C_SHARE, "C$", rng
                        )
                    )
                    files.append(
                        _file(
                            timestamp + 5,
                            host,
                            target,
                            "write",
                            C_SHARE,
                            f"agent-update-{window}.msi",
                            5_242_880,
                            rng,
                        )
                    )
                    conn.append(_conn(timestamp, host, target, rng))
                continue
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, C_SHARE, "C$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "write",
                    C_SHARE,
                    "agent-update.msi",
                    5_242_880,
                    rng,
                )
            )
            files.append(
                _file(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "write",
                    C_SHARE,
                    "deploy.cab",
                    1_048_576,
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_it_audit(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host in (BENIGN_HOSTS[0], BENIGN_HOSTS[2]):
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "read",
                    ADMIN_SHARE,
                    f"inventory-{window}.csv",
                    8192,
                    rng,
                )
            )
            files.append(
                _file(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "read",
                    ADMIN_SHARE,
                    "services.log",
                    2048,
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_file_server(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host in (BENIGN_HOSTS[1], BENIGN_HOSTS[4]):
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, C_SHARE, "C$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "read",
                    C_SHARE,
                    f"report-{window}.docx",
                    30_000,
                    rng,
                )
            )
            files.append(
                _file(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "read",
                    C_SHARE,
                    f"budget-{window}.xlsx",
                    20_000,
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_mixed(
    start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    for host in (BENIGN_HOSTS[0], BENIGN_HOSTS[3]):
        for window in range(WINDOWS_PER_RUN):
            base = start + window * 600
            mapping.append(
                _mapping(base + 10, host, VICTIM_HOST, C_SHARE, "C$", rng)
            )
            files.append(
                _file(
                    base + 30,
                    host,
                    VICTIM_HOST,
                    "read",
                    C_SHARE,
                    "app.log",
                    4096,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 50,
                    host,
                    VICTIM_HOST,
                    "lsarpc",
                    "LsarLookupNames",
                    "\\pipe\\lsarpc",
                    rng,
                )
            )
            conn.append(_conn(base + 10, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 30, host, VICTIM_HOST, rng))
            conn.append(_conn(base + 50, host, VICTIM_HOST, rng))
    return conn, mapping, files, dce


def _benign_events(
    scenario: str, start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    builders = {
        "benign_smb_admin_share": _benign_admin_share,
        "benign_smb_backup": _benign_backup,
        "benign_smb_software_deploy": _benign_software_deploy,
        "benign_smb_it_audit": _benign_it_audit,
        "benign_smb_file_server": _benign_file_server,
        "benign_smb_mixed": _benign_mixed,
    }
    builder = builders.get(scenario)
    if builder is None:
        raise ValueError(f"unknown benign lateral scenario: {scenario}")
    return builder(start, rng)


def _attack_events(
    scenario: str, start: float, rng: random.Random
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    conn: list[dict] = []
    mapping: list[dict] = []
    files: list[dict] = []
    dce: list[dict] = []
    first, second, third = ATTACK_TARGETS

    for window in range(WINDOWS_PER_RUN):
        base = start + window * 600
        if scenario == "attack_lateral_psexec":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 20,
                    ATTACK_HOST,
                    second,
                    "write",
                    ADMIN_SHARE,
                    "svc.exe",
                    71_680,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "svcctl",
                    "CreateServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
        elif scenario == "attack_lateral_smbexec":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 20,
                    ATTACK_HOST,
                    second,
                    "write",
                    ADMIN_SHARE,
                    "exec.bat",
                    512,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "svcctl",
                    "CreateServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
        elif scenario == "attack_lateral_atexec":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 20,
                    ATTACK_HOST,
                    second,
                    "write",
                    ADMIN_SHARE,
                    "task.ps1",
                    1024,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "atsvc",
                    "SchRpcRun",
                    "\\pipe\\atsvc",
                    rng,
                )
            )
        elif scenario == "attack_lateral_remote_service":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, C_SHARE, "C$", rng)
            )
            files.append(
                _file(
                    base + 15,
                    ATTACK_HOST,
                    second,
                    "write",
                    C_SHARE,
                    "svc.exe",
                    71_680,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 20,
                    ATTACK_HOST,
                    second,
                    "svcctl",
                    "CreateServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "svcctl",
                    "StartServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
        elif scenario == "attack_lateral_chain":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, ADMIN_SHARE, "ADMIN$", rng)
            )
            files.append(
                _file(
                    base + 20,
                    ATTACK_HOST,
                    second,
                    "write",
                    ADMIN_SHARE,
                    "payload.dll",
                    120_000,
                    rng,
                )
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "svcctl",
                    "CreateServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
        elif scenario == "attack_lateral_credential_reuse":
            mapping.append(
                _mapping(base + 10, ATTACK_HOST, first, ADMIN_SHARE, "ADMIN$", rng)
            )
            mapping.append(
                _mapping(base + 20, ATTACK_HOST, second, C_SHARE, "C$", rng)
            )
            dce.append(
                _dce(
                    base + 40,
                    ATTACK_HOST,
                    third,
                    "svcctl",
                    "CreateServiceW",
                    "\\pipe\\svcctl",
                    rng,
                )
            )
        else:
            raise ValueError(f"unknown attack lateral scenario: {scenario}")

        for target in (first, second, third):
            conn.append(_conn(base + 10, ATTACK_HOST, target, rng))

    return conn, mapping, files, dce


def write_lateral_run(
    out_dir: Path,
    run_id: str,
    ground_truth: GroundTruthRun,
    conn_events: list[dict],
    mapping_events: list[dict],
    file_events: list[dict],
    dce_events: list[dict],
) -> Path:
    logs = (
        ("conn.jsonl", conn_events),
        ("smb_mapping.jsonl", mapping_events),
        ("smb_files.jsonl", file_events),
        ("dce_rpc.jsonl", dce_events),
    )
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    counter = 0
    for filename, events in logs:
        ordered = sorted(events, key=lambda event: float(event["ts"]))
        for event in ordered:
            event["uid"] = make_uid(run_id, counter)
            counter += 1
        with (run_dir / filename).open("w", encoding="utf-8") as handle:
            for event in ordered:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
    (run_dir / "run.json").write_text(
        ground_truth.model_dump_json(indent=2), encoding="utf-8"
    )
    return run_dir


def generate_lateral_corpus(
    out_dir: Path,
    seed: int = 42,
    benign_runs: int = 6,
    attack_runs: int = 6,
) -> list[Path]:
    if benign_runs < 6 or attack_runs < 5:
        raise ValueError("lateral corpus needs >=6 benign and >=5 attack runs")

    specs: list[tuple[str, str]] = [
        BENIGN_SPECS[index % len(BENIGN_SPECS)]
        for index in range(benign_runs)
    ]
    specs.extend(
        ATTACK_SPECS[index % len(ATTACK_SPECS)]
        for index in range(attack_runs)
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    run_dirs: list[Path] = []

    for index, (scenario, variant) in enumerate(specs):
        run_id = f"lateral-{index:02d}-{scenario}-{variant}"
        start = LATERAL_BASE_TS + index * 3600
        rng = random.Random(seed ^ zlib.crc32(run_id.encode("utf-8")))

        if scenario.startswith("benign_"):
            conn, mapping, files, dce = _benign_events(scenario, start, rng)
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="benign",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + LATERAL_RUN_SECONDS),
                attacker_ip=None,
                victim_ip=None,
                tool="synthetic_lateral_benign",
                mitre_tactic=[],
                mitre_technique=[],
                expected_detection=[],
                notes="synthetic lateral corpus",
            )
        else:
            conn, mapping, files, dce = _attack_events(
                scenario, start, rng
            )
            ground_truth = GroundTruthRun(
                run_id=run_id,
                scenario=scenario,
                kind="attack",
                variant=variant,
                start_ts=to_utc(start),
                end_ts=to_utc(start + LATERAL_RUN_SECONDS),
                attacker_ip=ATTACK_HOST,
                victim_ip=VICTIM_HOST,
                tool="synthetic_lateral",
                mitre_tactic=["TA0008", "TA0002"],
                mitre_technique=["T1021.002", "T1569.002"],
                expected_detection=["D6"],
                notes="synthetic lateral corpus",
            )

        run_dirs.append(
            write_lateral_run(
                out_dir, run_id, ground_truth, conn, mapping, files, dce
            )
        )

    return run_dirs
