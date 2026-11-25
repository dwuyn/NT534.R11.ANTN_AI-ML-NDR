"""Offline adapter for raw Zeek lab logs and the synthetic run contract."""

from __future__ import annotations

import gzip
import json
import math
import re
import shutil
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.beacon.score import score_beacon
from ndr.brute.score import score_brute
from ndr.contracts import GroundTruthRun
from ndr.dns.score import score_dns
from ndr.risk.engine import (
    build_alerts,
    load_detections,
    load_enrichment,
    write_alerts,
)
from ndr.risk.report import build_risk_report
from ndr.scan.score import score_scan

LAB_LOG_TYPES = (
    "conn",
    "dns",
    "ssh",
    "ftp",
    "http",
    "files",
    "ssl",
    "intel",
    "smb_mapping",
    "smb_files",
    "dce_rpc",
)
LAB_LOG_FILENAMES = {
    "conn": ("conn.log", "conn.log.gz"),
    "dns": ("dns.log", "dns.log.gz"),
    "ssh": ("ssh.log", "ssh.log.gz"),
    "ftp": ("ftp.log", "ftp.log.gz"),
    "http": ("http.log", "http.log.gz"),
    "files": ("files.log", "files.log.gz"),
    "ssl": ("ssl.log", "ssl.log.gz"),
    "intel": ("intel.log", "intel.log.gz"),
    "smb_mapping": ("smb_mapping.log", "smb_mapping.log.gz"),
    "smb_files": ("smb_files.log", "smb_files.log.gz"),
    "dce_rpc": ("dce_rpc.log", "dce_rpc.log.gz"),
}
LAB_ATTACK_SCENARIOS = frozenset(
    {"port_scan", "brute_force", "c2_beaconing", "dns_tunneling"}
)
LAB_SUPPORTED_DETECTORS = frozenset({"D1", "D2", "D3", "D5", "D7"})
LAB_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
LAB_MODEL_KEYS = frozenset({"anomaly", "scan", "brute", "beacon", "dns"})
TARGET_FP_PER_DAY = 10.0


def load_lab_manifest(path: Path) -> list[GroundTruthRun]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list")

    runs: list[GroundTruthRun] = []
    seen: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"{path}[{index}]: expected a JSON object")
        try:
            run = GroundTruthRun.model_validate(item)
        except Exception as exc:
            raise ValueError(f"{path}[{index}]: {exc}") from exc
        if not LAB_RUN_ID_RE.fullmatch(run.run_id):
            raise ValueError(
                f"{path}[{index}]: invalid run_id {run.run_id!r}"
            )
        if run.run_id in seen:
            raise ValueError(f"{path}: duplicate run_id {run.run_id}")
        seen.add(run.run_id)
        if run.start_ts >= run.end_ts:
            raise ValueError(f"{run.run_id}: start_ts must be before end_ts")
        if run.kind == "attack" and run.scenario not in LAB_ATTACK_SCENARIOS:
            raise ValueError(
                f"{run.run_id}: unsupported lab attack scenario "
                f"{run.scenario!r}; D4/D6 are out of lab scope"
            )
        for detector in run.expected_detection:
            if detector not in LAB_SUPPORTED_DETECTORS:
                raise ValueError(
                    f"{run.run_id}: unsupported detector {detector!r}"
                )
        runs.append(run)

    return sorted(runs, key=lambda run: (run.start_ts, run.run_id))


def _ensure_empty_directory(path: Path, label: str) -> None:
    if not path.exists():
        return
    if not path.is_dir():
        raise ValueError(f"{path}: {label} must be a directory")
    if next(path.iterdir(), None) is not None:
        raise ValueError(f"{path}: {label} must be empty")


def _parse_raw_event(path: Path, lineno: int, line: str) -> dict:
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc
    if not isinstance(event, dict):
        raise ValueError(f"{path}:{lineno}: expected a JSON object")
    timestamp = event.get("ts")
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(float(timestamp))
    ):
        raise ValueError(f"{path}:{lineno}: missing or invalid ts")
    return event


def prepare_lab_runs(
    raw_roots: Sequence[Path],
    manifest: Sequence[GroundTruthRun],
    out_dir: Path,
    require_events: bool = True,
) -> list[Path]:
    roots = [Path(root) for root in raw_roots]
    for root in roots:
        if not root.is_dir():
            raise ValueError(f"{root}: raw log directory not found")

    out_dir = Path(out_dir)
    existed = out_dir.exists()
    _ensure_empty_directory(out_dir, "output directory")
    if not existed:
        out_dir.mkdir(parents=True)

    runs = sorted(manifest, key=lambda run: (run.start_ts, run.run_id))
    for run in runs:
        (out_dir / run.run_id).mkdir()

    counts = {run.run_id: 0 for run in runs}
    seen: set[tuple[str, str, str]] = set()
    files_found = False

    try:
        with ExitStack() as stack:
            handles = {
                run.run_id: {
                    log_type: stack.enter_context(
                        (out_dir / run.run_id / f"{log_type}.jsonl").open(
                            "w", encoding="utf-8"
                        )
                    )
                    for log_type in LAB_LOG_TYPES
                }
                for run in runs
            }

            for root in roots:
                for log_type, filenames in LAB_LOG_FILENAMES.items():
                    for filename in filenames:
                        path = root / filename
                        if not path.is_file():
                            continue
                        files_found = True
                        opener = gzip.open if path.suffix == ".gz" else open
                        with opener(path, "rt", encoding="utf-8") as handle:
                            for lineno, line in enumerate(handle, start=1):
                                if not line.strip():
                                    continue
                                event = _parse_raw_event(path, lineno, line)
                                timestamp = float(event["ts"])
                                serialized = json.dumps(event, sort_keys=True)
                                uid = event.get("uid")
                                dedup_key = (
                                    uid
                                    if isinstance(uid, str) and uid
                                    else serialized
                                )
                                for run in runs:
                                    if not (
                                        run.start_ts.timestamp()
                                        <= timestamp
                                        < run.end_ts.timestamp()
                                    ):
                                        continue
                                    key = (run.run_id, log_type, dedup_key)
                                    if key in seen:
                                        continue
                                    seen.add(key)
                                    handles[run.run_id][log_type].write(
                                        serialized + "\n"
                                    )
                                    counts[run.run_id] += 1

            if not files_found:
                raise ValueError(
                    f"no supported Zeek log files under {', '.join(map(str, roots))}"
                )
            if require_events:
                for run in runs:
                    if counts[run.run_id] == 0:
                        raise ValueError(
                            f"{run.run_id}: no supported events in manifest window"
                        )
            for run in runs:
                (out_dir / run.run_id / "run.json").write_text(
                    run.model_dump_json(indent=2), encoding="utf-8"
                )
    except Exception:
        if not existed and out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        raise

    return [out_dir / run.run_id for run in sorted(runs, key=lambda item: item.run_id)]


def _detector_entry(events: Sequence, report: dict) -> dict[str, float | int]:
    return {
        "attack_recall": float(report["attack_recall"]),
        "benign_fp_per_day": float(report["benign_fp_per_day"]),
        "detections": len(events),
    }


def run_lab_eval(
    runs_dir: Path,
    workdir: Path,
    model_dirs: Mapping[str, Path],
    enrichment_path: Path | None = None,
) -> dict:
    if set(model_dirs) != LAB_MODEL_KEYS:
        raise ValueError(
            f"model_dirs must have keys {sorted(LAB_MODEL_KEYS)}, "
            f"got {sorted(model_dirs)}"
        )

    runs_dir = Path(runs_dir)
    workdir = Path(workdir)
    _ensure_empty_directory(workdir, "workdir")
    detections_dir = workdir / "detections"
    reports_dir = workdir / "reports"
    detections_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    d1_events = score(
        input_dir=runs_dir,
        model_dir=Path(model_dirs["anomaly"]),
        out_path=detections_dir / "anomaly.jsonl",
    )
    d2_events = score_scan(
        input_dir=runs_dir,
        model_dir=Path(model_dirs["scan"]),
        out_path=detections_dir / "scan.jsonl",
    )
    d3_events = score_brute(
        input_dir=runs_dir,
        model_dir=Path(model_dirs["brute"]),
        out_path=detections_dir / "brute.jsonl",
    )
    d5_events = score_beacon(
        input_dir=runs_dir,
        model_dir=Path(model_dirs["beacon"]),
        out_path=detections_dir / "beacon.jsonl",
    )
    d7_events = score_dns(
        input_dir=runs_dir,
        model_dir=Path(model_dirs["dns"]),
        out_path=detections_dir / "dns.jsonl",
    )

    reports = {
        "D1": build_report(
            detections_path=detections_dir / "anomaly.jsonl",
            input_dir=runs_dir,
            out_path=reports_dir / "d1.md",
            title="D1 anomaly report (lab)",
            target_fp_per_day=TARGET_FP_PER_DAY,
        ),
        "D2": build_report(
            detections_path=detections_dir / "scan.jsonl",
            input_dir=runs_dir,
            out_path=reports_dir / "d2.md",
            title="D2 port scan report (lab)",
            target_fp_per_day=TARGET_FP_PER_DAY,
        ),
        "D3": build_report(
            detections_path=detections_dir / "brute.jsonl",
            input_dir=runs_dir,
            out_path=reports_dir / "d3.md",
            title="D3 brute force report (lab)",
            target_fp_per_day=TARGET_FP_PER_DAY,
            run_filename="ssh.jsonl",
        ),
        "D5": build_report(
            detections_path=detections_dir / "beacon.jsonl",
            input_dir=runs_dir,
            out_path=reports_dir / "d5.md",
            title="D5 beaconing report (lab)",
            target_fp_per_day=TARGET_FP_PER_DAY,
        ),
        "D7": build_report(
            detections_path=detections_dir / "dns.jsonl",
            input_dir=runs_dir,
            out_path=reports_dir / "d7.md",
            title="D7 DNS tunneling report (lab)",
            target_fp_per_day=TARGET_FP_PER_DAY,
            run_filename="dns.jsonl",
        ),
    }

    events = {
        "D1": d1_events,
        "D2": d2_events,
        "D3": d3_events,
        "D5": d5_events,
        "D7": d7_events,
    }
    detectors = {
        name: _detector_entry(events[name], reports[name]) for name in events
    }

    enrichment = load_enrichment(enrichment_path)
    alerts_path = workdir / "alerts.jsonl"
    alerts = build_alerts(load_detections(detections_dir), enrichment)
    write_alerts(alerts, alerts_path)
    risk = build_risk_report(
        alerts_path=alerts_path,
        input_dir=detections_dir,
        out_path=workdir / "risk.md",
    )

    summary = {
        "detectors": detectors,
        "risk": risk,
        "excluded_detectors": ["D4", "D6"],
    }
    (workdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )

    lines = [
        "# Lab NDR evaluation",
        "",
        "| detector | detections | attack_recall | benign_fp_per_day |",
        "|---|---:|---:|---:|",
    ]
    for name, entry in detectors.items():
        lines.append(
            f"| {name} | {entry['detections']} | "
            f"{entry['attack_recall']:.2f} | "
            f"{entry['benign_fp_per_day']:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Risk",
            "",
            f"- Raw alerts: {risk['raw_alerts']}",
            f"- Fused alerts: {risk['fused_alerts']}",
            f"- Reduction: {risk['reduction'] * 100:.2f}%",
            f"- MITRE coverage: {risk['mitre_coverage'] * 100:.2f}%",
            "",
            "D4/D6 excluded: no malware scenario / no Windows SMB victim.",
        ]
    )
    (workdir / "lab.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary
