"""Inference-only runtime for prepared or live Zeek windows."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ndr.anomaly.score import score
from ndr.beacon.score import score_beacon
from ndr.brute.score import score_brute
from ndr.contracts import GroundTruthRun
from ndr.dns.score import score_dns
from ndr.elk import ElkConfig, export_alerts
from ndr.lab import prepare_lab_runs
from ndr.lateral.score import score_lateral
from ndr.malware.score import score_malware
from ndr.risk.engine import (
    build_alerts,
    load_detections,
    load_enrichment,
    write_alerts,
)
from ndr.scan.score import score_scan

MODEL_KEYS = (
    "anomaly",
    "scan",
    "brute",
    "malware",
    "beacon",
    "lateral",
    "dns",
)
ALIGNMENT_SECONDS = 600
DETECTOR_KEYS = ("D1", "D2", "D3", "D4", "D5", "D6", "D7")
DETECTOR_FILES = {
    "D1": "anomaly.jsonl",
    "D2": "scan.jsonl",
    "D3": "brute.jsonl",
    "D4": "malware.jsonl",
    "D5": "beacon.jsonl",
    "D6": "lateral.jsonl",
    "D7": "dns.jsonl",
}


def model_dirs_from_root(root: Path) -> dict[str, Path]:
    root = Path(root)
    dirs = {key: root / key for key in MODEL_KEYS}
    missing = [
        str(path)
        for path in dirs.values()
        if not path.is_dir()
    ]
    if missing:
        raise FileNotFoundError(", ".join(missing))
    return dirs


def _validate_window(start: datetime, end: datetime) -> None:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("window timestamps must be timezone-aware")
    if start >= end:
        raise ValueError("window start must be before end")
    if int(start.timestamp()) % ALIGNMENT_SECONDS != 0:
        raise ValueError("window start must be aligned to 600 seconds")
    if int(end.timestamp()) % ALIGNMENT_SECONDS != 0:
        raise ValueError("window end must be aligned to 600 seconds")


def prepare_live_run(
    raw_roots: Sequence[Path],
    out_dir: Path,
    start: datetime,
    end: datetime,
) -> Path:
    _validate_window(start, end)
    start = start.astimezone(UTC)
    end = end.astimezone(UTC)
    run_id = f"live-{int(start.timestamp())}"
    run = GroundTruthRun(
        run_id=run_id,
        scenario="live",
        kind="benign",
        variant="live",
        start_ts=start,
        end_ts=end,
        attacker_ip="0.0.0.0",
        victim_ip="0.0.0.0",
        tool="live",
        mitre_tactic=[],
        mitre_technique=[],
        expected_detection=[],
        notes="live batch",
    )
    prepare_lab_runs(
        raw_roots,
        [run],
        Path(out_dir),
        require_events=False,
    )
    return Path(out_dir) / run_id


def _guard_outputs(workdir: Path, detections_dir: Path) -> None:
    for path in (
        detections_dir,
        workdir / "alerts.jsonl",
        workdir / "summary.json",
    ):
        if path.exists():
            raise ValueError(f"{path}: already exists")


def run_infer(
    runs_dir: Path,
    workdir: Path,
    model_dirs: Mapping[str, Path],
    enrichment_path: Path | None = None,
    export_elk: bool = False,
) -> dict:
    if set(model_dirs) != set(MODEL_KEYS):
        raise ValueError(
            f"model_dirs must have keys {list(MODEL_KEYS)}, "
            f"got {sorted(model_dirs)}"
        )

    runs_dir = Path(runs_dir)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    detections_dir = workdir / "detections"
    _guard_outputs(workdir, detections_dir)
    detections_dir.mkdir(parents=True)

    events = {
        "D1": score(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["anomaly"]),
            out_path=detections_dir / DETECTOR_FILES["D1"],
        ),
        "D2": score_scan(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["scan"]),
            out_path=detections_dir / DETECTOR_FILES["D2"],
        ),
        "D3": score_brute(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["brute"]),
            out_path=detections_dir / DETECTOR_FILES["D3"],
        ),
        "D4": score_malware(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["malware"]),
            out_path=detections_dir / DETECTOR_FILES["D4"],
        ),
        "D5": score_beacon(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["beacon"]),
            out_path=detections_dir / DETECTOR_FILES["D5"],
        ),
        "D6": score_lateral(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["lateral"]),
            out_path=detections_dir / DETECTOR_FILES["D6"],
        ),
        "D7": score_dns(
            input_dir=runs_dir,
            model_dir=Path(model_dirs["dns"]),
            out_path=detections_dir / DETECTOR_FILES["D7"],
        ),
    }

    enrichment = load_enrichment(enrichment_path)
    alerts = build_alerts(load_detections(detections_dir), enrichment)
    write_alerts(alerts, workdir / "alerts.jsonl")

    exported = 0
    if export_elk:
        exported = export_alerts(alerts, ElkConfig.from_env())

    counts = {key: len(events[key]) for key in DETECTOR_KEYS}
    summary = {
        "detectors": {
            key: {"detections": counts[key]} for key in DETECTOR_KEYS
        },
        "total_detections": sum(counts.values()),
        "total_alerts": len(alerts),
        "exported_alerts": exported,
    }
    (workdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary
