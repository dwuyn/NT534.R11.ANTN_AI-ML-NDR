from __future__ import annotations

import json
import shutil
from pathlib import Path

from ndr.contracts import AlertEvent
from ndr.lab import LAB_LOG_TYPES
from ndr.prelab import run_prelab
from ndr.runtime import run_infer


def test_run_infer_scores_all_detectors(tmp_path: Path) -> None:
    prelab = tmp_path / "prelab"
    run_prelab(prelab, seed=42)

    attack = None
    for run_json in sorted((prelab / "d7" / "synthetic").glob("*/run.json")):
        data = json.loads(run_json.read_text(encoding="utf-8"))
        if data["kind"] == "attack":
            attack = run_json.parent
            break
    assert attack is not None

    runs = tmp_path / "runs"
    run_dir = runs / attack.name
    shutil.copytree(attack, run_dir)
    for log_type in LAB_LOG_TYPES:
        path = run_dir / f"{log_type}.jsonl"
        if not path.exists():
            path.write_text("", encoding="utf-8")

    workdir = tmp_path / "out"
    summary = run_infer(
        runs_dir=runs,
        workdir=workdir,
        model_dirs={
            "anomaly": prelab / "d1" / "model",
            "scan": prelab / "d2" / "model",
            "brute": prelab / "d3" / "model",
            "malware": prelab / "d4" / "model",
            "beacon": prelab / "d5" / "model",
            "lateral": prelab / "d6" / "model",
            "dns": prelab / "d7" / "model",
        },
    )

    assert list(summary["detectors"]) == ["D1", "D2", "D3", "D4", "D5", "D6", "D7"]
    assert summary["total_detections"] >= 1
    for name in (
        "anomaly",
        "scan",
        "brute",
        "malware",
        "beacon",
        "lateral",
        "dns",
    ):
        assert (workdir / "detections" / f"{name}.jsonl").is_file()
    assert summary["detectors"]["D7"]["detections"] > 0
    for line in (workdir / "alerts.jsonl").read_text(encoding="utf-8").splitlines():
        if line:
            AlertEvent.model_validate_json(line)
