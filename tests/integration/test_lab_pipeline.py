from __future__ import annotations

import json
from pathlib import Path

from ndr.contracts import GroundTruthRun
from ndr.lab import prepare_lab_runs, run_lab_eval
from ndr.prelab import run_prelab
from ndr.risk.engine import load_alerts


def _manifest(prelab: Path) -> list[dict]:
    runs: list[dict] = []
    for detector in ("d2", "d3", "d5", "d7"):
        for path in sorted((prelab / detector / "synthetic").glob("*/run.json")):
            runs.append(json.loads(path.read_text(encoding="utf-8")))
    for path in sorted((prelab / "d1" / "synthetic").glob("*/run.json")):
        run = json.loads(path.read_text(encoding="utf-8"))
        if run["kind"] == "benign":
            runs.append(run)
    return runs


def _raw_logs(prelab: Path, raw: Path) -> None:
    raw.mkdir(parents=True)
    for log_type in ("conn", "dns", "ssh", "ftp"):
        with (raw / f"{log_type}.log").open("w", encoding="utf-8") as out:
            for detector in ("d1", "d2", "d3", "d5", "d7"):
                for run_dir in sorted(
                    (prelab / detector / "synthetic").glob("*")
                ):
                    path = run_dir / f"{log_type}.jsonl"
                    if path.is_file():
                        out.write(path.read_text(encoding="utf-8"))


def test_lab_pipeline_end_to_end(tmp_path: Path) -> None:
    prelab = tmp_path / "prelab"
    run_prelab(prelab, seed=42)

    manifest_data = _manifest(prelab)
    manifest = [GroundTruthRun.model_validate(item) for item in manifest_data]
    assert len(manifest) == 52

    raw = tmp_path / "raw"
    _raw_logs(prelab, raw)
    lab_runs = tmp_path / "lab-runs"
    paths = prepare_lab_runs([raw], manifest, lab_runs)
    assert len(paths) == 52
    assert all((path / "run.json").is_file() for path in paths)
    assert not (lab_runs / "d4").exists()
    assert not (lab_runs / "d6").exists()

    summary = run_lab_eval(
        runs_dir=lab_runs,
        workdir=tmp_path / "lab-eval",
        model_dirs={
            "anomaly": prelab / "d1" / "model",
            "scan": prelab / "d2" / "model",
            "brute": prelab / "d3" / "model",
            "beacon": prelab / "d5" / "model",
            "dns": prelab / "d7" / "model",
        },
    )

    assert set(summary["detectors"]) == {"D1", "D2", "D3", "D5", "D7"}
    assert summary["excluded_detectors"] == ["D4", "D6"]
    assert sorted(
        path.name for path in (tmp_path / "lab-eval" / "detections").glob("*.jsonl")
    ) == ["anomaly.jsonl", "beacon.jsonl", "brute.jsonl", "dns.jsonl", "scan.jsonl"]
    load_alerts(tmp_path / "lab-eval" / "alerts.jsonl")
    assert (tmp_path / "lab-eval" / "risk.md").is_file()
    assert (tmp_path / "lab-eval" / "summary.json").is_file()
    lab_report = (tmp_path / "lab-eval" / "lab.md").read_text(encoding="utf-8")
    assert "D4/D6 excluded: no malware scenario / no Windows SMB victim." in lab_report
